package service

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/proxyurl"
	"github.com/Wei-Shaw/sub2api/internal/pkg/servertiming"
)

const (
	// SidecarE2EEHeader marks a loopback hop as sealed (value "1").
	SidecarE2EEHeader = "x-s2s-enc"
	// SidecarE2EEOrigLenHeader carries the pre-sealing body length so the
	// sidecar can restore Content-Length toward upstream.
	SidecarE2EEOrigLenHeader = "x-s2s-enc-len"
	// SidecarAccountIDHeader carries the trusted local account primary key over
	// the authenticated loopback hop. It is consumed and stripped by the sidecar.
	SidecarAccountIDHeader = "x-upstream-account-id"
)

// ShouldUseSidecarTLS reports whether this upstream request should leave through
// the local rustls sidecar so OpenAI OAuth traffic matches official Codex CLI
// TLS (rustls 0.23 + aws-lc). Official ChatGPT and auth.openai.com hosts are
// included; api.openai.com API-key traffic stays on the Go transport.
func ShouldUseSidecarTLS(req *http.Request) bool {
	if req == nil {
		return false
	}
	return shouldUseSidecarTLSURL(req.URL)
}

// ShouldUseSidecarTLSURL is the WS/string form of ShouldUseSidecarTLS.
func ShouldUseSidecarTLSURL(rawURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	return shouldUseSidecarTLSURL(parsed)
}

func shouldUseSidecarTLSURL(u *url.URL) bool {
	if u == nil {
		return false
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme != "https" && scheme != "wss" {
		return false
	}
	if u.User != nil {
		if u.User.Username() != "" {
			return false
		}
		if _, ok := u.User.Password(); ok {
			return false
		}
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if !isOpenAIOAuthSidecarHost(host) {
		return false
	}

	// Match against the escaped path so percent-encoded separators cannot be
	// interpreted as routing structure by Go when the Rust URL parser would keep
	// them inside a segment. Reject dot segments because rust-url normalizes them
	// before the sidecar allowlist is evaluated.
	p := u.EscapedPath()
	if hasOpenAISidecarDotSegment(p) {
		return false
	}

	// 1. auth.openai.com: only OAuth/token and account-auth API traffic belongs
	// on the Codex sidecar. Browser/login/UI routes remain on the origin transport.
	if host == "auth.openai.com" || strings.HasSuffix(host, ".auth.openai.com") {
		return shouldUseOpenAIAuthSidecarPath(p)
	}

	// 2. chatgpt.com / chat.openai.com: only explicit Codex CLI and wham
	// endpoints are classified automatically. Files/conversation traffic is
	// transport-neutral and must be routed explicitly by its owning caller.
	return shouldUseOpenAIChatSidecarPath(p)
}

func shouldUseOpenAIAuthSidecarPath(p string) bool {
	return strings.HasPrefix(p, "/oauth/") ||
		p == "/api/v1/oauth/token" ||
		strings.HasPrefix(p, "/api/accounts/")
}

func shouldUseOpenAIChatSidecarPath(p string) bool {
	return strings.HasPrefix(p, "/backend-api/codex/") ||
		strings.HasPrefix(p, "/backend-api/wham/")
}

func hasOpenAISidecarDotSegment(p string) bool {
	for _, segment := range strings.Split(p, "/") {
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			return true
		}
		if decoded == "." || decoded == ".." {
			return true
		}
	}
	return false
}

func isOpenAIOAuthSidecarHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	switch {
	case host == "chatgpt.com", strings.HasSuffix(host, ".chatgpt.com"):
		return true
	case host == "chat.openai.com", strings.HasSuffix(host, ".chat.openai.com"):
		return true
	case host == "auth.openai.com", strings.HasSuffix(host, ".auth.openai.com"):
		return true
	default:
		return false
	}
}

var sidecarRuntimeConfig atomic.Pointer[config.Config]

// SetSidecarRuntimeConfig installs the process-wide gateway.sidecar routing
// config. It backs ApplySidecarHTTPClient for egress paths that have no direct
// config access (Codex PAT whoami, agent-identity registration, usage probes).
// Called once from startup wiring.
func SetSidecarRuntimeConfig(cfg *config.Config) {
	sidecarRuntimeConfig.Store(cfg)
}

func sidecarRuntime() *config.Config {
	return sidecarRuntimeConfig.Load()
}

// SidecarSettings contains normalized sidecar routing settings.
type SidecarSettings struct {
	Enabled bool
	BaseURL string
	Token   string
}

// ResolveSidecarSettings resolves sidecar configuration directly from
// environment variables (GATEWAY_SIDECAR_* / SUB2API_SIDECAR_*).
func ResolveSidecarSettings(_ *config.Config) SidecarSettings {
	var s SidecarSettings
	enabledConfigured := false
	for _, name := range []string{"GATEWAY_SIDECAR_ENABLED", "SUB2API_SIDECAR_ENABLED"} {
		raw, exists := os.LookupEnv(name)
		if !exists || strings.TrimSpace(raw) == "" {
			continue
		}
		enabledConfigured = true
		value := strings.TrimSpace(raw)
		s.Enabled = value == "1" || strings.EqualFold(value, "true")
		break
	}
	if u := os.Getenv("GATEWAY_SIDECAR_BASE_URL"); u != "" {
		s.BaseURL = strings.TrimSpace(u)
	} else if u := os.Getenv("SUB2API_SIDECAR_BASE_URL"); u != "" {
		s.BaseURL = strings.TrimSpace(u)
	}
	if tok := os.Getenv("GATEWAY_SIDECAR_TOKEN"); tok != "" {
		s.Token = strings.TrimSpace(tok)
	} else if tok := os.Getenv("SUB2API_SIDECAR_TOKEN"); tok != "" {
		s.Token = strings.TrimSpace(tok)
	}
	// Preserve the historical convenience auto-enable only when no explicit
	// enablement value was supplied. Explicit false/0/invalid values fail closed.
	if !enabledConfigured && s.BaseURL != "" && s.Token != "" {
		s.Enabled = true
	}
	return s
}

// SidecarTLSEnabled reports whether the gateway sidecar is configured enough
// to accept loopback forwards.
func SidecarTLSEnabled(cfg *config.Config) bool {
	settings := ResolveSidecarSettings(cfg)
	if !settings.Enabled || settings.Token == "" {
		return false
	}
	base, err := url.Parse(settings.BaseURL)
	return err == nil && base != nil && base.Host != ""
}

// EncodeSidecarUpstreamProxy returns the base64 x-upstream-proxy value the
// rustls sidecar expects. Empty input means direct connect. Non-empty invalid
// URLs fail closed (no silent direct). socks5:// is upgraded to socks5h:// so
// DNS stays on the account proxy, matching the rest of Sub2API.
func EncodeSidecarUpstreamProxy(proxyURL string) (string, error) {
	normalized, _, err := proxyurl.Parse(proxyURL)
	if err != nil {
		return "", err
	}
	if normalized == "" {
		return "", nil
	}
	return base64.StdEncoding.EncodeToString([]byte(normalized)), nil
}

var sidecarLoopbackClients sync.Map

// NewSidecarLoopbackClient builds the loopback HTTP client used to reach the
// sidecar. Nil means sidecar is not usable.
func NewSidecarLoopbackClient(cfg *config.Config) *http.Client {
	if !SidecarTLSEnabled(cfg) {
		settings := ResolveSidecarSettings(cfg)
		if settings.Enabled {
			if settings.Token == "" {
				slog.Warn("sidecar disabled: empty token")
			} else {
				slog.Warn("sidecar disabled: invalid base_url", "base_url", settings.BaseURL)
			}
		}
		return nil
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       5 * time.Minute,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 0,
	}
	return &http.Client{Transport: transport}
}

// cachedSidecarLoopbackClient reuses one loopback client per sidecar identity
// so round-tripper callers do not rebuild a Transport per request.
func cachedSidecarLoopbackClient(cfg *config.Config) *http.Client {
	if !SidecarTLSEnabled(cfg) {
		return nil
	}
	settings := ResolveSidecarSettings(cfg)
	key := settings.BaseURL + "|" + settings.Token
	if v, ok := sidecarLoopbackClients.Load(key); ok {
		if client, ok := v.(*http.Client); ok {
			return client
		}
	}
	client := NewSidecarLoopbackClient(cfg)
	if client == nil {
		return nil
	}
	actual, _ := sidecarLoopbackClients.LoadOrStore(key, client)
	if c, ok := actual.(*http.Client); ok {
		return c
	}
	return client
}

// ForwardHTTPViaSidecar rewrites req to the local sidecar /v1/http tunnel
// without an account selector. Any untrusted selector already present on req is
// removed before the authenticated loopback hop.
func ForwardHTTPViaSidecar(cfg *config.Config, client *http.Client, req *http.Request, proxyURL string) (*http.Response, error) {
	return forwardHTTPViaSidecar(cfg, client, req, proxyURL, 0)
}

// ForwardHTTPViaSidecarForAccount rewrites req to the local sidecar and binds
// the tunnel to the scheduler-selected account. The caller-provided account ID
// always overrides client-controlled headers.
func ForwardHTTPViaSidecarForAccount(cfg *config.Config, client *http.Client, req *http.Request, proxyURL string, accountID int64) (*http.Response, error) {
	return forwardHTTPViaSidecar(cfg, client, req, proxyURL, accountID)
}

func forwardHTTPViaSidecar(cfg *config.Config, client *http.Client, req *http.Request, proxyURL string, accountID int64) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("sidecar forward is missing request")
	}
	if client == nil {
		client = cachedSidecarLoopbackClient(cfg)
		if client == nil {
			return nil, errors.New("sidecar is not configured")
		}
	}
	settings := ResolveSidecarSettings(cfg)
	originalURL := req.URL.String()
	sidecarBase, err := url.Parse(settings.BaseURL)
	if err != nil {
		return nil, err
	}
	sidecarBase.Path = strings.TrimRight(sidecarBase.Path, "/") + "/v1/http"

	clone := req.Clone(req.Context())
	clone.URL = sidecarBase
	clone.Host = sidecarBase.Host
	clone.Header = req.Header.Clone()
	// Never trust sidecar control headers originating from the client request.
	// Rebuild every selector from scheduler-owned arguments below.
	stripSidecarControlHeaders(clone.Header)
	if accountID > 0 {
		clone.Header.Set(SidecarAccountIDHeader, strconv.FormatInt(accountID, 10))
	}
	// PATCH hook: 调度器切换账号时告知 sidecar（HTTP 用 header；WS 用拨号头，
	// 见 openai_ws_sidecar_account_switch.go）。头值在 strip 之后按
	// scheduler-owned ctx 重建，客户端伪造的同名头已被剥掉。
	if from := openAISidecarAccountSwitchHeaderValue(req.Context(), accountID); from != "" {
		clone.Header.Set(openAISidecarAccountSwitchHeader, from)
	}
	clone.Header.Set("x-s2s-token", settings.Token)
	clone.Header.Set("x-upstream-url", originalURL)
	encodedProxy, err := EncodeSidecarUpstreamProxy(proxyURL)
	if err != nil {
		return nil, err
	}
	if encodedProxy != "" {
		clone.Header.Set("x-upstream-proxy", encodedProxy)
	}
	clone.Header.Del("Host")
	var loopbackKey [32]byte
	var haveLoopbackKey bool

	// E2EE the loopback hop: request body leaves as sealed records; the
	// sidecar decrypts before forwarding upstream and seals the response back.
	if token := settings.Token; token != "" {
		if key, keyErr := DeriveSidecarLoopbackKey(token); keyErr == nil {
			loopbackKey, haveLoopbackKey = key, true
			clone.Header.Set(SidecarE2EEHeader, "1")
			if clone.Body != nil && clone.Body != http.NoBody {
				originalLen := clone.ContentLength
				if originalLen >= 0 {
					clone.Header.Set(SidecarE2EEOrigLenHeader, strconv.FormatInt(originalLen, 10))
				}
				clone.Body = newSealReadCloser(clone.Body, key)
				clone.ContentLength = -1
				clone.Header.Del("Content-Length")
			}
		}
	}
	resp, err := servertiming.Do(client, clone)
	if err != nil {
		return nil, err
	}
	// Decrypt the sealed response body if the sidecar E2EE'd this hop.
	if resp != nil && resp.Header.Get(SidecarE2EEHeader) == "1" && haveLoopbackKey {
		resp.Body = newOpenReadCloser(resp.Body, loopbackKey)
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
		resp.Header.Del(SidecarE2EEHeader)
	}
	return resp, nil
}

// NewSidecarAwareRoundTripper sends official OpenAI OAuth URLs through the
// rustls sidecar and leaves every other request on base.
func NewSidecarAwareRoundTripper(cfg *config.Config, base http.RoundTripper, proxyURL string) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &sidecarAwareRoundTripper{cfg: cfg, base: base, proxyURL: proxyURL}
}

type sidecarAwareRoundTripper struct {
	cfg      *config.Config
	base     http.RoundTripper
	proxyURL string
}

func (t *sidecarAwareRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	cfg := t.cfg
	if cfg == nil {
		cfg = sidecarRuntime()
	}
	if ShouldUseSidecarTLS(req) && SidecarTLSEnabled(cfg) {
		return ForwardHTTPViaSidecar(cfg, nil, req, t.proxyURL)
	}
	return t.base.RoundTrip(req)
}

// ApplySidecarHTTPClient clones client and routes matching OpenAI OAuth URLs
// through the sidecar. A nil cfg falls back to the runtime config installed by
// SetSidecarRuntimeConfig. The original pooled client is never mutated.
func ApplySidecarHTTPClient(cfg *config.Config, client *http.Client, proxyURL string) *http.Client {
	if client == nil {
		return nil
	}
	if cfg == nil {
		cfg = sidecarRuntime()
	}
	if !SidecarTLSEnabled(cfg) {
		return client
	}
	clone := *client
	clone.Transport = NewSidecarAwareRoundTripper(cfg, client.Transport, proxyURL)
	return &clone
}
