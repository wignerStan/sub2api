package service

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/proxyurl"
	"github.com/Wei-Shaw/sub2api/internal/pkg/servertiming"
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
	return isOpenAIOAuthSidecarHost(u.Hostname())
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

// SidecarTLSEnabled reports whether the gateway sidecar is configured enough
// to accept loopback forwards.
func SidecarTLSEnabled(cfg *config.Config) bool {
	if cfg == nil || !cfg.Gateway.Sidecar.Enabled {
		return false
	}
	if strings.TrimSpace(cfg.Gateway.Sidecar.Token) == "" {
		return false
	}
	base, err := url.Parse(cfg.Gateway.Sidecar.BaseURL)
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
		if cfg != nil && cfg.Gateway.Sidecar.Enabled {
			if strings.TrimSpace(cfg.Gateway.Sidecar.Token) == "" {
				slog.Warn("sidecar disabled: empty token")
			} else {
				slog.Warn("sidecar disabled: invalid base_url", "base_url", cfg.Gateway.Sidecar.BaseURL)
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
	key := strings.TrimSpace(cfg.Gateway.Sidecar.BaseURL) + "|" + strings.TrimSpace(cfg.Gateway.Sidecar.Token)
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

// ForwardHTTPViaSidecar rewrites req to the local sidecar /v1/http tunnel.
func ForwardHTTPViaSidecar(cfg *config.Config, client *http.Client, req *http.Request, proxyURL string) (*http.Response, error) {
	if cfg == nil || req == nil || req.URL == nil {
		return nil, errors.New("sidecar forward is missing request or config")
	}
	if client == nil {
		client = cachedSidecarLoopbackClient(cfg)
		if client == nil {
			return nil, errors.New("sidecar is not configured")
		}
	}
	originalURL := req.URL.String()
	sidecarBase, err := url.Parse(cfg.Gateway.Sidecar.BaseURL)
	if err != nil {
		return nil, err
	}
	sidecarBase.Path = strings.TrimRight(sidecarBase.Path, "/") + "/v1/http"

	clone := req.Clone(req.Context())
	clone.URL = sidecarBase
	clone.Host = sidecarBase.Host
	clone.Header = req.Header.Clone()
	clone.Header.Set("x-s2s-token", cfg.Gateway.Sidecar.Token)
	clone.Header.Set("x-upstream-url", originalURL)
	encodedProxy, err := EncodeSidecarUpstreamProxy(proxyURL)
	if err != nil {
		return nil, err
	}
	if encodedProxy != "" {
		clone.Header.Set("x-upstream-proxy", encodedProxy)
	}
	clone.Header.Del("Host")
	return servertiming.Do(client, clone)
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
