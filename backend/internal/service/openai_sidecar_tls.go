package service

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/proxyurl"
)

const chatgptCodexPathPrefix = "/backend-api/codex"

// ShouldUseSidecarTLS reports whether this upstream request should leave through
// the local rustls sidecar. Every ChatGPT Codex endpoint under
// /backend-api/codex (responses, compact, models, input_tokens, alpha/search,
// live/CUA, and future siblings) uses that TLS disguise. api.openai.com and
// other chatgpt.com surfaces (for example /backend-api/wham) stay on the
// normal Go transport.
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
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host != "chatgpt.com" && !strings.HasSuffix(host, ".chatgpt.com") {
		return false
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(u.Path, "/"))
	return cleaned == chatgptCodexPathPrefix ||
		strings.HasPrefix(cleaned, chatgptCodexPathPrefix+"/")
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
