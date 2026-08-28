package service

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func TestShouldUseSidecarTLSURL(t *testing.T) {
	t.Parallel()

	yes := []string{
		"https://chatgpt.com/backend-api/codex/responses",
		"https://chatgpt.com/backend-api/codex/responses/",
		"https://chatgpt.com/backend-api/codex/responses?stream=true",
		"wss://chatgpt.com/backend-api/codex/responses",
		"https://chatgpt.com/backend-api/codex/models",
		"https://chatgpt.com/backend-api/wham/usage",
		"https://chatgpt.com/backend-api/wham/rate-limit-reset-credits",
		"https://chatgpt.com/backend-api/wham/rate-limit-reset-credits/consume",
		"https://ab.chatgpt.com/backend-api/wham/usage",
		"https://chat.openai.com/backend-api/codex/responses",
		"https://auth.openai.com/oauth/token",
		"https://auth.openai.com/api/v1/oauth/token",
		"https://auth.openai.com/api/accounts/v1/user-auth-credential/whoami",
		"https://auth.openai.com/api/accounts/v1/agent/runtime/task/register",
	}
	for _, raw := range yes {
		require.True(t, ShouldUseSidecarTLSURL(raw), raw)
	}

	no := []string{
		"",
		"://bad",
		"https://chatgpt.com/",
		"https://chatgpt.com/backend-api/settings/account_user_setting",
		"https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27",
		"https://chatgpt.com/backend-api/subscriptions",
		"http://chatgpt.com/backend-api/codex/responses",
		"ws://chatgpt.com/backend-api/codex/call_proxy",
		"https://api.openai.com/v1/responses",
		"https://api.openai.com/v1/models",
		"https://notchatgpt.com/backend-api/codex/responses",
		"https://chatgpt.com.example/backend-api/codex/responses",
		"https://auth.openai.com.evil.example/oauth/token",
	}
	for _, raw := range no {
		require.False(t, ShouldUseSidecarTLSURL(raw), raw)
	}
}

func TestShouldUseSidecarTLSRequest(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", nil)
	require.NoError(t, err)
	require.True(t, ShouldUseSidecarTLS(req))

	req, err = http.NewRequest(http.MethodGet, "https://chatgpt.com/backend-api/wham/usage", nil)
	require.NoError(t, err)
	require.True(t, ShouldUseSidecarTLS(req))

	req, err = http.NewRequest(http.MethodPost, "https://auth.openai.com/oauth/token", nil)
	require.NoError(t, err)
	require.True(t, ShouldUseSidecarTLS(req))

	req, err = http.NewRequest(http.MethodGet, "https://api.openai.com/v1/models", nil)
	require.NoError(t, err)
	require.False(t, ShouldUseSidecarTLS(req))
	require.False(t, ShouldUseSidecarTLS(nil))
}

func TestEncodeSidecarUpstreamProxy(t *testing.T) {
	t.Parallel()

	encoded, err := EncodeSidecarUpstreamProxy("")
	require.NoError(t, err)
	require.Empty(t, encoded)

	encoded, err = EncodeSidecarUpstreamProxy("   ")
	require.NoError(t, err)
	require.Empty(t, encoded)

	encoded, err = EncodeSidecarUpstreamProxy("http://127.0.0.1:8080")
	require.NoError(t, err)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:8080", string(decoded))

	encoded, err = EncodeSidecarUpstreamProxy("socks5://127.0.0.1:1080")
	require.NoError(t, err)
	decoded, err = base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	require.Equal(t, "socks5h://127.0.0.1:1080", string(decoded))

	_, err = EncodeSidecarUpstreamProxy("ftp://127.0.0.1:21")
	require.Error(t, err)
	_, err = EncodeSidecarUpstreamProxy("://bad")
	require.Error(t, err)
}

func TestSidecarTLSEnabled(t *testing.T) {
	t.Setenv("GATEWAY_SIDECAR_BASE_URL", "http://127.0.0.1:21333")
	t.Setenv("GATEWAY_SIDECAR_TOKEN", "tok")
	t.Setenv("SUB2API_SIDECAR_ENABLED", "")

	for _, value := range []string{"false", "FALSE", "0", "invalid"} {
		t.Run("explicit_"+value+"_stays_disabled", func(t *testing.T) {
			t.Setenv("GATEWAY_SIDECAR_ENABLED", value)
			require.False(t, SidecarTLSEnabled(nil))
		})
	}

	t.Setenv("GATEWAY_SIDECAR_ENABLED", "true")
	require.True(t, SidecarTLSEnabled(nil))
	t.Setenv("GATEWAY_SIDECAR_ENABLED", "1")
	require.True(t, SidecarTLSEnabled(nil))

	// With no explicit enablement value, base URL + token retain the historical
	// convenience auto-enable behavior.
	t.Setenv("GATEWAY_SIDECAR_ENABLED", "")
	require.True(t, SidecarTLSEnabled(nil))
}

func TestResolveSidecarSettingsEnablementPrecedence(t *testing.T) {
	t.Setenv("GATEWAY_SIDECAR_BASE_URL", "http://127.0.0.1:21333")
	t.Setenv("GATEWAY_SIDECAR_TOKEN", "tok")
	t.Setenv("GATEWAY_SIDECAR_ENABLED", "0")
	t.Setenv("SUB2API_SIDECAR_ENABLED", "true")
	require.False(t, ResolveSidecarSettings(nil).Enabled, "gateway setting must take precedence")

	t.Setenv("GATEWAY_SIDECAR_ENABLED", "")
	require.True(t, ResolveSidecarSettings(nil).Enabled, "sub2api fallback should be honored")
}

func sidecarTestConfig(t *testing.T, baseURL string) *config.Config {
	t.Setenv("GATEWAY_SIDECAR_ENABLED", "true")
	t.Setenv("GATEWAY_SIDECAR_BASE_URL", baseURL)
	t.Setenv("GATEWAY_SIDECAR_TOKEN", "test-token")
	return &config.Config{}
}

func TestForwardHTTPViaSidecarTrustedAccountSelector(t *testing.T) {
	seen := make(chan [3]string, 2)
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- [3]string{
			r.Header.Get(SidecarAccountIDHeader),
			r.Header.Get("x-account-id"),
			r.Header.Get("x-upstream-proxy"),
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer sidecar.Close()
	cfg := sidecarTestConfig(t, sidecar.URL)

	trustedReq, err := http.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", nil)
	require.NoError(t, err)
	trustedReq.Header.Set(SidecarAccountIDHeader, "999")
	trustedReq.Header.Set("x-account-id", "998")
	trustedReq.Header.Set("x-upstream-proxy", "client-controlled-proxy")
	resp, err := ForwardHTTPViaSidecarForAccount(cfg, sidecar.Client(), trustedReq, "", 42)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, [3]string{"42", "", ""}, <-seen)

	unscopedReq, err := http.NewRequest(http.MethodPost, "https://auth.openai.com/oauth/token", nil)
	require.NoError(t, err)
	unscopedReq.Header.Set(SidecarAccountIDHeader, "997")
	unscopedReq.Header.Set("x-account-id", "996")
	unscopedReq.Header.Set("x-upstream-proxy", "client-controlled-proxy")
	resp, err = ForwardHTTPViaSidecar(cfg, sidecar.Client(), unscopedReq, "")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, [3]string{"", "", ""}, <-seen)
}

func TestApplySidecarHTTPClientRoutesOAuthHosts(t *testing.T) {
	var baseHits atomic.Int64
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		baseHits.Add(1)
		return &http.Response{StatusCode: http.StatusTeapot, Body: io.NopCloser(strings.NewReader(""))}, nil
	})

	var sidecarTunneled atomic.Int64
	var gotUpstreamURL atomic.Value
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/http" || r.Header.Get("x-s2s-token") != "test-token" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sidecarTunneled.Add(1)
		gotUpstreamURL.Store(r.Header.Get("x-upstream-url"))
		w.WriteHeader(http.StatusOK)
	}))
	defer sidecar.Close()

	pooled := &http.Client{Transport: base, Timeout: 5 * time.Second}
	client := ApplySidecarHTTPClient(sidecarTestConfig(t, sidecar.URL), pooled, "")
	require.NotSame(t, pooled, client)

	// OAuth hosts tunnel through the sidecar.
	for _, target := range []string{
		"https://chatgpt.com/backend-api/codex/responses",
		"https://auth.openai.com/oauth/token",
	} {
		req, err := http.NewRequest(http.MethodPost, target, nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err, target)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, target)
	}
	require.Equal(t, int64(2), sidecarTunneled.Load())
	require.Contains(t, gotUpstreamURL.Load(), "auth.openai.com/oauth/token")

	req, err := http.NewRequest(http.MethodGet, "https://api.openai.com/v1/models", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusTeapot, resp.StatusCode)

	require.Equal(t, int64(1), baseHits.Load(), "api.openai.com must stay on the base transport")
	require.Equal(t, int64(2), sidecarTunneled.Load())
}

func TestApplySidecarHTTPClientRuntimeConfigFallback(t *testing.T) {
	var hits atomic.Int64
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer sidecar.Close()

	sidecarTestConfig(t, sidecar.URL)

	client := ApplySidecarHTTPClient(nil, &http.Client{Timeout: 5 * time.Second}, "")
	require.NotNil(t, client)

	req, err := http.NewRequest(http.MethodPost, "https://auth.openai.com/oauth/token", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int64(1), hits.Load())

	// Disabled runtime config leaves the pooled client untouched.
	t.Setenv("GATEWAY_SIDECAR_ENABLED", "false")
	same := ApplySidecarHTTPClient(nil, client, "")
	require.Same(t, client, same)
}
