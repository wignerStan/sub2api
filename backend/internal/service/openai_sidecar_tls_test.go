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
		"https://chatgpt.com/backend-api/settings/account_user_setting",
		"https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27",
		"https://chatgpt.com/backend-api/files",
		"https://chatgpt.com/",
		"https://ab.chatgpt.com/backend-api/wham/usage",
		"https://chat.openai.com/backend-api/codex/responses",
		"https://auth.openai.com/oauth/token",
		"https://auth.openai.com/api/accounts/v1/agent/runtime/task/register",
		"https://chatgpt.com/backend-api/codex/responses/../../../backend-api/wham/usage",
	}
	for _, raw := range yes {
		require.True(t, ShouldUseSidecarTLSURL(raw), raw)
	}

	no := []string{
		"",
		"://bad",
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
	t.Parallel()
	require.False(t, SidecarTLSEnabled(nil))
	require.False(t, SidecarTLSEnabled(&config.Config{}))

	cfg := &config.Config{}
	cfg.Gateway.Sidecar.Enabled = true
	cfg.Gateway.Sidecar.BaseURL = "http://127.0.0.1:21333"
	cfg.Gateway.Sidecar.Token = "tok"
	require.True(t, SidecarTLSEnabled(cfg))
}

func sidecarTestConfig(baseURL string) *config.Config {
	cfg := &config.Config{}
	cfg.Gateway.Sidecar.Enabled = true
	cfg.Gateway.Sidecar.BaseURL = baseURL
	cfg.Gateway.Sidecar.Token = "test-token"
	return cfg
}

func TestApplySidecarHTTPClientRoutesOAuthHosts(t *testing.T) {
	t.Parallel()

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
	client := ApplySidecarHTTPClient(sidecarTestConfig(sidecar.URL), pooled, "")
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
	t.Parallel()

	var hits atomic.Int64
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer sidecar.Close()

	prev := sidecarRuntimeConfig.Load()
	t.Cleanup(func() { sidecarRuntimeConfig.Store(prev) })
	SetSidecarRuntimeConfig(sidecarTestConfig(sidecar.URL))

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
	SetSidecarRuntimeConfig(&config.Config{})
	same := ApplySidecarHTTPClient(nil, client, "")
	require.Same(t, client, same)
}
