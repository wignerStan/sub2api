package service

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShouldUseSidecarTLSURL(t *testing.T) {
	t.Parallel()

	yes := []string{
		"https://chatgpt.com/backend-api/codex/responses",
		"https://chatgpt.com/backend-api/codex/responses/",
		"https://chatgpt.com/backend-api/codex/responses?stream=true",
		"wss://chatgpt.com/backend-api/codex/responses",
		"https://chatgpt.com/backend-api/codex/responses/compact",
		"https://chatgpt.com/backend-api/codex/responses/compact/detail",
		"https://chatgpt.com/backend-api/codex/responses/input_tokens",
		"https://chatgpt.com/backend-api/codex/models",
		"https://chatgpt.com/backend-api/codex/alpha/search",
		"https://chatgpt.com/backend-api/codex/realtime/calls",
		"https://chatgpt.com/backend-api/codex/cua",
		"wss://chatgpt.com/backend-api/codex/call_proxy",
		"wss://chatgpt.com/backend-api/codex/call_123",
		"https://ab.chatgpt.com/backend-api/codex/responses",
		"https://chatgpt.com/backend-api/codex/responses/../../../backend-api/codex/models",
	}
	for _, raw := range yes {
		require.True(t, ShouldUseSidecarTLSURL(raw), raw)
	}

	no := []string{
		"",
		"://bad",
		"https://api.openai.com/v1/responses",
		"https://api.openai.com/v1/models",
		"https://chatgpt.com/backend-api/wham/usage",
		"https://chatgpt.com/backend-api/codexfoo/responses",
		"https://chatgpt.com/backend-api/codex/../wham/usage",
		"https://notchatgpt.com/backend-api/codex/responses",
		"https://chatgpt.com.example/backend-api/codex/responses",
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

	req, err = http.NewRequest(http.MethodGet, "https://chatgpt.com/backend-api/codex/models", nil)
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
