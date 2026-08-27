package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestForwardResponsesInputTokensCustomRelayUsesLocalEstimate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses/input_tokens", nil)

	upstream := &httpUpstreamRecorder{}
	svc := &OpenAIGatewayService{
		cfg:          &config.Config{Security: config.SecurityConfig{URLAllowlist: config.URLAllowlistConfig{Enabled: false}}},
		httpUpstream: upstream,
	}
	account := &Account{
		ID:          159,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Concurrency: 1,
		Credentials: map[string]any{
			"api_key":  "relay-key",
			"base_url": "https://relay.example/v1",
		},
	}
	body := []byte(`{"model":"gpt-5.4","instructions":"Be concise.","input":"hello world","tools":[{"type":"function","name":"lookup","description":"Look up a value","parameters":{"type":"object"}}]}`)

	err := svc.ForwardResponsesInputTokens(context.Background(), c, account, body)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, "response.input_tokens", gjson.Get(recorder.Body.String(), "object").String())
	require.Positive(t, gjson.Get(recorder.Body.String(), "input_tokens").Int())
	require.Nil(t, upstream.lastReq, "custom relay must not receive /v1/responses/input_tokens")
}

func TestForwardResponsesInputTokensGrokOAuthUsesLocalEstimate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses/input_tokens", nil)

	upstream := &httpUpstreamRecorder{}
	svc := &OpenAIGatewayService{httpUpstream: upstream}
	account := &Account{ID: 160, Platform: PlatformGrok, Type: AccountTypeOAuth}
	body := []byte(`{"model":"grok-4.1","input":"hello world"}`)

	err := svc.ForwardResponsesInputTokens(context.Background(), c, account, body)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, "response.input_tokens", gjson.Get(recorder.Body.String(), "object").String())
	require.Positive(t, gjson.Get(recorder.Body.String(), "input_tokens").Int())
	require.Nil(t, upstream.lastReq)
}

func TestForwardResponsesInputTokensUpstream404FallsBackLocally(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses/input_tokens", nil)

	upstream := &httpUpstreamRecorder{resp: &http.Response{
		StatusCode: http.StatusNotFound,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"error":{"type":"invalid_request_error","message":"Invalid URL (POST /v1/responses/input_tokens)"}}`)),
	}}
	svc := &OpenAIGatewayService{
		cfg:          &config.Config{Security: config.SecurityConfig{URLAllowlist: config.URLAllowlistConfig{Enabled: false}}},
		httpUpstream: upstream,
	}
	account := &Account{
		ID:          171,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Concurrency: 1,
		Credentials: map[string]any{
			"api_key":  "official-key",
			"base_url": "https://api.openai.com/v1",
		},
	}
	body := []byte(`{"model":"gpt-5.4","instructions":"Be concise.","input":"hello world"}`)

	err := svc.ForwardResponsesInputTokens(context.Background(), c, account, body)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, "response.input_tokens", gjson.Get(recorder.Body.String(), "object").String())
	require.Positive(t, gjson.Get(recorder.Body.String(), "input_tokens").Int())
	require.NotNil(t, upstream.lastReq)
}

func TestForwardResponsesInputTokensOAuthConvergesMetadataAndPreservesSchema(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses/input_tokens", nil)
	c.Request.Header.Set("User-Agent", "codex_cli_rs/0.147.0 (Mac OS 26.5; arm64) iTerm2")
	c.Request.Header.Set("originator", "codex_cli_rs")
	c.Request.Header.Set("session-id", "client-header-session")
	c.Request.Header.Set("x-codex-installation-id", "client-header-install")
	c.Request.Header.Set("x-codex-turn-state", "client-turn-state")
	c.Request.Header.Set("Accept", "text/html")
	c.Request.Header.Set("Accept-Language", "zh-CN")

	upstream := &httpUpstreamRecorder{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"object":"response.input_tokens","input_tokens":37}`)),
	}}
	svc := &OpenAIGatewayService{cfg: &config.Config{}, httpUpstream: upstream}
	account := newTestOAuthAccount(172, map[string]any{codexFingerprintModeExtraKey: "session"})
	account.Concurrency = 1
	account.Credentials = map[string]any{"access_token": "oauth-token"}
	body := []byte(`{
		"model":"gpt-5.4",
		"conversation":{"id":"conv_123"},
		"instructions":"Be concise.",
		"input":"hello world",
		"parallel_tool_calls":true,
		"personality":"pragmatic",
		"reasoning":{"effort":"high"},
		"text":{"verbosity":"low"},
		"truncation":"auto",
		"future_option":{"keep":true},
		"prompt_cache_key":"client-body-session",
		"client_metadata":{
			"session_id":"client-body-session",
			"x-codex-installation-id":"client-body-install",
			"cwd":"/Users/alice/private-repo",
			"os":"darwin",
			"trace_id":"client-trace"
		}
	}`)

	err := svc.ForwardResponsesInputTokens(context.Background(), c, account, body)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.NotNil(t, upstream.lastReq)
	require.Equal(t, "https://api.openai.com/v1/responses/input_tokens", upstream.lastReq.URL.String())
	require.Equal(t, "application/json", upstream.lastReq.Header.Get("Accept"))
	require.Equal(t, "en-US", upstream.lastReq.Header.Get("Accept-Language"))
	require.Empty(t, upstream.lastReq.Header.Get("x-codex-turn-state"))
	require.NotEqual(t, "client-header-install", upstream.lastReq.Header.Get("x-codex-installation-id"))
	require.NotEqual(t, "client-header-session", upstream.lastReq.Header.Get("session-id"))
	require.Equal(t, "remote_compaction_v2", upstream.lastReq.Header.Get("x-codex-beta-features"))

	// Keep the complete documented request surface (and future fields) while
	// reducing only the association-bearing Codex metadata.
	require.Equal(t, "conv_123", gjson.GetBytes(upstream.lastBody, "conversation.id").String())
	require.True(t, gjson.GetBytes(upstream.lastBody, "parallel_tool_calls").Bool())
	require.Equal(t, "pragmatic", gjson.GetBytes(upstream.lastBody, "personality").String())
	require.Equal(t, "high", gjson.GetBytes(upstream.lastBody, "reasoning.effort").String())
	require.Equal(t, "low", gjson.GetBytes(upstream.lastBody, "text.verbosity").String())
	require.Equal(t, "auto", gjson.GetBytes(upstream.lastBody, "truncation").String())
	require.True(t, gjson.GetBytes(upstream.lastBody, "future_option.keep").Bool())
	requireNoLeakedCodexClientMetadata(t, upstream.lastBody)
	require.NotEqual(t, "client-body-install", gjson.GetBytes(upstream.lastBody, "client_metadata.x-codex-installation-id").String())
	require.NotEqual(t, "client-body-session", gjson.GetBytes(upstream.lastBody, "client_metadata.session_id").String())
	require.Equal(t,
		gjson.GetBytes(upstream.lastBody, "client_metadata.session_id").String(),
		gjson.GetBytes(upstream.lastBody, "prompt_cache_key").String(),
	)
	require.Equal(t,
		upstream.lastReq.Header.Get("session-id"),
		gjson.GetBytes(upstream.lastBody, "client_metadata.session_id").String(),
	)
}
