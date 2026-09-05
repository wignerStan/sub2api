package service

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/imroc/req/v3"
	"github.com/stretchr/testify/assert"
)

func TestOpenAIQuotaService_HookDirectClient(t *testing.T) {
	svc := &OpenAIQuotaService{}
	hookCalled := false

	svc.SetQuotaClientFactory(func(ctx context.Context, accountID int64, proxyURL string) (*req.Client, error) {
		hookCalled = true
		assert.Equal(t, int64(42), accountID)
		assert.Equal(t, "http://127.0.0.1:8080", proxyURL)
		return req.C(), nil
	})

	client, err := svc.getQuotaClient(context.Background(), 42, "http://127.0.0.1:8080")
	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.True(t, hookCalled)
}

func TestBuildCodexCommonHeaders_CodexTUIConformant(t *testing.T) {
	headers := buildCodexCommonHeaders("test-token", "acc-123", true)

	assert.Equal(t, "Bearer test-token", headers["authorization"])
	assert.Equal(t, "acc-123", headers["chatgpt-account-id"])
	assert.Equal(t, "true", headers["x-openai-fedramp"])
	assert.Equal(t, "codex-1", headers["openai-beta"])
	assert.Equal(t, openai.CodexDefaultOriginator, headers["originator"])
	assert.Equal(t, CodexCanonicalUserAgent(), headers["user-agent"])
	assert.Equal(t, "application/json", headers["accept"])

	// Must NOT contain browser impersonation headers
	assert.NotContains(t, headers, "sec-fetch-site")
	assert.NotContains(t, headers, "sec-fetch-mode")
	assert.NotContains(t, headers, "sec-fetch-dest")
	assert.NotContains(t, headers, "priority")
}
