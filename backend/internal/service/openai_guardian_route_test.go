package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func guardianTestContext(t *testing.T, body []byte, model string, lite bool) (*gin.Context, context.Context) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "http://sub2api.local/v1/responses", nil)
	c.Request.Header.Set("User-Agent", CodexCanonicalUserAgent())
	c.Request.Header.Set("x-codex-window-id", "window-guardian:0")
	c.Request.Header.Set(openAISubagentHeader, "guardian")
	if lite {
		c.Request.Header.Set(responsesLiteHeaderKey, "true")
	}
	ctx := WithOpenAICodexGuardianRoute(c.Request.Context(), c, body, model, false)
	return c, ctx
}

func TestOpenAICodexGuardianRouteRecognizesFullReviewFallback(t *testing.T) {
	_, ctx := guardianTestContext(t, []byte(`{"model":"codex-auto-review"}`), codexAutoReviewModel, false)
	require.Equal(t, OpenAICodexGuardianRouteReview, OpenAICodexGuardianRouteFromContext(ctx))
	require.Equal(t, chatgptCodexGuardianURL, openAICodexBackendURLForContext(ctx))
}

func TestOpenAICodexGuardianRouteRecognizesClassifierFallback(t *testing.T) {
	_, ctx := guardianTestContext(
		t,
		[]byte(`{"type":"response.create","model":"gpt-5.6-luna","client_metadata":{"ws_request_header_x_openai_internal_codex_responses_lite":"true"}}`),
		codexGuardianClassifierModel,
		true,
	)
	require.Equal(t, OpenAICodexGuardianRouteClassifier, OpenAICodexGuardianRouteFromContext(ctx))
	require.Equal(t, chatgptCodexGuardianClassifierURL, openAICodexBackendURLForContext(ctx))
}

func TestOpenAICodexGuardianRouteRejectsNormalReviewAndSpoofedSignals(t *testing.T) {
	c, _ := guardianTestContext(t, []byte(`{"model":"codex-auto-review"}`), codexAutoReviewModel, false)
	c.Request.Header.Set(openAISubagentHeader, "review")
	ctx := WithOpenAICodexGuardianRoute(c.Request.Context(), c, []byte(`{"model":"codex-auto-review"}`), codexAutoReviewModel, false)
	require.False(t, IsOpenAICodexGuardianRequest(ctx))

	c, _ = guardianTestContext(t, []byte(`{"model":"codex-auto-review"}`), codexAutoReviewModel, false)
	c.Request.Header.Set("User-Agent", "curl/8.0")
	c.Request.Header.Del("originator")
	ctx = WithOpenAICodexGuardianRoute(c.Request.Context(), c, []byte(`{"model":"codex-auto-review"}`), codexAutoReviewModel, false)
	require.False(t, IsOpenAICodexGuardianRequest(ctx))

	c, _ = guardianTestContext(t, []byte(`{"model":"codex-auto-review"}`), codexAutoReviewModel, false)
	c.Request.Header.Del("x-codex-window-id")
	ctx = WithOpenAICodexGuardianRoute(c.Request.Context(), c, []byte(`{"model":"codex-auto-review"}`), codexAutoReviewModel, false)
	require.False(t, IsOpenAICodexGuardianRequest(ctx))
}

func TestOpenAICodexGuardianRouteRejectsConflictingMetadata(t *testing.T) {
	c, _ := guardianTestContext(t, []byte(`{"model":"codex-auto-review"}`), codexAutoReviewModel, false)
	c.Request.Header.Set(codexTurnMetadataHeader, `{"subagent_kind":"review"}`)
	ctx := WithOpenAICodexGuardianRoute(c.Request.Context(), c, []byte(`{"model":"codex-auto-review"}`), codexAutoReviewModel, false)
	require.False(t, IsOpenAICodexGuardianRequest(ctx))
}

func TestOpenAICodexGuardianAccountSchedulableIgnoresNormalQuotaOnly(t *testing.T) {
	now := time.Now()
	quotaReset := now.Add(4 * time.Hour)
	account := &Account{
		Platform:         PlatformOpenAI,
		Type:             AccountTypeOAuth,
		Status:           StatusActive,
		Schedulable:      true,
		RateLimitResetAt: &quotaReset,
	}
	require.True(t, isOpenAICodexGuardianAccountSchedulable(account))

	overload := now.Add(time.Minute)
	account.OverloadUntil = &overload
	require.False(t, isOpenAICodexGuardianAccountSchedulable(account))
	account.OverloadUntil = nil

	temp := now.Add(time.Minute)
	account.TempUnschedulableUntil = &temp
	require.False(t, isOpenAICodexGuardianAccountSchedulable(account))
}

func TestOpenAICodexGuardianRuntimeBlockIgnoresOnly429(t *testing.T) {
	svc := &OpenAIGatewayService{}
	account := &Account{
		ID:          901,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeOAuth,
		Status:      StatusActive,
		Schedulable: true,
	}
	guardianCtx := context.WithValue(context.Background(), openAICodexGuardianRouteContextKey{}, OpenAICodexGuardianRouteReview)

	svc.BlockAccountScheduling(account, time.Now().Add(time.Minute), "429")
	require.False(t, svc.isOpenAIAccountRequestRuntimeBlockedForContext(guardianCtx, account, codexAutoReviewModel))

	svc.ClearAccountSchedulingBlock(account.ID)
	svc.BlockAccountScheduling(account, time.Now().Add(time.Minute), "openai_access_state")
	require.True(t, svc.isOpenAIAccountRequestRuntimeBlockedForContext(guardianCtx, account, codexAutoReviewModel))
}

func TestOpenAICodexGuardianHeadersAreForwardable(t *testing.T) {
	require.True(t, openaiAllowedHeaders[openAISubagentHeader])
	require.True(t, openaiAllowedHeaders[codexParentThreadIDHeader])
	require.True(t, openaiPassthroughAllowedHeaders[openAISubagentHeader])
	require.True(t, openaiPassthroughAllowedHeaders[codexParentThreadIDHeader])
}
