package service

import (
	"context"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/gin-gonic/gin"
)

type OpenAICodexGuardianRoute string

const (
	OpenAICodexGuardianRouteNone       OpenAICodexGuardianRoute = ""
	OpenAICodexGuardianRouteReview     OpenAICodexGuardianRoute = "guardian"
	OpenAICodexGuardianRouteClassifier OpenAICodexGuardianRoute = "guardian-classifier"

	codexGuardianClassifierModel = "gpt-5.6-luna"
)

type openAICodexGuardianRouteContextKey struct{}

// WithOpenAICodexGuardianRoute recognizes stock Codex Guardian traffic that
// fell back to /responses because a custom provider cannot satisfy Codex's
// first-party backend/auth gate. Only internally consistent official-Codex
// requests are upgraded to the dedicated unmetered backend routes.
func WithOpenAICodexGuardianRoute(
	ctx context.Context,
	c *gin.Context,
	body []byte,
	requestedModel string,
	forceCodexCLI bool,
) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	route := detectOpenAICodexGuardianRoute(c, body, requestedModel, forceCodexCLI)
	if route == OpenAICodexGuardianRouteNone {
		return ctx
	}
	ctx = context.WithValue(ctx, openAICodexGuardianRouteContextKey{}, route)
	// The provider route is unmetered, so provider-cost profitability gates
	// must not reject an otherwise valid Guardian request.
	return WithOpenAIProfitControlSuppressed(ctx)
}

func detectOpenAICodexGuardianRoute(
	c *gin.Context,
	body []byte,
	requestedModel string,
	forceCodexCLI bool,
) OpenAICodexGuardianRoute {
	if c == nil || c.Request == nil || openAIResponsesRequestPathSuffix(c) != "" {
		return OpenAICodexGuardianRouteNone
	}

	if !forceCodexCLI {
		userAgent := strings.TrimSpace(c.GetHeader("User-Agent"))
		originator := strings.TrimSpace(c.GetHeader("originator"))
		if !openai.IsCodexOfficialClientRequestStrict(userAgent) &&
			!openai.IsCodexOfficialClientOriginator(originator) {
			return OpenAICodexGuardianRouteNone
		}
		if !openai.EvaluateEngineFingerprint(c.Request.Header, body, openai.DefaultEngineFingerprintSignals) {
			return OpenAICodexGuardianRouteNone
		}
	}

	headerMetadata := c.GetHeader(codexTurnMetadataHeader)
	bodyMetadata := openAIRequestPayloadView(body).Get("client_metadata.x-codex-turn-metadata").String()
	if !hasUnambiguousOpenAICodexGuardianSubagent(
		c.GetHeader(openAISubagentHeader),
		codexSubagentKindFromMetadata(headerMetadata),
		codexSubagentKindFromMetadata(bodyMetadata),
	) {
		return OpenAICodexGuardianRouteNone
	}

	model := strings.ToLower(strings.TrimSpace(requestedModel))
	responsesLite := isOpenAIResponsesLiteHeader(c.GetHeader(responsesLiteHeaderKey)) ||
		isOpenAIResponsesLiteWebSocketPayload(body)
	if responsesLite {
		if model == codexGuardianClassifierModel {
			return OpenAICodexGuardianRouteClassifier
		}
		return OpenAICodexGuardianRouteNone
	}

	if model == codexAutoReviewModel || model == codexGuardianClassifierModel {
		return OpenAICodexGuardianRouteReview
	}
	return OpenAICodexGuardianRouteNone
}

func hasUnambiguousOpenAICodexGuardianSubagent(candidates ...string) bool {
	seen := false
	for _, candidate := range candidates {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if candidate == "" {
			continue
		}
		if candidate != "guardian" {
			return false
		}
		seen = true
	}
	return seen
}

func OpenAICodexGuardianRouteFromContext(ctx context.Context) OpenAICodexGuardianRoute {
	if ctx == nil {
		return OpenAICodexGuardianRouteNone
	}
	route, _ := ctx.Value(openAICodexGuardianRouteContextKey{}).(OpenAICodexGuardianRoute)
	switch route {
	case OpenAICodexGuardianRouteReview, OpenAICodexGuardianRouteClassifier:
		return route
	default:
		return OpenAICodexGuardianRouteNone
	}
}

func IsOpenAICodexGuardianRequest(ctx context.Context) bool {
	return OpenAICodexGuardianRouteFromContext(ctx) != OpenAICodexGuardianRouteNone
}

func openAICodexBackendURLForContext(ctx context.Context) string {
	switch OpenAICodexGuardianRouteFromContext(ctx) {
	case OpenAICodexGuardianRouteReview:
		return chatgptCodexGuardianURL
	case OpenAICodexGuardianRouteClassifier:
		return chatgptCodexGuardianClassifierURL
	default:
		return chatgptCodexURL
	}
}

// Guardian uses a separate unmetered provider route. Normal Codex quota
// cooldowns therefore do not make the credential unhealthy for Guardian.
// Auth/admin/expiry/overload/transport health still apply.
func isOpenAICodexGuardianAccountSchedulable(account *Account) bool {
	if account == nil || !account.IsOpenAI() || !account.IsOpenAIOAuthLike() {
		return false
	}
	if !account.IsActive() || !account.Schedulable {
		return false
	}
	now := time.Now()
	if account.AutoPauseOnExpired && account.ExpiresAt != nil && !now.Before(*account.ExpiresAt) {
		return false
	}
	if account.OverloadUntil != nil && now.Before(*account.OverloadUntil) {
		return false
	}
	if account.TempUnschedulableUntil != nil && now.Before(*account.TempUnschedulableUntil) {
		return false
	}
	return true
}

func (s *OpenAIGatewayService) getOpenAIAccountForSchedulingContext(ctx context.Context, accountID int64) (*Account, error) {
	if IsOpenAICodexGuardianRequest(ctx) && s != nil && s.accountRepo != nil {
		return s.accountRepo.GetByID(ctx, accountID)
	}
	return s.getSchedulableAccount(ctx, accountID)
}

func shouldClearOpenAIStickySessionForRequest(ctx context.Context, account *Account, requestedModel string) bool {
	if IsOpenAICodexGuardianRequest(ctx) {
		return !isOpenAICodexGuardianAccountSchedulable(account)
	}
	return shouldClearStickySession(account, requestedModel)
}
