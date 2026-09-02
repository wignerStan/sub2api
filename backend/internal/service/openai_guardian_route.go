package service

import (
	"context"
	"strings"
	"sync"
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

	// Dedicated unmetered Guardian backend routes (patch; upstream only knows
	// chatgptCodexURL). Declared here so openai_gateway_service.go stays
	// upstream-pure.
	chatgptCodexGuardianURL           = "https://chatgpt.com/backend-api/codex/guardian"
	chatgptCodexGuardianClassifierURL = "https://chatgpt.com/backend-api/codex/guardian-classifier"
)

func init() {
	// Guardian/subagent headers required by the dedicated route. Injected at
	// init so the upstream whitelist maps in openai_gateway_service.go remain
	// untouched (patch-point discipline: logic in patch files, not upstream
	// tables).
	for _, h := range []string{"x-codex-parent-thread-id", "x-openai-subagent"} {
		openaiAllowedHeaders[h] = true
		openaiPassthroughAllowedHeaders[h] = true
	}
}

// openaiAccountRuntimeBlockReason tracks the strongest active runtime block
// reason per account so Guardian can distinguish a plain 429 quota cooldown
// (which must NOT unbind the Guardian sticky account) from real health gates.
// Package-level on purpose: keeps OpenAIGatewayService struct upstream-pure.
var openaiAccountRuntimeBlockReason sync.Map // key: int64(accountID), value: string

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

func isOpenAIAccountSchedulableForRequest(ctx context.Context, account *Account) bool {
	if IsOpenAICodexGuardianRequest(ctx) && account != nil && account.IsOpenAI() && account.IsOpenAIOAuthLike() {
		return isOpenAICodexGuardianAccountSchedulable(account)
	}
	return account != nil && account.IsSchedulable()
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

// rememberOpenAIAccountRuntimeBlockReason records the strongest active block
// reason. A pre-existing non-429 reason (auth/expiry/overload/transport)
// always wins over a plain 429 quota cooldown.
func (s *OpenAIGatewayService) rememberOpenAIAccountRuntimeBlockReason(accountID int64, reason string) {
	if s == nil || accountID <= 0 {
		return
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "unknown"
	}
	if reason == "429" {
		if current, ok := openaiAccountRuntimeBlockReason.Load(accountID); ok {
			if currentReason, _ := current.(string); strings.TrimSpace(currentReason) != "" && currentReason != "429" {
				return
			}
		}
	}
	openaiAccountRuntimeBlockReason.Store(accountID, reason)
}

// isOpenAIAccountRequestRuntimeBlockedForContext is the Guardian-aware
// runtime-block check: a 429-only cooldown must not block a Guardian request
// (quota isolation — the Guardian sticky account stays bound on 429), while
// every other active block reason still applies.
func (s *OpenAIGatewayService) isOpenAIAccountRequestRuntimeBlockedForContext(ctx context.Context, account *Account, requestedModel string) bool {
	if s == nil || !IsOpenAICodexGuardianRequest(ctx) || account == nil || !account.IsOpenAI() || !account.IsOpenAIOAuthLike() {
		return s != nil && s.isOpenAIAccountRequestRuntimeBlocked(account, requestedModel)
	}
	if s.isOpenAIAccountRuntimeBlocked(account) {
		reasonValue, ok := openaiAccountRuntimeBlockReason.Load(account.ID)
		if !ok {
			return true
		}
		reason, _ := reasonValue.(string)
		if strings.TrimSpace(reason) != "429" {
			return true
		}
	}
	return s.isOpenAIAccountModelRuntimeBlocked(account, requestedModel)
}
