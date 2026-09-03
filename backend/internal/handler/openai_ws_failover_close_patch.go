package handler

import (
	"net/http"
	"strings"

	coderws "github.com/coder/websocket"
	"github.com/gin-gonic/gin"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// sync-183 WS failover-exhausted close 终态（patch 分支的 hook 逻辑集中地）。
//
// 上游 openai_gateway_handler.go 的 closeOpenAIWSFailoverExhausted 顶部保留
// 一个 2 行 hook 调用本文件；SUB2API_PATCH 关闭时 native close 行为不变。
//
// 相对 native 的差异（3544767b8 → 7fa72847e → b6214d414 的演化终态）：
//   - close 帧之前先下发结构化 error 事件（openai_gateway_ws_failover_event.go）：
//     Codex 把带根 HTTP 状态码的 error 帧映射回其正常 HTTP/限流处理；只有
//     close 帧会被上报为中断流并重试。
//   - 429 文案对齐 Codex 延迟解析器（"Rate limit reached. Please try again
//     in 3s." + retry-after: 3 兜底，7fa72847e）。
//   - 账号级自定义错误码映射下发的 ClientStatusCode/ClientMessage（b6214d414）。
//   - 错误透传规则在 close 事件上的等价应用（HTTP 路径早已有同款规则匹配）。

func closeOpenAIWSFailoverExhaustedPatched(c *gin.Context, conn *coderws.Conn, failoverErr *service.UpstreamFailoverError) bool {
	if !service.Sub2apiPatchGateForHandler() {
		return false
	}

	intendedStatus := http.StatusBadGateway
	errorType := "upstream_error"
	errorCode := "upstream_ws_failover_exhausted"
	message := "upstream websocket proxy failed"
	closeStatus := coderws.StatusInternalError
	passthroughBody := true

	if failoverErr != nil {
		if reason := strings.TrimSpace(string(failoverErr.Reason)); reason != "" {
			errorCode = reason
		}
		if failoverErr.Stage == service.GatewayFailureStageAccountAuth {
			intendedStatus = http.StatusServiceUnavailable
			errorType = "api_error"
			message = service.GrokCredentialUnavailableClientMessage
			closeStatus = coderws.StatusTryAgainLater
			passthroughBody = false
		} else {
			switch failoverErr.StatusCode {
			case http.StatusTooManyRequests:
				intendedStatus = http.StatusTooManyRequests
				errorType = "rate_limit_error"
				errorCode = "rate_limit_exceeded"
				message = "Rate limit reached. Please try again in 3s."
				closeStatus = coderws.StatusTryAgainLater
			case http.StatusInternalServerError:
				intendedStatus = http.StatusInternalServerError
				errorType = "internal_server_error"
				errorCode = "internal_server_error"
				message = "The server encountered an internal error. Please retry your request."
				closeStatus = coderws.StatusTryAgainLater
				passthroughBody = false
			case 529, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
				intendedStatus = failoverErr.StatusCode
				errorType = "api_error"
				message = "upstream service temporarily unavailable"
				closeStatus = coderws.StatusTryAgainLater
			case http.StatusUnauthorized, http.StatusForbidden:
				intendedStatus = failoverErr.StatusCode
				errorType = "authentication_error"
				message = "upstream websocket authentication failed"
				closeStatus = coderws.StatusPolicyViolation
			}
		}

		if failoverErr.ClientStatusCode > 0 {
			intendedStatus = failoverErr.ClientStatusCode
			if failoverErr.ClientStatusCode == http.StatusInternalServerError {
				errorType = "internal_server_error"
				errorCode = "internal_server_error"
				message = "The server encountered an internal error. Please retry your request."
				passthroughBody = false
			}
		}
		if failoverErr.ClientMessage != "" {
			message = failoverErr.ClientMessage
		}

		if svc := service.ErrorPassthroughServiceForPatch(c); svc != nil {
			if rule := svc.MatchRule(service.PlatformOpenAI, failoverErr.StatusCode, failoverErr.ResponseBody); rule != nil {
				passthroughBody = rule.PassthroughBody
				if rule.ResponseCode != nil && *rule.ResponseCode > 0 {
					intendedStatus = *rule.ResponseCode
				}
				if rule.CustomMessage != nil && strings.TrimSpace(*rule.CustomMessage) != "" {
					message = strings.TrimSpace(*rule.CustomMessage)
				}
				switch {
				case intendedStatus == http.StatusTooManyRequests:
					errorType = "rate_limit_error"
					errorCode = "rate_limit_exceeded"
					closeStatus = coderws.StatusTryAgainLater
				case intendedStatus == http.StatusUnauthorized || intendedStatus == http.StatusForbidden:
					errorType = "authentication_error"
					closeStatus = coderws.StatusPolicyViolation
				case intendedStatus == http.StatusInternalServerError:
					errorType = "internal_server_error"
					errorCode = "internal_server_error"
					closeStatus = coderws.StatusTryAgainLater
				case intendedStatus >= 500:
					errorType = "api_error"
					closeStatus = coderws.StatusTryAgainLater
				default:
					errorType = "invalid_request_error"
					closeStatus = coderws.StatusPolicyViolation
				}
			}
		}
	}

	service.MarkOpsStreamFailure(c, errorType, errorCode, message, intendedStatus)
	writeOpenAIWSFailoverErrorEvent(conn, failoverErr, intendedStatus, errorType, errorCode, message, passthroughBody)
	closeOpenAIClientWS(conn, closeStatus, message)
	return true
}
