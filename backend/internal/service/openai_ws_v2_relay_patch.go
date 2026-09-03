package service

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// sync-183 WS relay/failover 补丁（patch 分支的 hook 逻辑集中地）。
//
// 上游文件里只保留 1–3 行 hook（见 docs/PATCHES.md）：
//   - openai_ws_v2_passthrough_adapter.go openAIWSClientFrameConn.WriteFrame:
//     下行直写容量降载改写（1dc0a0900 在 ctx_pool ingress 直写路径的等价缺口；
//     HTTP/SSE 与 http_bridge 早已有同款改写）。
//   - openai_ws_v2_passthrough_adapter.go response.create 帧处理: passthrough
//     模式下调用 BeforeTurn（a0cfa8002），恢复 turn 级利润准入门与 pricingAt
//     冻结——patch 分支强制 WS v2 + passthrough，native 的 "passthrough 无
//     BeforeTurn" 前提在此部署形态下不成立。
//   - openai_gateway_upstream_errors.go newOpenAIAccountFailoverErrorWith
//     ClassificationHeaders: 账号级自定义错误码映射（b6214d414）。
//
// 全部由 SUB2API_PATCH 门控；关闭时 native 行为字节不变。

// openAIWSRewriteDownstreamCapacityShedPatch rewrites the bytes of one
// downstream text frame right before the client write. The relay's
// observation hooks (usage accounting, account-state judgment,
// markOpenAIWSClientVisibleFailure) still see the original upstream payload —
// same contract as sanitizeOpenAICapacityShedErrorCodeForClient documents for
// the http_bridge path.
func openAIWSRewriteDownstreamCapacityShedPatch(payload []byte) []byte {
	if !isSub2apiPatchEnabled() || len(payload) == 0 {
		return payload
	}
	eventType, _, _ := parseOpenAIWSEventEnvelope(payload)
	if eventType != "error" && eventType != "response.failed" {
		return payload
	}
	if rewritten, changed := sanitizeOpenAICapacityShedErrorCodeForClient(payload); changed {
		return rewritten
	}
	return payload
}

// openAIWSRelayBeforeTurnPatch invokes the handler's BeforeTurn hook for
// passthrough relay turns (sync-183 a0cfa8002): per-turn profit admission
// re-check and pricingAt freeze. Upstream intentionally skips BeforeTurn in
// passthrough mode; under SUB2API_PATCH passthrough is the only ingress mode,
// so the turn gate must run here.
func openAIWSRelayBeforeTurnPatch(hooks *OpenAIWSIngressHooks, turnNo int) error {
	if !isSub2apiPatchEnabled() || hooks == nil || hooks.BeforeTurn == nil {
		return nil
	}
	return hooks.BeforeTurn(turnNo)
}

// applyOpenAIAccountCustomErrorMappingPatch applies the account-level custom
// error-code mapping to a failover error (sync-183 b6214d414): when the
// account declares it handles its own status-code set, uncovered codes are
// downgraded to a retryable 500 instead of being forwarded to the client.
// Capacity-shed / access-state constructors override ClientStatusCode after
// this, so their specific client contracts win.
func applyOpenAIAccountCustomErrorMappingPatch(account *Account, statusCode int, failoverErr *UpstreamFailoverError) {
	if !isSub2apiPatchEnabled() || account == nil || failoverErr == nil {
		return
	}
	if !account.IsCustomErrorCodesEnabled() || account.ShouldHandleErrorCode(statusCode) {
		return
	}
	failoverErr.ClientStatusCode = http.StatusInternalServerError
	failoverErr.ClientMessage = "The server encountered an internal error. Please retry your request."
}

// ErrorPassthroughServiceForPatch exposes the bound error-passthrough service
// to the handler-side failover close patch (handler/openai_ws_failover_close_patch.go).
func ErrorPassthroughServiceForPatch(c *gin.Context) *ErrorPassthroughService {
	return getBoundErrorPassthroughService(c)
}

// Sub2apiPatchGateForHandler reports the SUB2API_PATCH master switch to the
// handler package (the gate itself is unexported by design).
func Sub2apiPatchGateForHandler() bool {
	return isSub2apiPatchEnabled()
}
