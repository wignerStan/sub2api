package service

// PATCH: 调度器切换账号时的信号语义（Go nearly passthrough）：
//   - WS delta turn（previous_response_id 非空）：续链（response→account 绑定）
//     属于其他账号 = 调度器换了账号 → 直接向下游返回 retryable 错误事件
//     （previous_response_not_found，Codex responses_retry 语义：丢弃当前 WS →
//     重连 → 全量重放）+ 良性 NormalClosure。这是唯一的决策 hook。
//   - 其它一律加 header：x-s2s-account-switched（值 = 切换前账号 ID），由
//     failover 事件经 request ctx带到出站 seam（HTTP 转发 / WS 拨号头）；
//     sidecar按控制头剥离，不转发上游。
//   - 虚拟帧（vframe）协议已废除：换号必然伴随重建新 WS（delta 错误 → 客户端
//     重连），header 走拨号/请求头即可。
// 补丁原则：判断逻辑全部收在本文件；上游文件只有 1–3 行挂点。

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	coderws "github.com/coder/websocket"
)

// x-s2s-account-switched 是告知 sidecar 账号切换的控制头，值为切换前
// （previous）的账号 ID；sidecar 按控制头剥离，不转发上游。
const openAISidecarAccountSwitchHeader = "x-s2s-account-switched"

type openAISidecarAccountSwitchContextKey struct{}

// WithOpenAISidecarAccountSwitch 标记"本次尝试是调度器从 fromAccountID 切换
// 过来的"。由 handler 的 failover 分支在切换后挂到请求 ctx 上；出站 seam
// （HTTP 转发 / WS 拨号头）据此加 x-s2s-account-switched。
func WithOpenAISidecarAccountSwitch(ctx context.Context, fromAccountID int64) context.Context {
	if fromAccountID <= 0 {
		return ctx
	}
	return context.WithValue(ctx, openAISidecarAccountSwitchContextKey{}, fromAccountID)
}

func openAISidecarAccountSwitchFrom(ctx context.Context) int64 {
	if ctx == nil {
		return 0
	}
	from, _ := ctx.Value(openAISidecarAccountSwitchContextKey{}).(int64)
	return from
}

// openAIWSSidecarAccountSwitchDownstreamEvent 构造发给下游 Codex 客户端的
// error event。previous_response_not_found 被 Codex 分类为 retryable：丢弃
// 当前 WS → 重连 → 全量重放（显式 drop previous_response_id）。
func openAIWSSidecarAccountSwitchDownstreamEvent(previousAccountID, accountID int64) []byte {
	payload, err := json.Marshal(map[string]any{
		"event_id": newOpenAIFastPolicyWSEventID(),
		"type":     "error",
		"error": map[string]any{
			"type": "invalid_request_error",
			"code": "previous_response_not_found",
			"message": fmt.Sprintf(
				"upstream account switched by scheduler (previous account %d); reconnect and resend the full request context",
				previousAccountID,
			),
		},
	})
	if err != nil {
		return nil
	}
	return payload
}

// openAIWSSidecarOnDeltaTurnSwitch 在新 sessionLease 建立后调用（WS delta
// turn 的切换判定）：续链绑定属于另一个账号 = 调度器切换了账号 → 向下游写
// error event 后返回良性 NormalClosure（调用方原样返回给 handler，不再触发
// 账号 failover）。非 delta turn / 绑定同账号 / 无绑定 → 返回 nil 放行，
// 换号信号由 header 通道承载。
func openAIWSSidecarOnDeltaTurnSwitch(
	ctx context.Context,
	stateStore OpenAIWSStateStore,
	groupID int64,
	previousResponseID string,
	account *Account,
	clientConn *coderws.Conn,
	hooks *OpenAIWSIngressHooks,
	writeTimeout time.Duration,
) error {
	if account == nil || stateStore == nil || previousResponseID == "" {
		return nil
	}
	previousAccountID, err := stateStore.GetResponseAccount(ctx, groupID, previousResponseID)
	if err != nil || previousAccountID <= 0 || previousAccountID == account.ID {
		return nil
	}
	if clientConn != nil {
		if eventBytes := openAIWSSidecarAccountSwitchDownstreamEvent(previousAccountID, account.ID); eventBytes != nil {
			writeCtx, cancel := newOpenAIWSDownstreamWriteContext(ctx, hooks, writeTimeout)
			_ = clientConn.Write(writeCtx, coderws.MessageText, eventBytes)
			cancel()
		}
	}
	logOpenAIWSModeInfo(
		"ingress_ws_sidecar_switch_delta_error account_id=%d previous_account_id=%d",
		account.ID,
		previousAccountID,
	)
	return NewOpenAIWSClientCloseError(
		coderws.StatusNormalClosure,
		"upstream account switched by scheduler; please reconnect",
		nil,
	)
}

// openAISidecarAccountSwitchHeaderValue 返回出站切换通知头值；
// 无切换（未标记 / 同账号）时返回空串。
func openAISidecarAccountSwitchHeaderValue(ctx context.Context, accountID int64) string {
	from := openAISidecarAccountSwitchFrom(ctx)
	if from <= 0 || from == accountID {
		return ""
	}
	return fmt.Sprintf("%d", from)
}
