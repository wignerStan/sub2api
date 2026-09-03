package service

// PATCH: 调度器切换账号时通知 sidecar，避免跨账号污染同一线程范围的连接
// 亲和/路由提示/续链缓存（docs/06：session_id 由 root+所有子线程共享，而
// 传输与 delta 链按 thread 独立）。
// - WS 模式：在 sidecar hop 上发一个"虚拟帧"（sidecar 侧消费，不转发上游）。
// - HTTP 模式：走 x-s2s-account-switched header（sidecar 按控制头剥离）。
// 补丁原则：判断逻辑全部收在本文件；上游文件只有 1–3 行的挂点。

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// openAIWSSidecarVFrameMarker 是 sidecar 虚拟帧协议字段名。
const openAIWSSidecarVFrameMarker = "x-s2s-vframe"

// x-s2s-account-switched 是 HTTP 侧告知 sidecar 账号切换的控制头，
// 值为切换前（previous）的账号 ID；sidecar 按控制头剥离，不转发上游。
const openAISidecarAccountSwitchHeader = "x-s2s-account-switched"

type openAISidecarAccountSwitchContextKey struct{}

// WithOpenAISidecarAccountSwitch 标记"本次尝试是调度器从 fromAccountID 切换
// 过来的"。由 handler 的 failover 分支在切换后挂到请求 ctx 上。
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

// openAIWSSidecarAccountSwitchFrame 构造 WS 虚拟帧；无需通知时返回 nil。
func openAIWSSidecarAccountSwitchFrame(previousAccountID, accountID int64) json.RawMessage {
	if previousAccountID <= 0 || previousAccountID == accountID {
		return nil
	}
	payload, err := json.Marshal(map[string]any{
		openAIWSSidecarVFrameMarker: "account-switch",
		"previous_account_id":       previousAccountID,
		"account_id":                accountID,
	})
	if err != nil {
		return nil
	}
	return payload
}

// maybeWriteOpenAIWSSidecarAccountSwitchFrame 在新 sessionLease 建立后调用：
// 会话续链（previous_response_id 的 response→account 绑定）属于另一个账号 =
// 调度器切换了账号，先向 sidecar 发虚拟帧再写正式 turn payload。发送失败仅
// 记日志，绝不影响业务链路。
func maybeWriteOpenAIWSSidecarAccountSwitchFrame(
	ctx context.Context,
	stateStore OpenAIWSStateStore,
	groupID int64,
	previousResponseID string,
	account *Account,
	lease *openAIWSConnLease,
	writeTimeout time.Duration,
) {
	if lease == nil || account == nil || stateStore == nil || previousResponseID == "" {
		return
	}
	previousAccountID, err := stateStore.GetResponseAccount(ctx, groupID, previousResponseID)
	if err != nil || previousAccountID <= 0 || previousAccountID == account.ID {
		return
	}
	frame := openAIWSSidecarAccountSwitchFrame(previousAccountID, account.ID)
	if frame == nil {
		return
	}
	if writeErr := lease.WriteJSONWithContextTimeout(ctx, frame, writeTimeout); writeErr != nil {
		logOpenAIWSModeInfo(
			"ingress_ws_sidecar_switch_frame_write_fail account_id=%d previous_account_id=%d cause=%s",
			account.ID,
			previousAccountID,
			truncateOpenAIWSLogValue(writeErr.Error(), openAIWSLogValueMaxLen),
		)
		return
	}
	logOpenAIWSModeInfo(
		"ingress_ws_sidecar_switch_frame_sent account_id=%d previous_account_id=%d",
		account.ID,
		previousAccountID,
	)
}

// openAISidecarAccountSwitchHeaderValue 返回 HTTP 侧的切换通知头值；
// 无切换（未标记 / 同账号）时返回空串。
func openAISidecarAccountSwitchHeaderValue(ctx context.Context, accountID int64) string {
	from := openAISidecarAccountSwitchFrom(ctx)
	if from <= 0 || from == accountID {
		return ""
	}
	return fmt.Sprintf("%d", from)
}
