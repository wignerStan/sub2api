package service

// PATCH: 调度器切换账号时的切换信号与下游错误语义（docs/06：session_id 由
// root+所有子线程共享，而传输与 delta 链按 thread 独立）。
//
// 信号模型（WS 与 HTTPS 分流，turn 分 delta/full 两种）：
//   - WS delta turn（带 previous_response_id）：续链绑定属于签发它的账号。
//     调度器把会话换到其他账号时，直接向下游返回 retryable 错误事件
//     （previous_response_not_found → Codex 丢弃当前 WS、重连并全量重放，
//     见 codex-rs responses_retry）。不发虚拟帧：重连本身就会弃用旧 hop。
//   - WS full turn（不带 previous_response_id）：请求自含全量上下文，直接
//     放行，但在「sticky 路由命中了不同账号（旧账号不可调度被放弃）」或
//     「sticky 路由不存在（视为需要新账号关联）」时先发 sidecar 虚拟帧并
//     清洗会话 turn-state 绑定；同账号 sticky 命中不需要任何信号。
//   - HTTPS：恒为 full turn —— 选中账号后与 sticky 路由比对，命中不同账号
//     或未命中时把信号挂到出站 ctx（OpenAISidecarHTTPSwitchContext），由
//     ForwardHTTPViaSidecarForAccount 转为 x-s2s-account-switched 控制头；
//     WS 新连接拨号同理（openAIWSSidecarDialSwitchValue）。
//   - sidecar 收到信号后：剥离服务端签发的 x-codex-turn-state、使旧账号的
//     身份再生成 map 条目失效并再生成 codex 形态的 prompt_cache_key（永不
//     删除），完成跨账号关联切分。
//
// 补丁原则：判断/状态全部收在本文件；上游文件只有 1–3 行挂点。

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	coderws "github.com/coder/websocket"
)

// openAIWSSidecarVFrameMarker 是 sidecar 虚拟帧协议字段名。
const openAIWSSidecarVFrameMarker = "x-s2s-vframe"

// x-s2s-account-switched 是 HTTP/拨号侧告知 sidecar 账号切换的控制头，值为
// 切换前（previous）的账号 ID；未知时为 0。sidecar 按控制头剥离，不转发上游。
const openAISidecarAccountSwitchHeader = "x-s2s-account-switched"

type openAISidecarAccountSwitchContextKey struct{}

// openAISidecarAccountSwitchMarker 以"值存在即已标记"区分未标记请求与
// previous 未知的切换（from=0）。
type openAISidecarAccountSwitchMarker struct{ from int64 }

// WithOpenAISidecarAccountSwitch 标记"本次出站请求的账号相对 sticky 关联
// 发生了切换"。fromAccountID 为切换前账号 ID，未知时为 0（sidecar 收到即
// 做关联清洗，不依赖具体值）。
func WithOpenAISidecarAccountSwitch(ctx context.Context, fromAccountID int64) context.Context {
	if ctx == nil || fromAccountID < 0 {
		return ctx
	}
	return context.WithValue(ctx, openAISidecarAccountSwitchContextKey{}, openAISidecarAccountSwitchMarker{from: fromAccountID})
}

func openAISidecarAccountSwitchFrom(ctx context.Context) (int64, bool) {
	if ctx == nil {
		return 0, false
	}
	marker, ok := ctx.Value(openAISidecarAccountSwitchContextKey{}).(openAISidecarAccountSwitchMarker)
	if !ok {
		return 0, false
	}
	return marker.from, true
}

// openAIWSSidecarAccountSwitchFrame 构造 WS 虚拟帧。previousAccountID 为 0
// 表示切换前账号未知（sticky 路由已失效），sidecar 仍按"本 scope 发生过切换"
// 处理；无需通知（同账号）时返回 nil。
func openAIWSSidecarAccountSwitchFrame(previousAccountID, accountID int64) json.RawMessage {
	if previousAccountID == accountID {
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

// openAIWSSidecarAccountSwitchDownstreamEvent 构造发给下游 Codex 客户端的
// error event。previous_response_not_found 被 Codex 分类为 retryable：
// 丢弃当前 WS → 重连 → 全量重放（显式 drop previous_response_id）。
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

// openAIWSSidecarStickyResolver 抽象 sticky 路由（session→account）查询，
// 使切换判定无需依赖完整 service 即可测试。
type openAIWSSidecarStickyResolver func(ctx context.Context, groupID int64, sessionHash string) (int64, error)

func openAIWSSidecarStickyAccountFunc(s *OpenAIGatewayService) openAIWSSidecarStickyResolver {
	if s == nil {
		return nil
	}
	return func(ctx context.Context, groupID int64, sessionHash string) (int64, error) {
		return s.getStickySessionAccountID(ctx, &groupID, sessionHash)
	}
}

// openAIWSSidecarSwitchFromForTurn 返回 full turn / 拨号场景的切换信号值：
// sticky 命中不同账号 → 旧账号 ID；sticky 未命中 → 0（未知）；同账号 →
// 无信号（-1 哨兵）。查询错误视为无信号（cache 故障不应放大为请求失败）。
func openAIWSSidecarSwitchFromForTurn(
	ctx context.Context,
	resolve openAIWSSidecarStickyResolver,
	groupID int64,
	sessionHash string,
	accountID int64,
) (int64, bool) {
	if resolve == nil || sessionHash == "" {
		return 0, false
	}
	bound, err := resolve(ctx, groupID, sessionHash)
	if err != nil || bound < 0 {
		return 0, false
	}
	if bound == accountID {
		return 0, false
	}
	return bound, true
}

// OpenAISidecarHTTPSwitchContext 是 HTTPS 侧的切换判定挂点（HTTP 请求恒为
// full turn）。在调度器选中账号后调用：sticky 命中不同账号或未命中时返回
// 携带切换标记的 ctx，由 ForwardHTTPViaSidecarForAccount 发出控制头。
func OpenAISidecarHTTPSwitchContext(
	ctx context.Context,
	s *OpenAIGatewayService,
	groupID *int64,
	sessionHash string,
	accountID int64,
) context.Context {
	if s == nil || ctx == nil || sessionHash == "" {
		return ctx
	}
	group := int64(0)
	if groupID != nil {
		group = *groupID
	}
	from, switched := openAIWSSidecarSwitchFromForTurn(
		ctx, openAIWSSidecarStickyAccountFunc(s), group, sessionHash, accountID,
	)
	if !switched {
		return ctx
	}
	return WithOpenAISidecarAccountSwitch(ctx, from)
}

// openAIWSSidecarDialSwitchValue 是 WS 新连接拨号侧的切换判定挂点：sticky
// 命中不同账号或未命中时返回控制头值（未知为 "0"），同账号返回空串。
func openAIWSSidecarDialSwitchValue(
	ctx context.Context,
	s *OpenAIGatewayService,
	groupID int64,
	sessionHash string,
	accountID int64,
) string {
	from, switched := openAIWSSidecarSwitchFromForTurn(
		ctx, openAIWSSidecarStickyAccountFunc(s), groupID, sessionHash, accountID,
	)
	if !switched {
		return ""
	}
	return fmt.Sprintf("%d", from)
}

// openAIWSSidecarOnAccountSwitch 是 WS ingress 的切换判定统一入口（取得
// sessionLease 后调用）。按 turn 形态分流：
//
//   - delta turn：续链绑定（response→account）显示链属于其他账号 → 返回
//     non-nil error（下游已收到 retryable error event，良性 NormalClosure
//     关闭；调用方原样返回给 handler，不再触发账号 failover）。
//   - full turn：发虚拟帧（如需）+ 清洗会话 turn-state 绑定后放行（nil）。
func openAIWSSidecarOnAccountSwitch(
	ctx context.Context,
	resolve openAIWSSidecarStickyResolver,
	stateStore OpenAIWSStateStore,
	groupID int64,
	sessionHash string,
	previousResponseID string,
	account *Account,
	lease *openAIWSConnLease,
	clientConn *coderws.Conn,
	hooks *OpenAIWSIngressHooks,
	writeTimeout time.Duration,
) error {
	if lease == nil || account == nil {
		return nil
	}

	if previousResponseID != "" {
		// Delta turn：链绑定属于旧账号且调度器已换号 → 直接返回 retryable
		// 错误，让客户端重连 + 全量重放。不发虚拟帧：重连会弃用旧 hop，
		// 且重连后的 full turn 会走下方分支补发 sidecar 信号。
		if stateStore != nil {
			if bound, err := stateStore.GetResponseAccount(ctx, groupID, previousResponseID); err == nil && bound > 0 && bound != account.ID {
				return openAIWSSidecarReturnRetryableSwitch(ctx, clientConn, hooks, writeTimeout, bound, account.ID)
			}
		}
		return nil
	}

	// Full turn：sticky 关联可能变化（旧账号不可调度被放弃 / 路由失效）。
	from, switched := openAIWSSidecarSwitchFromForTurn(ctx, resolve, groupID, sessionHash, account.ID)
	if !switched {
		return nil
	}

	// 1. 通知 sidecar（虚拟帧）：逐出旧账号在该 thread scope 的空闲 socket，
	//    触发该 hop 的 turn-state 剥离与 prompt_cache_key 再生成。
	if frame := openAIWSSidecarAccountSwitchFrame(from, account.ID); frame != nil {
		if writeErr := lease.WriteJSONWithContextTimeout(ctx, frame, writeTimeout); writeErr != nil {
			logOpenAIWSModeInfo(
				"ingress_ws_sidecar_switch_frame_write_fail account_id=%d previous_account_id=%d cause=%s",
				account.ID,
				from,
				truncateOpenAIWSLogValue(writeErr.Error(), openAIWSLogValueMaxLen),
			)
		} else {
			logOpenAIWSModeInfo(
				"ingress_ws_sidecar_switch_frame_sent account_id=%d previous_account_id=%d",
				account.ID,
				from,
			)
		}
	}

	// 2. 清洗会话级 turn-state 绑定：旧账号上游签发的 x-codex-turn-state
	//    不得再 ride 到新账号的拨号头 / 后续请求。BindSessionTurnState 对空
	//    值是 no-op（store 语义：空 = 不绑定），必须显式 Delete。
	if stateStore != nil && sessionHash != "" {
		stateStore.DeleteSessionTurnState(groupID, sessionHash)
	}
	return nil
}

// openAIWSSidecarReturnRetryableSwitch 向下游写出 previous_response_not_found
// error event（先于 close 帧落盘，与 Fast Policy 拦截同一 writeFrameMu 顺序
// 保证），随后返回良性 NormalClosure 关闭错误。
func openAIWSSidecarReturnRetryableSwitch(
	ctx context.Context,
	clientConn *coderws.Conn,
	hooks *OpenAIWSIngressHooks,
	writeTimeout time.Duration,
	previousAccountID, accountID int64,
) error {
	if clientConn != nil {
		if eventBytes := openAIWSSidecarAccountSwitchDownstreamEvent(previousAccountID, accountID); eventBytes != nil {
			writeCtx, cancel := newOpenAIWSDownstreamWriteContext(ctx, hooks, writeTimeout)
			_ = clientConn.Write(writeCtx, coderws.MessageText, eventBytes)
			cancel()
		}
	}
	return NewOpenAIWSClientCloseError(
		coderws.StatusNormalClosure,
		"upstream account switched by scheduler; please reconnect",
		nil,
	)
}

// openAISidecarAccountSwitchHeaderValue 返回 HTTP 侧的切换通知头值；
// 无切换（未标记 / 同账号）时返回空串。
func openAISidecarAccountSwitchHeaderValue(ctx context.Context, accountID int64) string {
	from, marked := openAISidecarAccountSwitchFrom(ctx)
	if !marked || from == accountID {
		return ""
	}
	return fmt.Sprintf("%d", from)
}
