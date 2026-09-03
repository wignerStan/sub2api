package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"
)

func TestOpenAIWSSidecarAccountSwitchFrame(t *testing.T) {
	// 同账号不产帧；sticky 未命中（previous=0，未知）仍产帧。
	require.Nil(t, openAIWSSidecarAccountSwitchFrame(5, 5))

	frame := openAIWSSidecarAccountSwitchFrame(3, 5)
	require.NotNil(t, frame)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(frame, &decoded))
	require.Equal(t, "account-switch", decoded["x-s2s-vframe"])
	require.Equal(t, float64(3), decoded["previous_account_id"])
	require.Equal(t, float64(5), decoded["account_id"])

	unknown := openAIWSSidecarAccountSwitchFrame(0, 5)
	require.NotNil(t, unknown)
	var unknownDecoded map[string]any
	require.NoError(t, json.Unmarshal(unknown, &unknownDecoded))
	require.Equal(t, float64(0), unknownDecoded["previous_account_id"])
}

func TestOpenAIWSSidecarAccountSwitchDownstreamEvent(t *testing.T) {
	event := openAIWSSidecarAccountSwitchDownstreamEvent(3, 5)
	require.NotNil(t, event)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(event, &decoded))
	require.Equal(t, "error", decoded["type"])
	errObj, ok := decoded["error"].(map[string]any)
	require.True(t, ok)
	// previous_response_not_found 被 Codex 分类为 retryable：客户端丢弃当前
	// WS、重连并以全量上下文重放。
	require.Equal(t, "previous_response_not_found", errObj["code"])
}

// sticky 路由比对核心：命中不同账号 → (旧账号, true)；未命中 → (0, true)；
// 同账号 / 查询失败 → 无信号。
func TestOpenAIWSSidecarSwitchFromForTurn(t *testing.T) {
	ctx := context.Background()
	bound3 := func(_ context.Context, _ int64, _ string) (int64, error) {
		return 3, nil
	}

	from, ok := openAIWSSidecarSwitchFromForTurn(ctx, bound3, 1, "hash", 5)
	require.True(t, ok)
	require.Equal(t, int64(3), from)

	_, ok = openAIWSSidecarSwitchFromForTurn(ctx, bound3, 1, "hash", 3)
	require.False(t, ok, "同账号 sticky 命中不需要信号")

	miss := func(_ context.Context, _ int64, _ string) (int64, error) {
		return 0, nil
	}
	from, ok = openAIWSSidecarSwitchFromForTurn(ctx, miss, 1, "hash", 5)
	require.True(t, ok, "sticky 未命中也发信号（视为需要新账号关联）")
	require.Equal(t, int64(0), from)

	failing := func(_ context.Context, _ int64, _ string) (int64, error) {
		return 0, errors.New("cache down")
	}
	_, ok = openAIWSSidecarSwitchFromForTurn(ctx, failing, 1, "hash", 5)
	require.False(t, ok, "cache 故障不放大为请求失败")

	_, ok = openAIWSSidecarSwitchFromForTurn(ctx, bound3, 1, "", 5)
	require.False(t, ok, "无 sessionHash 不发信号")
}

// WS ingress 切换判定按 turn 形态分流：
//   - delta turn：续链绑定（response→account）指向其他账号 → retryable 错误
//     事件 + 良性 NormalClosure；绑定同账号 / 无绑定 → 放行。
//   - full turn：sticky 命中不同账号或未命中 → 虚拟帧 + 清洗 turn-state 绑定
//     后放行；同账号命中 → 无信号不清洗。
func TestOpenAIWSSidecarOnAccountSwitchTurnBranches(t *testing.T) {
	ctx := context.Background()
	const groupID = int64(7)
	const sessionHash = "turn-branch-hash"

	bound3 := func(_ context.Context, _ int64, _ string) (int64, error) {
		return 3, nil
	}
	same5 := func(_ context.Context, _ int64, _ string) (int64, error) {
		return 5, nil
	}
	lease := &openAIWSConnLease{}
	account5 := &Account{ID: 5}

	t.Run("delta turn + 绑定指向其他账号: 返回 retryable 良性关闭错误", func(t *testing.T) {
		store := NewOpenAIWSStateStore(&schedulerTestGatewayCache{})
		require.NoError(t, store.BindResponseAccount(ctx, groupID, "resp-1", 3, time.Hour))
		err := openAIWSSidecarOnAccountSwitch(ctx, bound3, store, groupID, sessionHash, "resp-1", account5, lease, nil, nil, time.Second)
		require.Error(t, err)
		var closeErr *OpenAIWSClientCloseError
		require.True(t, errors.As(err, &closeErr), "良性 NormalClosure，handler 不再触发账号 failover")
		require.Equal(t, websocket.StatusNormalClosure, closeErr.StatusCode())
	})

	t.Run("delta turn + 绑定同账号: 放行", func(t *testing.T) {
		store := NewOpenAIWSStateStore(&schedulerTestGatewayCache{})
		require.NoError(t, store.BindResponseAccount(ctx, groupID, "resp-1", 3, time.Hour))
		account3 := &Account{ID: 3}
		err := openAIWSSidecarOnAccountSwitch(ctx, bound3, store, groupID, sessionHash, "resp-1", account3, lease, nil, nil, time.Second)
		require.NoError(t, err)
	})

	t.Run("delta turn + 无绑定: 放行（由上游自然报错兜底）", func(t *testing.T) {
		store := NewOpenAIWSStateStore(&schedulerTestGatewayCache{})
		err := openAIWSSidecarOnAccountSwitch(ctx, bound3, store, groupID, sessionHash, "resp-missing", account5, lease, nil, nil, time.Second)
		require.NoError(t, err)
	})

	t.Run("full turn + sticky 命中不同账号: 发虚拟帧 + 清洗 turn-state + 放行", func(t *testing.T) {
		store := NewOpenAIWSStateStore(&schedulerTestGatewayCache{})
		store.BindSessionTurnState(groupID, sessionHash, "old-turn-state", time.Hour)
		err := openAIWSSidecarOnAccountSwitch(ctx, bound3, store, groupID, sessionHash, "", account5, lease, nil, nil, time.Second)
		require.NoError(t, err, "full turn 自含全量上下文，直接放行")
		if _, ok := store.GetSessionTurnState(groupID, sessionHash); ok {
			t.Fatal("turn-state 绑定应被清洗为空")
		}
	})

	t.Run("full turn + sticky 未命中: 同样发信号并清洗", func(t *testing.T) {
		store := NewOpenAIWSStateStore(&schedulerTestGatewayCache{})
		store.BindSessionTurnState(groupID, sessionHash, "old-turn-state", time.Hour)
		miss := func(_ context.Context, _ int64, _ string) (int64, error) { return 0, nil }
		err := openAIWSSidecarOnAccountSwitch(ctx, miss, store, groupID, sessionHash, "", account5, lease, nil, nil, time.Second)
		require.NoError(t, err)
		if _, ok := store.GetSessionTurnState(groupID, sessionHash); ok {
			t.Fatal("sticky 未命中（需要新账号关联）也应清洗 turn-state")
		}
	})

	t.Run("full turn + sticky 同账号: 无信号不清洗", func(t *testing.T) {
		store := NewOpenAIWSStateStore(&schedulerTestGatewayCache{})
		store.BindSessionTurnState(groupID, sessionHash, "kept", time.Hour)
		err := openAIWSSidecarOnAccountSwitch(ctx, same5, store, groupID, sessionHash, "", account5, lease, nil, nil, time.Second)
		require.NoError(t, err)
		if state, ok := store.GetSessionTurnState(groupID, sessionHash); !ok || state != "kept" {
			t.Fatal("同账号 sticky 命中不应清洗 turn-state")
		}
	})
}

func TestOpenAISidecarAccountSwitchHeaderValue(t *testing.T) {
	ctx := WithOpenAISidecarAccountSwitch(context.Background(), 3)
	require.Equal(t, "3", openAISidecarAccountSwitchHeaderValue(ctx, 5))
	// 同账号 / 未标记：不产头。
	require.Empty(t, openAISidecarAccountSwitchHeaderValue(ctx, 3))
	require.Empty(t, openAISidecarAccountSwitchHeaderValue(context.Background(), 5))
	require.Empty(t, openAISidecarAccountSwitchHeaderValue(context.Background(), 0))

	// previous=0（未知切换前账号）也产头，值为 0：sidecar 收到即做关联清洗。
	unknownCtx := WithOpenAISidecarAccountSwitch(context.Background(), 0)
	require.Equal(t, "0", openAISidecarAccountSwitchHeaderValue(unknownCtx, 5))
}

// Req: WS=no 的 OAuth 账号 HTTPS 出站仍走 sidecar（sidecar 判定只看目标
// host/scheme，与 WS 模式无关）；同时 WS/HTTP 互斥逻辑不被 patch 破坏：
// SUB2API_PATCH 下 OAuth 强制 WS-only（HTTP 自动透传禁用），PATCH 关闭时
// 完全尊重账号原有配置。
func TestOpenAIOAuthSidecarRoutingIndependentOfWSMode(t *testing.T) {
	sidecarTarget := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", nil)
	newOAuthAccount := func() *Account {
		return &Account{
			Platform: PlatformOpenAI,
			Type:     AccountTypeOAuth,
			Extra: map[string]any{
				"openai_passthrough": true,
			},
		}
	}

	t.Run("PATCH off: HTTP passthrough 按账号配置开启，sidecar 路由仍然生效", func(t *testing.T) {
		account := newOAuthAccount()
		require.True(t, account.IsOpenAIPassthroughEnabled(), "PATCH 关闭时尊重账号配置的 HTTP 透传")
		require.False(t, account.IsOpenAIResponsesWebSocketV2Enabled(), "PATCH 关闭时 WS 按账号配置（此处为关）")
		require.True(t, ShouldUseSidecarTLS(sidecarTarget), "WS 关闭不影响 OAuth HTTPS 出站走 sidecar")
	})

	t.Run("PATCH on: OAuth 强制 WS-only 且 HTTP 透传禁用，sidecar 路由不受影响", func(t *testing.T) {
		t.Setenv("SUB2API_PATCH", "true")
		account := newOAuthAccount()
		require.False(t, account.IsOpenAIPassthroughEnabled(), "WS 与 HTTP 互斥：PATCH 下 OAuth 禁用 HTTP 透传")
		require.True(t, account.IsOpenAIResponsesWebSocketV2Enabled())
		require.Equal(t, OpenAIWSIngressModePassthrough, account.ResolveOpenAIResponsesWebSocketV2Mode("off"))
		require.True(t, ShouldUseSidecarTLS(sidecarTarget), "WS=on 也不影响同账号 HTTP 控制面出站走 sidecar")
	})

	t.Run("sidecar 判定与账号无关：非 OAuth host 不走 sidecar", func(t *testing.T) {
		apikeyTarget := httptest.NewRequest(http.MethodPost, "https://api.openai.com/v1/responses", nil)
		require.False(t, ShouldUseSidecarTLS(apikeyTarget), "api.openai.com 永远走原生 Go 传输")
	})
}
