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

// WS delta turn 切换判定：续链绑定（response→account）属于其他账号 →
// 返回良性 NormalClosure（下游已收到 retryable error event）；绑定同账号 /
// 无绑定 / 非 delta turn → 放行，换号信号由 header 通道承载。
func TestOpenAIWSSidecarOnDeltaTurnSwitch(t *testing.T) {
	ctx := context.Background()
	const groupID = int64(7)
	account5 := &Account{ID: 5}

	t.Run("delta turn + 绑定指向其他账号: 返回良性关闭错误", func(t *testing.T) {
		store := NewOpenAIWSStateStore(&schedulerTestGatewayCache{})
		require.NoError(t, store.BindResponseAccount(ctx, groupID, "resp-1", 3, time.Hour))
		err := openAIWSSidecarOnDeltaTurnSwitch(ctx, store, groupID, "resp-1", account5, nil, nil, time.Second)
		require.Error(t, err)
		var closeErr *OpenAIWSClientCloseError
		require.True(t, errors.As(err, &closeErr), "良性 NormalClosure，handler 不再触发账号 failover")
		require.Equal(t, websocket.StatusNormalClosure, closeErr.StatusCode())
	})

	t.Run("delta turn + 绑定同账号: 放行", func(t *testing.T) {
		store := NewOpenAIWSStateStore(&schedulerTestGatewayCache{})
		require.NoError(t, store.BindResponseAccount(ctx, groupID, "resp-1", 3, time.Hour))
		account3 := &Account{ID: 3}
		err := openAIWSSidecarOnDeltaTurnSwitch(ctx, store, groupID, "resp-1", account3, nil, nil, time.Second)
		require.NoError(t, err)
	})

	t.Run("delta turn + 无绑定: 放行", func(t *testing.T) {
		store := NewOpenAIWSStateStore(&schedulerTestGatewayCache{})
		err := openAIWSSidecarOnDeltaTurnSwitch(ctx, store, groupID, "resp-missing", account5, nil, nil, time.Second)
		require.NoError(t, err)
	})

	t.Run("非 delta turn: 放行（换号信号走 header 通道）", func(t *testing.T) {
		store := NewOpenAIWSStateStore(&schedulerTestGatewayCache{})
		err := openAIWSSidecarOnDeltaTurnSwitch(ctx, store, groupID, "", account5, nil, nil, time.Second)
		require.NoError(t, err)
	})
}

func TestOpenAISidecarAccountSwitchHeaderValue(t *testing.T) {
	ctx := WithOpenAISidecarAccountSwitch(context.Background(), 3)
	require.Equal(t, "3", openAISidecarAccountSwitchHeaderValue(ctx, 5))
	// 同账号 / 未标记：不产头。
	require.Empty(t, openAISidecarAccountSwitchHeaderValue(ctx, 3))
	require.Empty(t, openAISidecarAccountSwitchHeaderValue(context.Background(), 5))
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
