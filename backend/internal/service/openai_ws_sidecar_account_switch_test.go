package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenAIWSSidecarAccountSwitchFrame(t *testing.T) {
	// 无切换场景不产帧。
	require.Nil(t, openAIWSSidecarAccountSwitchFrame(0, 5))
	require.Nil(t, openAIWSSidecarAccountSwitchFrame(5, 5))
	require.Nil(t, openAIWSSidecarAccountSwitchFrame(-1, 5))

	frame := openAIWSSidecarAccountSwitchFrame(3, 5)
	require.NotNil(t, frame)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(frame, &decoded))
	require.Equal(t, "account-switch", decoded["x-s2s-vframe"])
	require.Equal(t, float64(3), decoded["previous_account_id"])
	require.Equal(t, float64(5), decoded["account_id"])
}

func TestOpenAISidecarAccountSwitchHeaderValue(t *testing.T) {
	ctx := WithOpenAISidecarAccountSwitch(context.Background(), 3)
	require.Equal(t, "3", openAISidecarAccountSwitchHeaderValue(ctx, 5))
	// 同账号 / 未标记：不产头。
	require.Empty(t, openAISidecarAccountSwitchHeaderValue(ctx, 3))
	require.Empty(t, openAISidecarAccountSwitchHeaderValue(context.Background(), 5))
	require.Empty(t, openAISidecarAccountSwitchHeaderValue(context.Background(), 0))
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
