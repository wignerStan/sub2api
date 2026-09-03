package service

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenAIWSRewriteDownstreamCapacityShedPatch(t *testing.T) {
	t.Run("patch off keeps payload byte-identical", func(t *testing.T) {
		payload := []byte(`{"type":"error","error":{"code":"server_is_overloaded","message":"overloaded"}}`)
		require.Equal(t, payload, openAIWSRewriteDownstreamCapacityShedPatch(append([]byte(nil), payload...)))
	})

	t.Run("capacity shed codes are rewritten for the client copy", func(t *testing.T) {
		t.Setenv("SUB2API_PATCH", "1")
		for _, code := range []string{"server_is_overloaded", "slow_down"} {
			payload := []byte(`{"type":"error","response":{"error":{"code":"` + code + `","message":"upstream is shedding load"}}}`)
			rewritten := openAIWSRewriteDownstreamCapacityShedPatch(append([]byte(nil), payload...))
			require.NotEqual(t, payload, rewritten, code)
			require.Contains(t, string(rewritten), `"code":"server_error"`, code)
			// 原始 payload 判定账号状态的前提：message 原样保留。
			require.Contains(t, string(rewritten), "upstream is shedding load", code)
		}
	})

	t.Run("other error codes pass through untouched", func(t *testing.T) {
		t.Setenv("SUB2API_PATCH", "1")
		payload := []byte(`{"type":"error","error":{"code":"rate_limit_exceeded","message":"slow down please"}}`)
		require.Equal(t, payload, openAIWSRewriteDownstreamCapacityShedPatch(append([]byte(nil), payload...)))
	})

	t.Run("non error events untouched", func(t *testing.T) {
		t.Setenv("SUB2API_PATCH", "1")
		payload := []byte(`{"type":"response.completed","response":{"error":{"code":"server_is_overloaded"}}}`)
		require.Equal(t, payload, openAIWSRewriteDownstreamCapacityShedPatch(append([]byte(nil), payload...)))
	})
}

func TestOpenAIWSRelayBeforeTurnPatch(t *testing.T) {
	t.Run("patch off never invokes the hook", func(t *testing.T) {
		called := false
		hooks := &OpenAIWSIngressHooks{BeforeTurn: func(turn int) error {
			called = true
			return nil
		}}
		require.NoError(t, openAIWSRelayBeforeTurnPatch(hooks, 3))
		require.False(t, called)
	})

	t.Run("patch on invokes BeforeTurn with the turn number", func(t *testing.T) {
		t.Setenv("SUB2API_PATCH", "1")
		seen := 0
		hooks := &OpenAIWSIngressHooks{BeforeTurn: func(turn int) error {
			seen = turn
			return nil
		}}
		require.NoError(t, openAIWSRelayBeforeTurnPatch(hooks, 4))
		require.Equal(t, 4, seen)
	})

	t.Run("patch on surfaces the hook error", func(t *testing.T) {
		t.Setenv("SUB2API_PATCH", "1")
		hooks := &OpenAIWSIngressHooks{BeforeTurn: func(turn int) error {
			return errPatchTestBeforeTurn
		}}
		require.ErrorIs(t, openAIWSRelayBeforeTurnPatch(hooks, 2), errPatchTestBeforeTurn)
	})

	t.Run("nil-safe", func(t *testing.T) {
		t.Setenv("SUB2API_PATCH", "1")
		require.NoError(t, openAIWSRelayBeforeTurnPatch(nil, 2))
	})
}

var errPatchTestBeforeTurn = &openAIWSPatchTestError{}

type openAIWSPatchTestError struct{}

func (*openAIWSPatchTestError) Error() string { return "before turn veto" }

func TestApplyOpenAIAccountCustomErrorMappingPatch(t *testing.T) {
	// API-key account with custom_error_codes_enabled + codes=[403]:
	// 403 is handled by the account itself, everything else downgrades to 500.
	newCustomCodeAccount := func() *Account {
		return &Account{
			Type: AccountTypeAPIKey,
			Credentials: map[string]any{
				"custom_error_codes_enabled": true,
				"custom_error_codes":         []any{float64(http.StatusForbidden)},
			},
		}
	}

	t.Run("patch off leaves failover error untouched", func(t *testing.T) {
		err := &UpstreamFailoverError{}
		applyOpenAIAccountCustomErrorMappingPatch(newCustomCodeAccount(), http.StatusTeapot, err)
		require.Zero(t, err.ClientStatusCode)
		require.Empty(t, err.ClientMessage)
	})

	t.Run("covered status codes pass through", func(t *testing.T) {
		t.Setenv("SUB2API_PATCH", "1")
		err := &UpstreamFailoverError{}
		applyOpenAIAccountCustomErrorMappingPatch(newCustomCodeAccount(), http.StatusForbidden, err)
		require.Zero(t, err.ClientStatusCode)
	})

	t.Run("custom error codes disabled means no downgrade", func(t *testing.T) {
		t.Setenv("SUB2API_PATCH", "1")
		err := &UpstreamFailoverError{}
		applyOpenAIAccountCustomErrorMappingPatch(&Account{Type: AccountTypeAPIKey}, http.StatusTeapot, err)
		require.Zero(t, err.ClientStatusCode)
	})

	t.Run("uncovered status codes downgrade to retryable 500", func(t *testing.T) {
		t.Setenv("SUB2API_PATCH", "1")
		err := &UpstreamFailoverError{}
		applyOpenAIAccountCustomErrorMappingPatch(newCustomCodeAccount(), http.StatusTeapot, err)
		require.Equal(t, http.StatusInternalServerError, err.ClientStatusCode)
		require.Equal(t, "The server encountered an internal error. Please retry your request.", err.ClientMessage)
	})

	t.Run("nil account and nil failover error are safe", func(t *testing.T) {
		t.Setenv("SUB2API_PATCH", "1")
		require.NotPanics(t, func() {
			applyOpenAIAccountCustomErrorMappingPatch(nil, http.StatusTeapot, nil)
		})
	})
}
