package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	coderws "github.com/coder/websocket"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type decodedOpenAIWSFailoverErrorEvent struct {
	Type       string            `json:"type"`
	Status     int               `json:"status"`
	StatusCode *int              `json:"status_code"`
	EventID    string            `json:"event_id"`
	Error      json.RawMessage   `json:"error"`
	Headers    map[string]string `json:"headers"`
}

func decodeOpenAIWSFailoverErrorEvent(t *testing.T, payload []byte) decodedOpenAIWSFailoverErrorEvent {
	t.Helper()
	var event decodedOpenAIWSFailoverErrorEvent
	require.NoError(t, json.Unmarshal(payload, &event))
	return event
}

func TestBuildOpenAIWSFailoverErrorEventPreservesUpstreamQuota(t *testing.T) {
	failoverErr := &service.UpstreamFailoverError{
		StatusCode: http.StatusTooManyRequests,
		ResponseBody: []byte(`{
			"type":"error",
			"event_id":"evt_quota_123",
			"status_code":418,
			"error":{
				"type":"usage_limit_reached",
				"code":"usage_limit_reached",
				"message":"The usage limit has been reached",
				"plan_type":"pro",
				"resets_at":1785276019,
				"resets_in_seconds":3600
			},
			"headers":{
				"Retry-After":600,
				"Authorization":"Bearer must-not-leak",
				"X-Codex-Primary-Used-Percent":"100"
			}
		}`),
		ResponseHeaders: http.Header{
			"Retry-After":                  []string{"3600"},
			"X-Codex-Primary-Used-Percent": []string{"100"},
		},
	}

	payload := buildOpenAIWSFailoverErrorEvent(
		failoverErr,
		http.StatusTooManyRequests,
		"rate_limit_error",
		"upstream_ws_failover_exhausted",
		"generic message must not replace the provider error",
	)
	event := decodeOpenAIWSFailoverErrorEvent(t, payload)

	require.Equal(t, "error", event.Type)
	require.Equal(t, http.StatusTooManyRequests, event.Status)
	require.Nil(t, event.StatusCode, "status_code must be removed to avoid serde's duplicate alias rejection")
	require.Equal(t, "evt_quota_123", event.EventID)
	require.JSONEq(t, `{
		"type":"usage_limit_reached",
		"code":"usage_limit_reached",
		"message":"The usage limit has been reached",
		"plan_type":"pro",
		"resets_at":1785276019,
		"resets_in_seconds":3600
	}`, string(event.Error))
	require.Equal(t, map[string]string{"retry-after": "600"}, event.Headers)
}

func TestBuildOpenAIWSFailoverErrorEventWrapsHandshakeHTTPBody(t *testing.T) {
	failoverErr := &service.UpstreamFailoverError{
		StatusCode: http.StatusTooManyRequests,
		ResponseBody: []byte(`{
			"error":{
				"type":"usage_limit_reached",
				"message":"The usage limit has been reached before upgrade",
				"plan_type":"plus",
				"resets_in_seconds":1800
			}
		}`),
		ResponseHeaders: http.Header{"Retry-After": []string{"1800"}},
	}

	payload := buildOpenAIWSFailoverErrorEvent(
		failoverErr,
		http.StatusTooManyRequests,
		"rate_limit_error",
		"upstream_ws_failover_exhausted",
		"generic message",
	)
	event := decodeOpenAIWSFailoverErrorEvent(t, payload)

	require.Equal(t, "error", event.Type)
	require.Equal(t, http.StatusTooManyRequests, event.Status)
	require.JSONEq(t, `{
		"type":"usage_limit_reached",
		"message":"The usage limit has been reached before upgrade",
		"plan_type":"plus",
		"resets_in_seconds":1800
	}`, string(event.Error))
	require.Equal(t, map[string]string{"retry-after": "1800"}, event.Headers)
}

func TestBuildOpenAIWSFailoverErrorEventFallsBackSafely(t *testing.T) {
	failoverErr := &service.UpstreamFailoverError{
		StatusCode:   http.StatusTooManyRequests,
		ResponseBody: []byte(`{"detail":"The usage limit has been reached"`),
		ResponseHeaders: http.Header{
			"Retry-After":   []string{"10\r\nAuthorization: secret"},
			"Authorization": []string{"Bearer secret"},
		},
	}

	payload := buildOpenAIWSFailoverErrorEvent(
		failoverErr,
		http.StatusTooManyRequests,
		"rate_limit_error",
		"upstream_ws_failover_exhausted",
		"upstream rate limit exceeded, please retry later",
	)
	event := decodeOpenAIWSFailoverErrorEvent(t, payload)

	require.Equal(t, http.StatusTooManyRequests, event.Status)
	require.JSONEq(t, `{
		"type":"rate_limit_error",
		"code":"rate_limit_exceeded",
		"message":"upstream rate limit exceeded, please retry later"
	}`, string(event.Error))
	require.Empty(t, event.Headers)
}

func TestCloseOpenAIWSFailoverExhaustedSendsUpstreamErrorBeforeClose(t *testing.T) {
	gin.SetMode(gin.TestMode)

	serverErr := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := coderws.Accept(w, r, nil)
		if err != nil {
			serverErr <- err
			return
		}

		recorder := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(recorder)
		ginCtx.Request = r
		closeOpenAIWSFailoverExhausted(ginCtx, conn, &service.UpstreamFailoverError{
			StatusCode: http.StatusTooManyRequests,
			ResponseBody: []byte(`{
				"type":"error",
				"error":{
					"type":"usage_limit_reached",
					"code":"usage_limit_reached",
					"message":"The 5-hour usage limit has been reached",
					"plan_type":"pro",
					"resets_in_seconds":3600
				}
			}`),
			ResponseHeaders: http.Header{"Retry-After": []string{"3600"}},
		})
		serverErr <- nil
	}))
	defer server.Close()

	dialCtx, cancelDial := context.WithTimeout(context.Background(), 5*time.Second)
	clientConn, _, err := coderws.Dial(dialCtx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	cancelDial()
	require.NoError(t, err)
	defer func() { _ = clientConn.CloseNow() }()

	readCtx, cancelRead := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelRead()
	msgType, payload, err := clientConn.Read(readCtx)
	require.NoError(t, err)
	require.Equal(t, coderws.MessageText, msgType)

	event := decodeOpenAIWSFailoverErrorEvent(t, payload)
	require.Equal(t, "error", event.Type)
	require.Equal(t, http.StatusTooManyRequests, event.Status)
	require.JSONEq(t, `{
		"type":"usage_limit_reached",
		"code":"usage_limit_reached",
		"message":"The 5-hour usage limit has been reached",
		"plan_type":"pro",
		"resets_in_seconds":3600
	}`, string(event.Error))
	require.Equal(t, map[string]string{"retry-after": "3600"}, event.Headers)

	_, _, err = clientConn.Read(readCtx)
	var closeErr coderws.CloseError
	require.ErrorAs(t, err, &closeErr)
	require.Equal(t, coderws.StatusTryAgainLater, closeErr.Code)
	require.Equal(t, "upstream rate limit exceeded, please retry later", closeErr.Reason)

	select {
	case err := <-serverErr:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("websocket failover close did not complete")
	}
}
