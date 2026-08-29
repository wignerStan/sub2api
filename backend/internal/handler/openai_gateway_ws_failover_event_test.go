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

func TestCloseOpenAIWSFailoverExhaustedSendsHTTPErrorBeforeClose(t *testing.T) {
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
			Reason:     "usage_limit_reached",
			ResponseHeaders: http.Header{
				"Retry-After":                  []string{"3600"},
				"X-Codex-Primary-Used-Percent": []string{"100"},
			},
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
	msgType, payload, err := clientConn.Read(readCtx)
	require.NoError(t, err)
	require.Equal(t, coderws.MessageText, msgType)

	var event openAIWSFailoverErrorEvent
	require.NoError(t, json.Unmarshal(payload, &event))
	require.Equal(t, "error", event.Type)
	require.Equal(t, http.StatusTooManyRequests, event.Status)
	require.Equal(t, "rate_limit_error", event.Error.Type)
	require.Equal(t, "usage_limit_reached", event.Error.Code)
	require.Equal(t, "upstream rate limit exceeded, please retry later", event.Error.Message)
	require.Equal(t, map[string]string{"retry-after": "3600"}, event.Headers)

	_, _, err = clientConn.Read(readCtx)
	cancelRead()
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
