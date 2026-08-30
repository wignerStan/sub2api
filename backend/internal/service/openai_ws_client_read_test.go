package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	coderws "github.com/coder/websocket"
	"github.com/stretchr/testify/require"
)

func TestReadOpenAIWSClientMessage_ControlCloseFrames(t *testing.T) {
	tests := []struct {
		name          string
		timeout       time.Duration
		timeoutStatus coderws.StatusCode
		timeoutReason string
		cancelCause   error
		wantStatus    coderws.StatusCode
		wantReason    string
	}{
		{
			name:          "inter-turn idle sends normal close for generic clients",
			timeout:       25 * time.Millisecond,
			timeoutStatus: coderws.StatusNormalClosure,
			timeoutReason: openAIWSClientInterTurnIdleReason,
			wantStatus:    coderws.StatusNormalClosure,
			wantReason:    openAIWSClientInterTurnIdleReason,
		},
		{
			name:          "first message timeout sends policy close",
			timeout:       25 * time.Millisecond,
			timeoutStatus: coderws.StatusPolicyViolation,
			timeoutReason: "missing first response.create message",
			wantStatus:    coderws.StatusPolicyViolation,
			wantReason:    "missing first response.create message",
		},
		{
			name:        "lease loss sends retry close",
			cancelCause: ErrOpenAIWSIngressLeaseLost,
			wantStatus:  coderws.StatusTryAgainLater,
			wantReason:  "websocket ingress capacity lease lost; please reconnect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controlCtx, cancelControl := context.WithCancelCause(context.Background())
			defer cancelControl(context.Canceled)
			serverResult := make(chan error, 1)
			readStarted := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := coderws.Accept(w, r, nil)
				if err != nil {
					serverResult <- err
					return
				}
				defer func() { _ = conn.CloseNow() }()
				close(readStarted)
				_, _, err = ReadOpenAIWSClientMessage(
					controlCtx,
					conn,
					tt.timeout,
					tt.timeoutStatus,
					tt.timeoutReason,
				)
				serverResult <- err
			}))
			defer server.Close()

			dialCtx, cancelDial := context.WithTimeout(context.Background(), time.Second)
			clientConn, _, err := coderws.Dial(dialCtx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
			cancelDial()
			require.NoError(t, err)
			defer func() { _ = clientConn.CloseNow() }()
			<-readStarted
			if tt.cancelCause != nil {
				cancelControl(tt.cancelCause)
			}

			readCtx, cancelRead := context.WithTimeout(context.Background(), time.Second)
			_, _, err = clientConn.Read(readCtx)
			cancelRead()
			var clientClose coderws.CloseError
			require.ErrorAs(t, err, &clientClose)
			require.Equal(t, tt.wantStatus, clientClose.Code)
			require.Equal(t, tt.wantReason, clientClose.Reason)

			select {
			case serverErr := <-serverResult:
				var closeErr *OpenAIWSClientCloseError
				require.ErrorAs(t, serverErr, &closeErr)
				require.Equal(t, tt.wantStatus, closeErr.StatusCode())
				require.Equal(t, tt.wantReason, closeErr.Reason())
			case <-time.After(time.Second):
				t.Fatal("server read goroutine did not exit after close handshake")
			}
		})
	}
}

func TestReadOpenAIWSClientMessage_InterTurnIdleProbesHealthyCodexPeer(t *testing.T) {
	controlCtx, cancelControl := context.WithCancelCause(
		withOpenAIWSClientIdleProbe(context.Background(), true),
	)
	defer cancelControl(context.Canceled)

	serverResult := make(chan openAIWSClientReadResult, 1)
	readStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := coderws.Accept(w, r, nil)
		if err != nil {
			serverResult <- openAIWSClientReadResult{err: err}
			return
		}
		defer func() { _ = conn.CloseNow() }()
		close(readStarted)
		messageType, payload, readErr := ReadOpenAIWSClientMessage(
			controlCtx,
			conn,
			50*time.Millisecond,
			coderws.StatusNormalClosure,
			openAIWSClientInterTurnIdleReason,
		)
		serverResult <- openAIWSClientReadResult{messageType: messageType, payload: payload, err: readErr}
	}))
	defer server.Close()

	dialCtx, cancelDial := context.WithTimeout(context.Background(), time.Second)
	clientConn, _, err := coderws.Dial(dialCtx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	cancelDial()
	require.NoError(t, err)
	defer func() { _ = clientConn.CloseNow() }()
	<-readStarted

	// Keep the peer reader active so coder/websocket can process server pings
	// and emit pongs while the Codex session has no application frames to send.
	clientReadDone := make(chan error, 1)
	go func() {
		_, _, readErr := clientConn.Read(context.Background())
		clientReadDone <- readErr
	}()

	// Cross multiple application-idle intervals. The old behavior closed the
	// root socket at the first interval even though the transport was healthy.
	time.Sleep(180 * time.Millisecond)
	writeCtx, cancelWrite := context.WithTimeout(context.Background(), time.Second)
	err = clientConn.Write(writeCtx, coderws.MessageText, []byte(`{"type":"response.create","model":"gpt-5.6-sol"}`))
	cancelWrite()
	require.NoError(t, err)

	select {
	case result := <-serverResult:
		require.NoError(t, result.err)
		require.Equal(t, coderws.MessageText, result.messageType)
		require.JSONEq(t, `{"type":"response.create","model":"gpt-5.6-sol"}`, string(result.payload))
	case <-time.After(time.Second):
		t.Fatal("healthy idle Codex websocket did not accept the next turn")
	}

	select {
	case <-clientReadDone:
	case <-time.After(time.Second):
		t.Fatal("client reader did not exit after server transport closed")
	}
}

func TestReadOpenAIWSClientMessage_InterTurnIdleClosesUnresponsiveCodexPeer(t *testing.T) {
	controlCtx, cancelControl := context.WithCancelCause(
		withOpenAIWSClientIdleProbe(context.Background(), true),
	)
	defer cancelControl(context.Canceled)

	serverResult := make(chan error, 1)
	readStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := coderws.Accept(w, r, nil)
		if err != nil {
			serverResult <- err
			return
		}
		defer func() { _ = conn.CloseNow() }()
		close(readStarted)
		_, _, err = ReadOpenAIWSClientMessage(
			controlCtx,
			conn,
			25*time.Millisecond,
			coderws.StatusNormalClosure,
			openAIWSClientInterTurnIdleReason,
		)
		serverResult <- err
	}))
	defer server.Close()

	dialCtx, cancelDial := context.WithTimeout(context.Background(), time.Second)
	clientConn, _, err := coderws.Dial(dialCtx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	cancelDial()
	require.NoError(t, err)
	defer func() { _ = clientConn.CloseNow() }()
	<-readStarted

	// Do not read yet: without a peer reader the ping cannot be serviced, so a
	// genuinely stuck client is still reclaimed after the bounded probe.
	time.Sleep(650 * time.Millisecond)
	readCtx, cancelRead := context.WithTimeout(context.Background(), time.Second)
	_, _, err = clientConn.Read(readCtx)
	cancelRead()
	var clientClose coderws.CloseError
	require.ErrorAs(t, err, &clientClose)
	require.Equal(t, coderws.StatusNormalClosure, clientClose.Code)
	require.Equal(t, openAIWSClientInterTurnIdleReason, clientClose.Reason)

	select {
	case serverErr := <-serverResult:
		var closeErr *OpenAIWSClientCloseError
		require.ErrorAs(t, serverErr, &closeErr)
		require.Equal(t, coderws.StatusNormalClosure, closeErr.StatusCode())
		require.Equal(t, openAIWSClientInterTurnIdleReason, closeErr.Reason())
	case <-time.After(time.Second):
		t.Fatal("server read goroutine did not exit after idle liveness failure")
	}
}

func TestReadOpenAIWSClientMessage_ParentCancellationStillJoinsRead(t *testing.T) {
	controlCtx, cancelControl := context.WithCancelCause(context.Background())
	serverResult := make(chan error, 1)
	readStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := coderws.Accept(w, r, nil)
		if err != nil {
			serverResult <- err
			return
		}
		defer func() { _ = conn.CloseNow() }()
		close(readStarted)
		_, _, err = ReadOpenAIWSClientMessage(controlCtx, conn, 0, 0, "")
		serverResult <- err
	}))
	defer server.Close()

	dialCtx, cancelDial := context.WithTimeout(context.Background(), time.Second)
	clientConn, _, err := coderws.Dial(dialCtx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	cancelDial()
	require.NoError(t, err)
	defer func() { _ = clientConn.CloseNow() }()
	<-readStarted
	cancelControl(errors.New("server shutting down"))
	readCtx, cancelRead := context.WithTimeout(context.Background(), time.Second)
	_, _, err = clientConn.Read(readCtx)
	cancelRead()
	var clientClose coderws.CloseError
	require.ErrorAs(t, err, &clientClose)
	require.Equal(t, coderws.StatusGoingAway, clientClose.Code)
	require.Equal(t, "websocket request canceled", clientClose.Reason)

	select {
	case <-serverResult:
	case <-time.After(time.Second):
		t.Fatal("server read goroutine leaked after parent cancellation")
	}
}
