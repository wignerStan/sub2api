package service

import (
	"context"
	"errors"
	"time"

	coderws "github.com/coder/websocket"
)

const (
	openAIWSClientInterTurnIdleReason = "websocket idle timeout"
	openAIWSClientIdlePingMinTimeout  = 500 * time.Millisecond
	openAIWSClientIdlePingMaxTimeout  = 5 * time.Second
)

type openAIWSClientReadResult struct {
	messageType coderws.MessageType
	payload     []byte
	err         error
}

type openAIWSClientIdleProbeContextKey struct{}

// withOpenAIWSClientIdleProbe marks a WebSocket request as safe to keep alive
// across application-idle inter-turn periods. The marker is intentionally set
// only after the gateway has identified an official Codex client (or the
// explicit ForceCodexCLI override), so generic WebSocket clients retain the
// configured hard idle-reclaim behavior.
func withOpenAIWSClientIdleProbe(ctx context.Context, enabled bool) context.Context {
	if !enabled {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, openAIWSClientIdleProbeContextKey{}, true)
}

func openAIWSClientShouldProbeIdle(controlCtx context.Context, timeoutStatus coderws.StatusCode, timeoutReason string) bool {
	if controlCtx == nil {
		return false
	}
	probeEnabled, _ := controlCtx.Value(openAIWSClientIdleProbeContextKey{}).(bool)
	return probeEnabled && timeoutStatus == coderws.StatusNormalClosure && timeoutReason == openAIWSClientInterTurnIdleReason
}

// openAIWSClientIdlePingTimeout keeps liveness probes long enough to tolerate
// normal scheduler/network jitter while bounding the time a genuinely dead
// Codex peer can hold an ingress lease after its configured idle interval.
func openAIWSClientIdlePingTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 || timeout > openAIWSClientIdlePingMaxTimeout {
		return openAIWSClientIdlePingMaxTimeout
	}
	if timeout < openAIWSClientIdlePingMinTimeout {
		return openAIWSClientIdlePingMinTimeout
	}
	return timeout
}

// ReadOpenAIWSClientMessage keeps one reader alive while control events send
// their close frame, then closes the transport and joins that reader.
func ReadOpenAIWSClientMessage(
	controlCtx context.Context,
	conn *coderws.Conn,
	timeout time.Duration,
	timeoutStatus coderws.StatusCode,
	timeoutReason string,
) (coderws.MessageType, []byte, error) {
	return readOpenAIWSClientMessageWithTimeoutStart(
		controlCtx,
		conn,
		timeout,
		timeoutStatus,
		timeoutReason,
		nil,
		nil,
	)
}

// readOpenAIWSClientMessageWithTimeoutStart supports readers whose timeout
// starts after a state transition, such as a completed passthrough turn. When
// timeoutActive is nil, a positive timeout starts immediately.
func readOpenAIWSClientMessageWithTimeoutStart(
	controlCtx context.Context,
	conn *coderws.Conn,
	timeout time.Duration,
	timeoutStatus coderws.StatusCode,
	timeoutReason string,
	timeoutStart <-chan struct{},
	timeoutActive func() bool,
) (coderws.MessageType, []byte, error) {
	if conn == nil {
		return 0, nil, errors.New("openai websocket client connection is nil")
	}
	if controlCtx == nil {
		controlCtx = context.Background()
	}

	readDone := make(chan openAIWSClientReadResult, 1)
	go func() {
		messageType, payload, err := conn.Read(context.Background())
		readDone <- openAIWSClientReadResult{messageType: messageType, payload: payload, err: err}
	}()

	var timer *time.Timer
	var timeoutCh <-chan time.Time
	startTimeout := func() {
		if timeout <= 0 || (timeoutActive != nil && !timeoutActive()) {
			return
		}
		if timer == nil {
			timer = time.NewTimer(timeout)
		} else {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(timeout)
		}
		timeoutCh = timer.C
	}
	if timeoutActive == nil || timeoutActive() {
		startTimeout()
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	closeAndJoin := func(status coderws.StatusCode, reason string, cause error) (coderws.MessageType, []byte, error) {
		_ = conn.Close(status, reason)
		_ = conn.CloseNow()
		<-readDone
		return 0, nil, NewOpenAIWSClientCloseError(status, reason, cause)
	}
	closeForControl := func(cause error) (coderws.MessageType, []byte, error) {
		if errors.Is(cause, ErrOpenAIWSIngressLeaseLost) {
			return closeAndJoin(
				coderws.StatusTryAgainLater,
				"websocket ingress capacity lease lost; please reconnect",
				cause,
			)
		}
		return closeAndJoin(coderws.StatusGoingAway, "websocket request canceled", cause)
	}

	for {
		select {
		case result := <-readDone:
			return result.messageType, result.payload, result.err
		case <-timeoutStart:
			startTimeout()
		case <-timeoutCh:
			timeoutCh = nil
			if timeoutActive != nil && !timeoutActive() {
				continue
			}
			if !openAIWSClientShouldProbeIdle(controlCtx, timeoutStatus, timeoutReason) {
				return closeAndJoin(timeoutStatus, timeoutReason, context.DeadlineExceeded)
			}

			// Inter-turn silence is not proof that a persistent Codex WebSocket is
			// dead. Probe transport liveness while the existing reader remains
			// active so coder/websocket can process the peer pong. Generic clients
			// never reach this branch and retain hard idle reclamation.
			pingCtx, cancelPing := context.WithTimeout(controlCtx, openAIWSClientIdlePingTimeout(timeout))
			pingDone := make(chan error, 1)
			go func() {
				pingDone <- conn.Ping(pingCtx)
			}()

			select {
			case result := <-readDone:
				cancelPing()
				return result.messageType, result.payload, result.err
			case pingErr := <-pingDone:
				cancelPing()
				if pingErr == nil {
					startTimeout()
					continue
				}
				// Prefer a data frame that raced with the failed ping over an idle
				// close; the peer demonstrated application activity.
				select {
				case result := <-readDone:
					return result.messageType, result.payload, result.err
				default:
				}
				if controlCtx.Err() != nil {
					return closeForControl(context.Cause(controlCtx))
				}
				return closeAndJoin(timeoutStatus, timeoutReason, pingErr)
			case <-controlCtx.Done():
				cancelPing()
				return closeForControl(context.Cause(controlCtx))
			}
		case <-controlCtx.Done():
			return closeForControl(context.Cause(controlCtx))
		}
	}
}
