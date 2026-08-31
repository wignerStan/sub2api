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
	// Keep the protocol heartbeat comfortably below the shortest idle timeout
	// commonly imposed by an ingress proxy.  A configured application timeout
	// can shorten this interval, but it must never postpone the first ping.
	openAIWSClientIdlePingIntervalDefault = 10 * time.Second
	openAIWSClientIdlePingIntervalMin     = 250 * time.Millisecond
)

type openAIWSClientReadResult struct {
	messageType coderws.MessageType
	payload     []byte
	err         error
}

// openAIWSIdlePingNonTerminalError lets a caller retire only an auxiliary
// transport (for example, a pooled upstream lease) while keeping the client
// WebSocket alive.  A failed upstream Pong must not be converted into the
// downstream inter-turn idle close: the client may still be connected and can
// send its next turn on a freshly acquired upstream socket.
type openAIWSIdlePingNonTerminalError struct {
	err error
}

func (e *openAIWSIdlePingNonTerminalError) Error() string {
	if e == nil || e.err == nil {
		return "non-terminal websocket idle ping failed"
	}
	return e.err.Error()
}

func (e *openAIWSIdlePingNonTerminalError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func newOpenAIWSIdlePingNonTerminalError(err error) error {
	if err == nil {
		return nil
	}
	return &openAIWSIdlePingNonTerminalError{err: err}
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

func openAIWSClientIdlePingInterval(timeout time.Duration) time.Duration {
	interval := openAIWSClientIdlePingIntervalDefault
	if timeout > 0 {
		// Probe at least twice during one configured idle window.  This keeps
		// the application timeout as a useful upper bound for non-protocol
		// failures while still allowing normal network jitter.
		if candidate := timeout / 3; candidate > 0 && candidate < interval {
			interval = candidate
		}
	}
	if interval < openAIWSClientIdlePingIntervalMin {
		interval = openAIWSClientIdlePingIntervalMin
	}
	return interval
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
	return ReadOpenAIWSClientMessageWithIdlePing(
		controlCtx,
		conn,
		timeout,
		timeoutStatus,
		timeoutReason,
		nil,
	)
}

// ReadOpenAIWSClientMessageWithIdlePing is the session variant used when a
// pooled upstream connection must be probed alongside the downstream client.
// The callback is optional; a nil callback preserves the ordinary client-only
// behavior.
func ReadOpenAIWSClientMessageWithIdlePing(
	controlCtx context.Context,
	conn *coderws.Conn,
	timeout time.Duration,
	timeoutStatus coderws.StatusCode,
	timeoutReason string,
	idlePing func(context.Context) error,
) (coderws.MessageType, []byte, error) {
	return readOpenAIWSClientMessageWithTimeoutStart(
		controlCtx,
		conn,
		timeout,
		timeoutStatus,
		timeoutReason,
		nil,
		nil,
		idlePing,
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
	idlePings ...func(context.Context) error,
) (coderws.MessageType, []byte, error) {
	if conn == nil {
		return 0, nil, errors.New("openai websocket client connection is nil")
	}
	if controlCtx == nil {
		controlCtx = context.Background()
	}
	var upstreamIdlePing func(context.Context) error
	if len(idlePings) > 0 {
		upstreamIdlePing = idlePings[0]
	}

	readDone := make(chan openAIWSClientReadResult, 1)
	readDoneConsumed := false
	readPump := openAIWSClientReadPumpFromContext(controlCtx, conn)
	go func() {
		var messageType coderws.MessageType
		var payload []byte
		var err error
		if readPump != nil {
			messageType, payload, err = readPump.ReadFrame(context.Background())
		} else {
			messageType, payload, err = conn.Read(context.Background())
		}
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
	probeEnabled := openAIWSClientShouldProbeIdle(controlCtx, timeoutStatus, timeoutReason)
	var pingTicker *time.Ticker
	var pingTickerCh <-chan time.Time
	if probeEnabled {
		pingTicker = time.NewTicker(openAIWSClientIdlePingInterval(timeout))
		pingTickerCh = pingTicker.C
		defer pingTicker.Stop()
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	closeAndJoin := func(status coderws.StatusCode, reason string, cause error) (coderws.MessageType, []byte, error) {
		// Conn.Close already bounds the close handshake and then closes the
		// underlying transport.  Calling CloseNow immediately afterwards races
		// that handshake and is the source of bare TCP resets (1005/EOF) seen by
		// Codex.  Route through the session reader adapter when present so its
		// sole Reader is joined before this function returns.
		_ = CloseOpenAIWSClientGracefully(controlCtx, conn, status, reason)
		if !readDoneConsumed {
			// Keep the final join bounded too. A broken peer must never strand
			// the HTTP handler after the close frame has already been queued.
			select {
			case <-readDone:
			case <-time.After(2 * time.Second):
			}
		}
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
	probeIdle := func() (coderws.MessageType, []byte, error, bool) {
		// Keep both halves alive.  The downstream reader is already active in
		// this function; the optional upstream callback is backed by the pool's
		// dedicated reader pump and is therefore safe to run concurrently.
		pingTimeout := openAIWSClientIdlePingTimeout(timeout)
		// coder/websocket attaches an AfterFunc to every write context; cancelling
		// that context while Ping is still flushing closes the whole connection.
		// Give each protocol operation a detached context and join its result before
		// returning from this function.  The caller's cancellation is consulted
		// before a probe starts, but is never used to abort an in-flight control
		// frame.
		downstreamPingCtx, cancelDownstreamPing := context.WithTimeout(context.Background(), pingTimeout)
		upstreamPingCtx, cancelUpstreamPing := context.WithTimeout(context.Background(), pingTimeout)
		pingDone := make(chan error, 1)
		go func() {
			pingDone <- conn.Ping(downstreamPingCtx)
		}()
		upstreamPingDone := make(chan error, 1)
		if upstreamIdlePing != nil {
			go func() {
				upstreamPingDone <- upstreamIdlePing(upstreamPingCtx)
			}()
		} else {
			upstreamPingDone <- nil
		}

		pending := 2
		var downstreamErr error
		var upstreamErr error
		var readResult openAIWSClientReadResult
		haveReadResult := false
		readDoneCh := (<-chan openAIWSClientReadResult)(readDone)
		controlDoneCh := controlCtx.Done()
		for pending > 0 {
			select {
			case result := <-readDoneCh:
				// Do not cancel either operation here; see the write-context note
				// above.  We join both result channels before returning the raced
				// data frame.
				// Disable this case after the first result so a closed/ready channel
				// cannot spin while the two probes finish.
				readResult = result
				haveReadResult = true
				readDoneConsumed = true
				readDoneCh = nil
			case err := <-pingDone:
				pending--
				downstreamErr = err
				cancelDownstreamPing()
			case err := <-upstreamPingDone:
				pending--
				upstreamErr = err
				cancelUpstreamPing()
			case <-controlDoneCh:
				// Do not cancel in-flight Ping operations.  Disable this case and
				// wait for their bounded contexts to settle, then perform the
				// graceful close handshake.
				controlDoneCh = nil
			}
		}
		// Both operations have returned, so cancellation cannot trigger a
		// coder/websocket write-timeout callback anymore.
		cancelDownstreamPing()
		cancelUpstreamPing()
		if haveReadResult {
			return readResult.messageType, readResult.payload, readResult.err, true
		}
		if downstreamErr == nil && upstreamErr == nil {
			startTimeout()
			return 0, nil, nil, false
		}
		// An auxiliary upstream probe can fail while the downstream client is
		// perfectly healthy.  The callback has already marked that lease broken;
		// stop probing that stale lease and continue waiting for the next client
		// frame.  Closing the downstream here would recreate the exact
		// multi-agent failure this helper is meant to prevent.
		if downstreamErr == nil {
			var nonTerminal *openAIWSIdlePingNonTerminalError
			if errors.As(upstreamErr, &nonTerminal) {
				upstreamIdlePing = nil
				startTimeout()
				return 0, nil, nil, false
			}
		}
		// Prefer a data frame that raced with a failed ping over an idle close;
		// the peer demonstrated application activity.
		select {
		case result := <-readDone:
			return result.messageType, result.payload, result.err, true
		default:
		}
		if controlCtx.Err() != nil {
			msgType, payload, err := closeForControl(context.Cause(controlCtx))
			return msgType, payload, err, true
		}
		cause := downstreamErr
		if cause == nil {
			cause = upstreamErr
		}
		msgType, payload, err := closeAndJoin(timeoutStatus, timeoutReason, cause)
		return msgType, payload, err, true
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
			if !probeEnabled {
				return closeAndJoin(timeoutStatus, timeoutReason, context.DeadlineExceeded)
			}
			if msgType, payload, err, done := probeIdle(); done {
				return msgType, payload, err
			}
		case <-pingTickerCh:
			if timeoutActive != nil && !timeoutActive() {
				continue
			}
			if msgType, payload, err, done := probeIdle(); done {
				return msgType, payload, err
			}
		case <-controlCtx.Done():
			return closeForControl(context.Cause(controlCtx))
		}
	}
}
