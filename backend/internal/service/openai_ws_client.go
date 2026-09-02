package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	openaiwsv2 "github.com/Wei-Shaw/sub2api/internal/service/openai_ws_v2"
	coderws "github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

const openAIWSMessageReadLimitBytes int64 = 16 * 1024 * 1024
const (
	openAIWSProxyTransportMaxIdleConns        = 128
	openAIWSProxyTransportMaxIdleConnsPerHost = 64
	openAIWSProxyTransportIdleConnTimeout     = 90 * time.Second
	openAIWSProxyClientCacheMaxEntries        = 256
	openAIWSProxyClientCacheIdleTTL           = 15 * time.Minute
)

type OpenAIWSTransportMetricsSnapshot struct {
	ProxyClientCacheHits   int64   `json:"proxy_client_cache_hits"`
	ProxyClientCacheMisses int64   `json:"proxy_client_cache_misses"`
	TransportReuseRatio    float64 `json:"transport_reuse_ratio"`
}

// openAIWSClientConn 抽象 WS 客户端连接，便于替换底层实现。
type openAIWSClientConn interface {
	WriteJSON(ctx context.Context, value any) error
	ReadMessage(ctx context.Context) ([]byte, error)
	Ping(ctx context.Context) error
	Close() error
}

// openAIWSGracefulCloser is implemented by adapters that own a background
// reader.  Close() on a pooled upstream adapter intentionally means "retire
// immediately", while a client-facing adapter must send a RFC 6455 close
// frame and wait for the peer acknowledgement.  Keeping the capability
// optional preserves compatibility with the small test doubles used by the
// pool and relay tests.
type openAIWSGracefulCloser interface {
	CloseGracefully(status coderws.StatusCode, reason string) error
}

// openAIWSIdlePingCapable is intentionally separate from openAIWSClientConn.
// A pool probe happens while no goroutine is reading an idle connection, which
// is not safe for every WebSocket implementation.
type openAIWSIdlePingCapable interface {
	SupportsIdlePingWithoutReader() bool
}

// openAIWSReadTimeoutTerminal is implemented by adapters whose ReadMessage
// call is decoupled from the caller context by a background reader.  For
// those adapters a per-call timeout must explicitly retire the transport to
// preserve the historical coder/websocket timeout semantics; test doubles
// and legacy adapters may keep their old per-read behavior.
type openAIWSReadTimeoutTerminal interface {
	ReadTimeoutClosesConnection() bool
}

type openAIWSClientReadPumpContextKey struct{}

// WithOpenAIWSClientReadPump installs one long-lived reader for a downstream
// WebSocket session.  The reader consumes control frames (including Pong) even
// while the gateway is waiting for an upstream response, and queues data
// frames for the regular ReadOpenAIWSClientMessage calls.  Callers that do not
// opt in retain the historical per-read behavior.
func WithOpenAIWSClientReadPump(ctx context.Context, conn *coderws.Conn) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if conn == nil {
		return ctx
	}
	if existing, ok := ctx.Value(openAIWSClientReadPumpContextKey{}).(*coderOpenAIWSClientConn); ok && existing != nil && existing.conn == conn {
		return ctx
	}
	reader := &coderOpenAIWSClientConn{conn: conn}
	reader.ensureReadPump()
	return context.WithValue(ctx, openAIWSClientReadPumpContextKey{}, reader)
}

func openAIWSClientReadPumpFromContext(ctx context.Context, conn *coderws.Conn) *coderOpenAIWSClientConn {
	if ctx == nil || conn == nil {
		return nil
	}
	reader, _ := ctx.Value(openAIWSClientReadPumpContextKey{}).(*coderOpenAIWSClientConn)
	if reader == nil || reader.conn != conn {
		return nil
	}
	return reader
}

// CloseOpenAIWSClientGracefully closes a client WebSocket through the reader
// pump when one is installed.  A raw coder/websocket Close is still safe for
// callers that did not opt into the pump.  In particular, this helper must not
// be followed by CloseNow: doing so races the close handshake and produces the
// "connection reset without closing handshake" observed by Codex clients.
func CloseOpenAIWSClientGracefully(ctx context.Context, conn *coderws.Conn, status coderws.StatusCode, reason string) error {
	if conn == nil {
		return nil
	}
	if reader := openAIWSClientReadPumpFromContext(ctx, conn); reader != nil {
		return reader.CloseGracefully(status, reason)
	}
	return conn.Close(status, reason)
}

// openAIWSClientDialer 抽象 WS 建连器。
type openAIWSClientDialer interface {
	Dial(ctx context.Context, wsURL string, headers http.Header, proxyURL string) (openAIWSClientConn, int, http.Header, error)
}

// openAIWSAccountAwareClientDialer is implemented only by transports that need
// the scheduler-owned local account ID. Keeping it out of the base interface
// prevents internal selectors from leaking to ordinary upstream WebSockets.
type openAIWSAccountAwareClientDialer interface {
	DialForAccount(ctx context.Context, wsURL string, headers http.Header, proxyURL string, accountID int64) (openAIWSClientConn, int, http.Header, error)
}

type openAIWSTransportMetricsDialer interface {
	SnapshotTransportMetrics() OpenAIWSTransportMetricsSnapshot
}

func newDefaultOpenAIWSClientDialer() openAIWSClientDialer {
	return &coderOpenAIWSClientDialer{
		proxyClients: make(map[string]*openAIWSProxyClientEntry),
	}
}


type coderOpenAIWSClientDialer struct {
	proxyMu      sync.Mutex
	proxyClients map[string]*openAIWSProxyClientEntry
	proxyHits    atomic.Int64
	proxyMisses  atomic.Int64
}

// openAIWSHandshakeError keeps a bounded, non-logged HTTP error body so the
// Agent Identity recovery path can distinguish an invalid task from other
// 401 handshake failures.
type openAIWSHandshakeError struct {
	Body []byte
	Err  error
}

func (e *openAIWSHandshakeError) Error() string {
	if e == nil || e.Err == nil {
		return "openai ws handshake failed"
	}
	return e.Err.Error()
}

func (e *openAIWSHandshakeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type openAIWSProxyClientEntry struct {
	client           *http.Client
	lastUsedUnixNano int64
}

func (d *coderOpenAIWSClientDialer) Dial(
	ctx context.Context,
	wsURL string,
	headers http.Header,
	proxyURL string,
) (openAIWSClientConn, int, http.Header, error) {
	targetURL := strings.TrimSpace(wsURL)
	if targetURL == "" {
		return nil, 0, nil, errors.New("ws url is empty")
	}

	outboundHeaders := cloneHeader(headers)
	stripSidecarControlHeaders(outboundHeaders)
	opts := &coderws.DialOptions{
		HTTPHeader:      outboundHeaders,
		CompressionMode: coderws.CompressionContextTakeover,
	}
	if proxy := strings.TrimSpace(proxyURL); proxy != "" {
		proxyClient, err := d.proxyHTTPClient(proxy)
		if err != nil {
			return nil, 0, nil, err
		}
		opts.HTTPClient = proxyClient
	}

	conn, resp, err := coderws.Dial(ctx, targetURL, opts)
	if err != nil {
		status := 0
		respHeaders := http.Header(nil)
		if resp != nil {
			status = resp.StatusCode
			respHeaders = cloneHeader(resp.Header)
		}
		var body []byte
		if resp != nil && resp.Body != nil {
			body, _ = io.ReadAll(io.LimitReader(resp.Body, 8<<10))
			_ = resp.Body.Close()
		}
		return nil, status, respHeaders, &openAIWSHandshakeError{Body: body, Err: err}
	}
	// coder/websocket 默认单消息读取上限为 32KB，Codex WS 事件（如 rate_limits/大 delta）
	// 可能超过该阈值，需显式提高上限，避免本地 read_fail(message too big)。
	conn.SetReadLimit(openAIWSMessageReadLimitBytes)
	respHeaders := http.Header(nil)
	if resp != nil {
		respHeaders = cloneHeader(resp.Header)
	}
	connWrapper := &coderOpenAIWSClientConn{conn: conn}
	connWrapper.ensureReadPump()
	return connWrapper, 0, respHeaders, nil
}

func (d *coderOpenAIWSClientDialer) proxyHTTPClient(proxy string) (*http.Client, error) {
	if d == nil {
		return nil, errors.New("openai ws dialer is nil")
	}
	normalizedProxy := strings.TrimSpace(proxy)
	if normalizedProxy == "" {
		return nil, errors.New("proxy url is empty")
	}
	parsedProxyURL, err := url.Parse(normalizedProxy)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy url: %w", err)
	}
	now := time.Now().UnixNano()

	d.proxyMu.Lock()
	defer d.proxyMu.Unlock()
	if entry, ok := d.proxyClients[normalizedProxy]; ok && entry != nil && entry.client != nil {
		entry.lastUsedUnixNano = now
		d.proxyHits.Add(1)
		return entry.client, nil
	}
	d.cleanupProxyClientsLocked(now)
	transport := &http.Transport{
		Proxy:               http.ProxyURL(parsedProxyURL),
		MaxIdleConns:        openAIWSProxyTransportMaxIdleConns,
		MaxIdleConnsPerHost: openAIWSProxyTransportMaxIdleConnsPerHost,
		IdleConnTimeout:     openAIWSProxyTransportIdleConnTimeout,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	client := &http.Client{Transport: transport}
	d.proxyClients[normalizedProxy] = &openAIWSProxyClientEntry{
		client:           client,
		lastUsedUnixNano: now,
	}
	d.ensureProxyClientCapacityLocked()
	d.proxyMisses.Add(1)
	return client, nil
}

func (d *coderOpenAIWSClientDialer) cleanupProxyClientsLocked(nowUnixNano int64) {
	if d == nil || len(d.proxyClients) == 0 {
		return
	}
	idleTTL := openAIWSProxyClientCacheIdleTTL
	if idleTTL <= 0 {
		return
	}
	now := time.Unix(0, nowUnixNano)
	for key, entry := range d.proxyClients {
		if entry == nil || entry.client == nil {
			delete(d.proxyClients, key)
			continue
		}
		lastUsed := time.Unix(0, entry.lastUsedUnixNano)
		if now.Sub(lastUsed) > idleTTL {
			closeOpenAIWSProxyClient(entry.client)
			delete(d.proxyClients, key)
		}
	}
}

func (d *coderOpenAIWSClientDialer) ensureProxyClientCapacityLocked() {
	if d == nil {
		return
	}
	maxEntries := openAIWSProxyClientCacheMaxEntries
	if maxEntries <= 0 {
		return
	}
	for len(d.proxyClients) > maxEntries {
		var oldestKey string
		var oldestLastUsed int64
		hasOldest := false
		for key, entry := range d.proxyClients {
			lastUsed := int64(0)
			if entry != nil {
				lastUsed = entry.lastUsedUnixNano
			}
			if !hasOldest || lastUsed < oldestLastUsed {
				hasOldest = true
				oldestKey = key
				oldestLastUsed = lastUsed
			}
		}
		if !hasOldest {
			return
		}
		if entry := d.proxyClients[oldestKey]; entry != nil {
			closeOpenAIWSProxyClient(entry.client)
		}
		delete(d.proxyClients, oldestKey)
	}
}

func closeOpenAIWSProxyClient(client *http.Client) {
	if client == nil || client.Transport == nil {
		return
	}
	if transport, ok := client.Transport.(*http.Transport); ok && transport != nil {
		transport.CloseIdleConnections()
	}
}

func (d *coderOpenAIWSClientDialer) SnapshotTransportMetrics() OpenAIWSTransportMetricsSnapshot {
	if d == nil {
		return OpenAIWSTransportMetricsSnapshot{}
	}
	hits := d.proxyHits.Load()
	misses := d.proxyMisses.Load()
	total := hits + misses
	reuseRatio := 0.0
	if total > 0 {
		reuseRatio = float64(hits) / float64(total)
	}
	return OpenAIWSTransportMetricsSnapshot{
		ProxyClientCacheHits:   hits,
		ProxyClientCacheMisses: misses,
		TransportReuseRatio:    reuseRatio,
	}
}

type coderOpenAIWSClientConn struct {
	conn *coderws.Conn

	// coder/websocket permits exactly one Reader.  A pooled upstream connection
	// must nevertheless keep consuming control frames while the application is
	// between turns, otherwise Conn.Ping cannot observe the matching Pong.  The
	// pump below is the sole Reader and hands data messages to callers through a
	// small queue.  Keeping this ownership in the concrete coder adapter also
	// means E2EE and sidecar transports get the same semantics without changing
	// the openAIWSClientConn interface used by test doubles.
	readOnce     sync.Once
	readCtx      context.Context
	readCancel   context.CancelFunc
	readQueueMu  sync.Mutex
	readQueue    []coderOpenAIWSReadResult
	readNotify   chan struct{}
	readDone     chan struct{}
	readFinished bool
	readErrMu    sync.RWMutex
	readErr      error
	closed       atomic.Bool
	closeOnce    sync.Once
	closeErr     error
}

type coderOpenAIWSReadResult struct {
	messageType coderws.MessageType
	payload     []byte
	err         error
}

func (c *coderOpenAIWSClientConn) ensureReadPump() bool {
	if c == nil || c.conn == nil || c.closed.Load() {
		return false
	}
	c.readOnce.Do(func() {
		// Close may win the race with the first Read/Ping call.  Do not start a
		// new reader after the transport has entered its terminal state.
		if c.closed.Load() {
			return
		}
		c.readCtx, c.readCancel = context.WithCancel(context.Background())
		// Use an in-memory queue rather than a bounded result channel.  A
		// server can legitimately burst dozens of events while the gateway is
		// between turn callbacks; blocking the sole Reader on a small channel
		// would prevent it from consuming the next Pong and make a healthy
		// connection look dead to Conn.Ping.  The queue is drained in FIFO order
		// and is released with the connection's lifecycle.
		c.readNotify = make(chan struct{}, 1)
		c.readDone = make(chan struct{})
		go c.readPump()
	})
	return c.readNotify != nil
}

func (c *coderOpenAIWSClientConn) readPump() {
	defer func() {
		c.readQueueMu.Lock()
		c.readFinished = true
		c.readQueueMu.Unlock()
		select {
		case c.readNotify <- struct{}{}:
		default:
		}
		close(c.readDone)
	}()
	for {
		// The pump owns the only Reader for the lifetime of the transport.  Its
		// context is cancelled only by Close, so using it here gives shutdown a
		// deterministic way to trigger coder/websocket's read-timeout hook and
		// wake a blocked network read.  Never use a per-call context: callers may
		// time out while the connection itself remains healthy between turns.
		messageType, payload, err := c.conn.Read(c.readCtx)
		if err != nil {
			c.readErrMu.Lock()
			c.readErr = err
			c.readErrMu.Unlock()
		}
		result := coderOpenAIWSReadResult{
			messageType: messageType,
			payload:     payload,
			err:         err,
		}
		select {
		case <-c.readCtx.Done():
			return
		default:
		}
		c.readQueueMu.Lock()
		c.readQueue = append(c.readQueue, result)
		c.readQueueMu.Unlock()
		select {
		case c.readNotify <- struct{}{}:
		default:
		}
		if err != nil {
			return
		}
	}
}

func (c *coderOpenAIWSClientConn) nextRead(ctx context.Context) (coderOpenAIWSReadResult, error) {
	if !c.ensureReadPump() {
		return coderOpenAIWSReadResult{}, errOpenAIWSConnClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		// Prefer a frame already queued by the pump over a simultaneously
		// cancelled caller context.  This is important at a turn boundary where
		// a response can race the inter-turn timer.
		c.readQueueMu.Lock()
		if len(c.readQueue) > 0 {
			result := c.readQueue[0]
			c.readQueue[0] = coderOpenAIWSReadResult{}
			c.readQueue = c.readQueue[1:]
			c.readQueueMu.Unlock()
			return result, nil
		}
		finished := c.readFinished
		notify := c.readNotify
		done := c.readDone
		c.readQueueMu.Unlock()
		if finished {
			return coderOpenAIWSReadResult{}, c.terminalReadError()
		}
		select {
		case <-ctx.Done():
			return coderOpenAIWSReadResult{}, ctx.Err()
		case <-notify:
			continue
		case <-done:
			// Recheck the queue first: the pump publishes its terminal result
			// before closing readDone.
			continue
		}
	}
}

func (c *coderOpenAIWSClientConn) terminalReadError() error {
	if c == nil {
		return errOpenAIWSConnClosed
	}
	c.readErrMu.RLock()
	err := c.readErr
	c.readErrMu.RUnlock()
	if err != nil {
		return err
	}
	return errOpenAIWSConnClosed
}

var _ openaiwsv2.FrameConn = (*coderOpenAIWSClientConn)(nil)

func (c *coderOpenAIWSClientConn) WriteJSON(ctx context.Context, value any) error {
	if c == nil || c.conn == nil {
		return errOpenAIWSConnClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return wsjson.Write(ctx, c.conn, value)
}

func (c *coderOpenAIWSClientConn) ReadMessage(ctx context.Context) ([]byte, error) {
	if c == nil || c.conn == nil {
		return nil, errOpenAIWSConnClosed
	}
	result, err := c.nextRead(ctx)
	if err != nil {
		return nil, err
	}
	if result.err != nil {
		return nil, result.err
	}
	switch result.messageType {
	case coderws.MessageText, coderws.MessageBinary:
		return result.payload, nil
	default:
		return nil, errOpenAIWSConnClosed
	}
}

func (c *coderOpenAIWSClientConn) ReadFrame(ctx context.Context) (coderws.MessageType, []byte, error) {
	if c == nil || c.conn == nil {
		return coderws.MessageText, nil, errOpenAIWSConnClosed
	}
	result, err := c.nextRead(ctx)
	if err != nil {
		return coderws.MessageText, nil, err
	}
	return result.messageType, result.payload, result.err
}

func (c *coderOpenAIWSClientConn) WriteFrame(ctx context.Context, msgType coderws.MessageType, payload []byte) error {
	if c == nil || c.conn == nil {
		return errOpenAIWSConnClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return c.conn.Write(ctx, msgType, payload)
}

func (c *coderOpenAIWSClientConn) Ping(ctx context.Context) error {
	if c == nil || c.conn == nil {
		return errOpenAIWSConnClosed
	}
	if !c.ensureReadPump() {
		return errOpenAIWSConnClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return c.conn.Ping(ctx)
}

func (c *coderOpenAIWSClientConn) SupportsPing() bool {
	return c != nil && c.conn != nil && !c.closed.Load()
}

func (*coderOpenAIWSClientConn) ReadTimeoutClosesConnection() bool { return true }

// SupportsIdlePingWithoutReader reports the adapter's read-pump contract.
// Conn.Ping itself still requires a Reader, but ensureReadPump installs one
// before every ping, including on an otherwise idle pooled connection.
func (c *coderOpenAIWSClientConn) SupportsIdlePingWithoutReader() bool {
	return c != nil && c.conn != nil && !c.closed.Load()
}

func (c *coderOpenAIWSClientConn) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.closeWithMode(false, coderws.StatusNormalClosure, "")
}

// CloseGracefully performs a real close handshake on an adapter that owns a
// reader pump.  sync.Once makes graceful and immediate closes race-safe: the
// first terminal operation wins and all concurrent callers observe its result.
// The immediate Close method remains the pool eviction primitive because an
// upstream socket may already be dead and must not hold an eviction path for a
// full close-handshake timeout.
func (c *coderOpenAIWSClientConn) CloseGracefully(status coderws.StatusCode, reason string) error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.closeWithMode(true, status, reason)
}

func (c *coderOpenAIWSClientConn) closeWithMode(graceful bool, status coderws.StatusCode, reason string) error {
	if c == nil || c.conn == nil {
		return nil
	}
	// Synchronize initialization of readCancel/readDone with a concurrent
	// first Ping/Read. Starting the pump before Conn.Close is essential: the
	// coder/websocket close handshake needs a Reader to consume the peer's close
	// acknowledgement (and Pong frames while the handshake is in progress).
	c.ensureReadPump()
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		if graceful {
			c.closeErr = c.conn.Close(status, reason)
		} else {
			c.closeErr = c.conn.CloseNow()
		}
		if c.readCancel != nil {
			c.readCancel()
		}
		if c.readDone != nil {
			select {
			case <-c.readDone:
			case <-time.After(2 * time.Second):
			}
		}
	})
	return c.closeErr
}

// e2eeOpenAIWSClientConn seals the loopback WS hop: WriteJSON/WriteFrame seal
