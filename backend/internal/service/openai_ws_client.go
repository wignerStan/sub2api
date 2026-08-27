package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
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

// openAIWSIdlePingCapable is intentionally separate from openAIWSClientConn.
// A pool probe happens while no goroutine is reading an idle connection, which
// is not safe for every WebSocket implementation.
type openAIWSIdlePingCapable interface {
	SupportsIdlePingWithoutReader() bool
}

// openAIWSClientDialer 抽象 WS 建连器。
type openAIWSClientDialer interface {
	Dial(ctx context.Context, wsURL string, headers http.Header, proxyURL string) (openAIWSClientConn, int, http.Header, error)
}

type openAIWSTransportMetricsDialer interface {
	SnapshotTransportMetrics() OpenAIWSTransportMetricsSnapshot
}

func newDefaultOpenAIWSClientDialer() openAIWSClientDialer {
	return &coderOpenAIWSClientDialer{
		proxyClients: make(map[string]*openAIWSProxyClientEntry),
	}
}

// newOpenAIWSClientDialer 依据配置选择 WS 建连器：
// sidecar 启用时，仅 chatgpt.com /backend-api/codex/* 握手改道
// 本地 /v1/ws；其它 WS 仍用默认 coder 实现。
func newOpenAIWSClientDialer(cfg *config.Config) openAIWSClientDialer {
	settings := ResolveSidecarSettings(cfg)
	if settings.Enabled {
		if base, err := url.Parse(settings.BaseURL); err == nil && base.Host != "" && settings.Token != "" {
			return &sidecarOpenAIWSClientDialer{
				cfg:      cfg,
				settings: settings,
				fallback: newDefaultOpenAIWSClientDialer(),
			}
		}
	}
	return newDefaultOpenAIWSClientDialer()
}

// sidecarOpenAIWSClientDialer 将 Codex /backend-api/codex WS 握手改道本地 sidecar /v1/ws。
type sidecarOpenAIWSClientDialer struct {
	cfg      *config.Config
	settings SidecarSettings
	fallback openAIWSClientDialer
}

func (d *sidecarOpenAIWSClientDialer) Dial(
	ctx context.Context,
	wsURL string,
	headers http.Header,
	proxyURL string,
) (openAIWSClientConn, int, http.Header, error) {
	if d == nil {
		return nil, 0, nil, errors.New("sidecar ws dialer is nil")
	}
	if !ShouldUseSidecarTLSURL(wsURL) {
		if d.fallback == nil {
			return nil, 0, nil, errors.New("sidecar ws fallback dialer is nil")
		}
		return d.fallback.Dial(ctx, wsURL, headers, proxyURL)
	}
	sidecarBase, err := url.Parse(d.settings.BaseURL)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("invalid sidecar base_url: %w", err)
	}
	sidecarBase.Path = strings.TrimRight(sidecarBase.Path, "/") + "/v1/ws"

	header := cloneHeader(headers)
	if header == nil {
		header = make(http.Header)
	}
	opts := &coderws.DialOptions{
		HTTPHeader:      header,
		CompressionMode: coderws.CompressionContextTakeover,
	}
	opts.HTTPHeader.Set("x-s2s-token", d.settings.Token)
	opts.HTTPHeader.Set("x-upstream-url", strings.TrimSpace(wsURL))
	if d.settings.Token != "" {
		opts.HTTPHeader.Set(SidecarE2EEHeader, "1")
	}
	encodedProxy, err := EncodeSidecarUpstreamProxy(proxyURL)
	if err != nil {
		return nil, 0, nil, err
	}
	if encodedProxy != "" {
		opts.HTTPHeader.Set("x-upstream-proxy", encodedProxy)
	}

	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       5 * time.Minute,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 0,
	}
	opts.HTTPClient = &http.Client{Transport: transport}

	conn, resp, err := coderws.Dial(ctx, sidecarBase.String(), opts)
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
	conn.SetReadLimit(openAIWSMessageReadLimitBytes)
	respHeaders := http.Header(nil)
	if resp != nil {
		respHeaders = cloneHeader(resp.Header)
	}
	connWrapper := openAIWSClientConn(&coderOpenAIWSClientConn{conn: conn})
	// E2EE the loopback WS hop when the sidecar negotiated it.
	if resp != nil && resp.Header.Get(SidecarE2EEHeader) == "1" {
		if key, keyErr := DeriveSidecarLoopbackKey(d.settings.Token); keyErr == nil {
			connWrapper = &e2eeOpenAIWSClientConn{
				inner: &coderOpenAIWSClientConn{conn: conn},
				key:   key,
			}
		}
	}
	return connWrapper, 0, respHeaders, nil
}

func (d *sidecarOpenAIWSClientDialer) SnapshotTransportMetrics() OpenAIWSTransportMetricsSnapshot {
	if d != nil && d.fallback != nil {
		if m, ok := d.fallback.(openAIWSTransportMetricsDialer); ok {
			return m.SnapshotTransportMetrics()
		}
	}
	return OpenAIWSTransportMetricsSnapshot{}
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

	opts := &coderws.DialOptions{
		HTTPHeader:      cloneHeader(headers),
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
	return &coderOpenAIWSClientConn{conn: conn}, 0, respHeaders, nil
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
	if ctx == nil {
		ctx = context.Background()
	}

	msgType, payload, err := c.conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	switch msgType {
	case coderws.MessageText, coderws.MessageBinary:
		return payload, nil
	default:
		return nil, errOpenAIWSConnClosed
	}
}

func (c *coderOpenAIWSClientConn) ReadFrame(ctx context.Context) (coderws.MessageType, []byte, error) {
	if c == nil || c.conn == nil {
		return coderws.MessageText, nil, errOpenAIWSConnClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	msgType, payload, err := c.conn.Read(ctx)
	if err != nil {
		return coderws.MessageText, nil, err
	}
	return msgType, payload, nil
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
	if ctx == nil {
		ctx = context.Background()
	}
	return c.conn.Ping(ctx)
}

// SupportsIdlePingWithoutReader reports the actual coder/websocket contract.
// Conn.Ping waits for a pong, while control frames are only consumed by Read.
// The pool deliberately has no reader on an idle connection, so using Ping as
// a health probe would deterministically time out a healthy socket.
func (*coderOpenAIWSClientConn) SupportsIdlePingWithoutReader() bool {
	return false
}

func (c *coderOpenAIWSClientConn) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	// Close 为幂等，忽略重复关闭错误。
	_ = c.conn.Close(coderws.StatusNormalClosure, "")
	_ = c.conn.CloseNow()
	return nil
}

// e2eeOpenAIWSClientConn seals the loopback WS hop: WriteJSON/WriteFrame seal
// outgoing payloads, ReadMessage/ReadFrame open incoming ones. Ping/Close and
// idle-ping semantics pass through to the inner coder connection.
type e2eeOpenAIWSClientConn struct {
	inner openAIWSClientConn
	key   [32]byte
}

var (
	_ openAIWSClientConn = (*e2eeOpenAIWSClientConn)(nil)
	_ openaiwsv2.FrameConn = (*e2eeOpenAIWSClientConn)(nil)
)

func (c *e2eeOpenAIWSClientConn) WriteJSON(ctx context.Context, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	sealed, err := SealSidecarChunk(c.key, raw)
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if fc, ok := c.inner.(openaiwsv2.FrameConn); ok {
		return fc.WriteFrame(ctx, coderws.MessageBinary, sealed)
	}
	return errors.New("underlying connection does not implement FrameConn")
}

func (c *e2eeOpenAIWSClientConn) ReadMessage(ctx context.Context) ([]byte, error) {
	_, payload, err := c.ReadFrame(ctx)
	return payload, err
}

func (c *e2eeOpenAIWSClientConn) ReadFrame(ctx context.Context) (coderws.MessageType, []byte, error) {
	fc, ok := c.inner.(openaiwsv2.FrameConn)
	if !ok {
		return coderws.MessageText, nil, errors.New("underlying connection does not implement FrameConn")
	}
	msgType, payload, err := fc.ReadFrame(ctx)
	if err != nil {
		return msgType, nil, err
	}
	if msgType != coderws.MessageBinary {
		return msgType, payload, nil
	}
	plain, err := OpenSidecarChunk(c.key, payload)
	if err != nil {
		return msgType, nil, err
	}
	return coderws.MessageText, plain, nil
}

func (c *e2eeOpenAIWSClientConn) WriteFrame(ctx context.Context, msgType coderws.MessageType, payload []byte) error {
	if msgType == coderws.MessageText || msgType == coderws.MessageBinary {
		sealed, err := SealSidecarChunk(c.key, payload)
		if err != nil {
			return err
		}
		msgType = coderws.MessageBinary
		payload = sealed
	}
	if fc, ok := c.inner.(openaiwsv2.FrameConn); ok {
		return fc.WriteFrame(ctx, msgType, payload)
	}
	return errors.New("underlying connection does not implement FrameConn")
}

func (c *e2eeOpenAIWSClientConn) Ping(ctx context.Context) error {
	return c.inner.Ping(ctx)
}

func (*e2eeOpenAIWSClientConn) SupportsIdlePingWithoutReader() bool { return false }

func (c *e2eeOpenAIWSClientConn) Close() error { return c.inner.Close() }
