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
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	openaiwsv2 "github.com/Wei-Shaw/sub2api/internal/service/openai_ws_v2"
	coderws "github.com/coder/websocket"
)

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

func stripSidecarControlHeaders(headers http.Header) {
	if headers == nil {
		return
	}
	for _, name := range []string{
		"x-account-id",
		SidecarAccountIDHeader,
		"x-upstream-url",
		"x-upstream-proxy",
		"x-s2s-token",
		SidecarE2EEHeader,
		SidecarE2EEOrigLenHeader,
	} {
		headers.Del(name)
	}
}

func (d *sidecarOpenAIWSClientDialer) Dial(
	ctx context.Context,
	wsURL string,
	headers http.Header,
	proxyURL string,
) (openAIWSClientConn, int, http.Header, error) {
	return d.dial(ctx, wsURL, headers, proxyURL, 0)
}

func (d *sidecarOpenAIWSClientDialer) DialForAccount(
	ctx context.Context,
	wsURL string,
	headers http.Header,
	proxyURL string,
	accountID int64,
) (openAIWSClientConn, int, http.Header, error) {
	return d.dial(ctx, wsURL, headers, proxyURL, accountID)
}

func (d *sidecarOpenAIWSClientDialer) dial(
	ctx context.Context,
	wsURL string,
	headers http.Header,
	proxyURL string,
	accountID int64,
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
	stripSidecarControlHeaders(header)
	if accountID > 0 {
		header.Set(SidecarAccountIDHeader, strconv.FormatInt(accountID, 10))
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
	innerConn := &coderOpenAIWSClientConn{conn: conn}
	// Start the reader before publishing the socket to the pool.  Prewarmed
	// connections can sit idle for minutes; without a reader they cannot answer
	// an unsolicited server Ping even though later health probes would install
	// one just in time.
	innerConn.ensureReadPump()
	connWrapper := openAIWSClientConn(innerConn)
	// E2EE the loopback WS hop when the sidecar negotiated it.
	if resp != nil && resp.Header.Get(SidecarE2EEHeader) == "1" {
		if key, keyErr := DeriveSidecarLoopbackKey(d.settings.Token); keyErr == nil {
			connWrapper = &e2eeOpenAIWSClientConn{
				inner: innerConn,
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

// outgoing payloads, ReadMessage/ReadFrame open incoming ones. Ping/Close and
// idle-ping semantics pass through to the inner coder connection.
type e2eeOpenAIWSClientConn struct {
	inner openAIWSClientConn
	key   [32]byte
}

var (
	_ openAIWSClientConn   = (*e2eeOpenAIWSClientConn)(nil)
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

func (c *e2eeOpenAIWSClientConn) SupportsPing() bool {
	if c == nil || c.inner == nil {
		return false
	}
	capability, ok := c.inner.(interface{ SupportsPing() bool })
	if ok {
		return capability.SupportsPing()
	}
	_, ok = c.inner.(interface{ Ping(context.Context) error })
	return ok
}

func (c *e2eeOpenAIWSClientConn) ReadTimeoutClosesConnection() bool {
	if c == nil || c.inner == nil {
		return false
	}
	terminal, ok := c.inner.(openAIWSReadTimeoutTerminal)
	return ok && terminal.ReadTimeoutClosesConnection()
}

func (c *e2eeOpenAIWSClientConn) SupportsIdlePingWithoutReader() bool {
	if c == nil || c.inner == nil {
		return false
	}
	capable, ok := c.inner.(openAIWSIdlePingCapable)
	if !ok {
		return false
	}
	return capable.SupportsIdlePingWithoutReader()
}

func (c *e2eeOpenAIWSClientConn) Close() error { return c.inner.Close() }

func (c *e2eeOpenAIWSClientConn) CloseGracefully(status coderws.StatusCode, reason string) error {
	if c == nil || c.inner == nil {
		return nil
	}
	if graceful, ok := c.inner.(openAIWSGracefulCloser); ok {
		return graceful.CloseGracefully(status, reason)
	}
	return c.inner.Close()
}
