package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	coderws "github.com/coder/websocket"
	"github.com/stretchr/testify/require"
)

type recordingOpenAIWSDialer struct {
	urls []string
}

func (d *recordingOpenAIWSDialer) Dial(
	_ context.Context,
	wsURL string,
	_ http.Header,
	_ string,
) (openAIWSClientConn, int, http.Header, error) {
	d.urls = append(d.urls, wsURL)
	return nil, 0, nil, errors.New("fallback used")
}

func TestSidecarOpenAIWSClientDialerFallsBackOutsideCodex(t *testing.T) {
	fallback := &recordingOpenAIWSDialer{}
	settings := SidecarSettings{
		Enabled: true,
		BaseURL: "http://127.0.0.1:9",
		Token:   "tok",
	}
	dialer := &sidecarOpenAIWSClientDialer{cfg: &config.Config{}, settings: settings, fallback: fallback}

	_, _, _, err := dialer.Dial(context.Background(), "wss://api.openai.com/v1/responses", http.Header{}, "")
	require.EqualError(t, err, "fallback used")
	require.Equal(t, []string{"wss://api.openai.com/v1/responses"}, fallback.urls)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, _, err = dialer.Dial(ctx, "wss://chatgpt.com/backend-api/codex/call_proxy", http.Header{}, "")
	require.Error(t, err)
	require.NotEqual(t, "fallback used", err.Error())
	require.Equal(t, []string{"wss://api.openai.com/v1/responses"}, fallback.urls)
}

func TestSidecarOpenAIWSClientDialerTrustedAccountSelector(t *testing.T) {
	seen := make(chan [2]string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- [2]string{
			r.Header.Get(SidecarAccountIDHeader),
			r.Header.Get("x-account-id"),
		}
		http.Error(w, "expected handshake failure", http.StatusBadRequest)
	}))
	defer server.Close()

	dialer := &sidecarOpenAIWSClientDialer{
		cfg: &config.Config{},
		settings: SidecarSettings{
			Enabled: true,
			BaseURL: server.URL,
			Token:   "tok",
		},
		fallback: &recordingOpenAIWSDialer{},
	}
	headers := http.Header{}
	headers.Set(SidecarAccountIDHeader, "999")
	headers.Set("x-account-id", "998")
	_, _, _, err := dialer.DialForAccount(
		context.Background(),
		"wss://chatgpt.com/backend-api/codex/call_proxy",
		headers,
		"",
		42,
	)
	require.Error(t, err)
	require.Equal(t, [2]string{"42", ""}, <-seen)
}

func TestStripSidecarControlHeaders(t *testing.T) {
	headers := http.Header{
		"Authorization":         {"Bearer keep"},
		"X-Account-Id":          {"1"},
		"X-Upstream-Account-Id": {"2"},
		"X-Upstream-Url":        {"https://example.invalid"},
		"X-Upstream-Proxy":      {"proxy"},
		"X-S2s-Token":           {"token"},
		"X-S2s-Enc":             {"1"},
		"X-S2s-Enc-Len":         {"10"},
	}
	stripSidecarControlHeaders(headers)
	require.Equal(t, "Bearer keep", headers.Get("Authorization"))
	for _, name := range []string{
		"x-account-id",
		SidecarAccountIDHeader,
		"x-upstream-url",
		"x-upstream-proxy",
		"x-s2s-token",
		SidecarE2EEHeader,
		SidecarE2EEOrigLenHeader,
	} {
		require.Empty(t, headers.Get(name), name)
	}
}

func TestSidecarOpenAIWSClientDialerRejectsInvalidProxy(t *testing.T) {
	fallback := &recordingOpenAIWSDialer{}
	settings := SidecarSettings{
		Enabled: true,
		BaseURL: "http://127.0.0.1:9",
		Token:   "tok",
	}
	dialer := &sidecarOpenAIWSClientDialer{cfg: &config.Config{}, settings: settings, fallback: fallback}

	_, _, _, err := dialer.Dial(
		context.Background(),
		"wss://chatgpt.com/backend-api/codex/call_proxy",
		http.Header{},
		"ftp://127.0.0.1:21",
	)
	require.Error(t, err)
	require.Empty(t, fallback.urls)
}

func TestCoderOpenAIWSClientDialer_ProxyHTTPClientReuse(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	c1, err := impl.proxyHTTPClient("http://127.0.0.1:8080")
	require.NoError(t, err)
	c2, err := impl.proxyHTTPClient("http://127.0.0.1:8080")
	require.NoError(t, err)
	require.Same(t, c1, c2, "同一代理地址应复用同一个 HTTP 客户端")

	c3, err := impl.proxyHTTPClient("http://127.0.0.1:8081")
	require.NoError(t, err)
	require.NotSame(t, c1, c3, "不同代理地址应分离客户端")
}

func TestCoderOpenAIWSClientDialer_ProxyHTTPClientInvalidURL(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	_, err := impl.proxyHTTPClient("://bad")
	require.Error(t, err)
}

func TestCoderOpenAIWSClientDialer_TransportMetricsSnapshot(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	_, err := impl.proxyHTTPClient("http://127.0.0.1:18080")
	require.NoError(t, err)
	_, err = impl.proxyHTTPClient("http://127.0.0.1:18080")
	require.NoError(t, err)
	_, err = impl.proxyHTTPClient("http://127.0.0.1:18081")
	require.NoError(t, err)

	snapshot := impl.SnapshotTransportMetrics()
	require.Equal(t, int64(1), snapshot.ProxyClientCacheHits)
	require.Equal(t, int64(2), snapshot.ProxyClientCacheMisses)
	require.InDelta(t, 1.0/3.0, snapshot.TransportReuseRatio, 0.0001)
}

func TestCoderOpenAIWSClientDialer_ProxyClientCacheCapacity(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	total := openAIWSProxyClientCacheMaxEntries + 32
	for i := 0; i < total; i++ {
		_, err := impl.proxyHTTPClient(fmt.Sprintf("http://127.0.0.1:%d", 20000+i))
		require.NoError(t, err)
	}

	impl.proxyMu.Lock()
	cacheSize := len(impl.proxyClients)
	impl.proxyMu.Unlock()

	require.LessOrEqual(t, cacheSize, openAIWSProxyClientCacheMaxEntries, "代理客户端缓存应受容量上限约束")
}

func TestCoderOpenAIWSClientDialer_ProxyClientCacheIdleTTL(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	oldProxy := "http://127.0.0.1:28080"
	_, err := impl.proxyHTTPClient(oldProxy)
	require.NoError(t, err)

	impl.proxyMu.Lock()
	oldEntry := impl.proxyClients[oldProxy]
	require.NotNil(t, oldEntry)
	oldEntry.lastUsedUnixNano = time.Now().Add(-openAIWSProxyClientCacheIdleTTL - time.Minute).UnixNano()
	impl.proxyMu.Unlock()

	// 触发一次新的代理获取，驱动 TTL 清理。
	_, err = impl.proxyHTTPClient("http://127.0.0.1:28081")
	require.NoError(t, err)

	impl.proxyMu.Lock()
	_, exists := impl.proxyClients[oldProxy]
	impl.proxyMu.Unlock()

	require.False(t, exists, "超过空闲 TTL 的代理客户端应被回收")
}

func TestCoderOpenAIWSClientDialer_ProxyTransportTLSHandshakeTimeout(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	client, err := impl.proxyHTTPClient("http://127.0.0.1:38080")
	require.NoError(t, err)
	require.NotNil(t, client)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport)
	require.Equal(t, 10*time.Second, transport.TLSHandshakeTimeout)
}

func TestCoderOpenAIWSClientConn_NilDoesNotSupportIdlePingWithoutReader(t *testing.T) {
	require.False(t, (&coderOpenAIWSClientConn{}).SupportsIdlePingWithoutReader())
}

func TestCoderOpenAIWSClientConn_PingStartsReaderPumpAndQueuesData(t *testing.T) {
	serverReady := make(chan struct{})
	serverDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := coderws.Accept(w, r, nil)
		if err != nil {
			close(serverDone)
			return
		}
		defer func() {
			_ = conn.CloseNow()
			close(serverDone)
		}()
		close(serverReady)
		// Keep a real Reader active so coder/websocket can consume the ping and
		// produce its pong.  The data frame is written while the client adapter
		// is still between turns; it must be available to the next ReadMessage.
		readDone := make(chan struct{})
		go func() {
			defer close(readDone)
			for {
				if _, _, readErr := conn.Read(context.Background()); readErr != nil {
					return
				}
			}
		}()
		time.Sleep(20 * time.Millisecond)
		writeCtx, cancelWrite := context.WithTimeout(context.Background(), time.Second)
		_ = conn.Write(writeCtx, coderws.MessageText, []byte(`{"type":"response.completed"}`))
		cancelWrite()
		<-readDone
	}))
	defer server.Close()

	dialCtx, cancelDial := context.WithTimeout(context.Background(), time.Second)
	client, _, err := coderws.Dial(dialCtx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	cancelDial()
	require.NoError(t, err)
	adapter := &coderOpenAIWSClientConn{conn: client}
	<-serverReady

	pingCtx, cancelPing := context.WithTimeout(context.Background(), time.Second)
	require.NoError(t, adapter.Ping(pingCtx))
	cancelPing()

	readCtx, cancelRead := context.WithTimeout(context.Background(), time.Second)
	payload, err := adapter.ReadMessage(readCtx)
	cancelRead()
	require.NoError(t, err)
	require.JSONEq(t, `{"type":"response.completed"}`, string(payload))
	require.True(t, adapter.SupportsIdlePingWithoutReader())
	require.NoError(t, adapter.Close())

	require.Eventually(t, func() bool {
		select {
		case <-serverDone:
			return true
		default:
			return false
		}
	}, time.Second, 5*time.Millisecond)
}

func TestCoderOpenAIWSClientConn_ReadPumpDoesNotStarvePongBehindBurst(t *testing.T) {
	serverReady := make(chan struct{})
	serverDone := make(chan struct{})
	serverHold := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := coderws.Accept(w, r, nil)
		if err != nil {
			close(serverDone)
			return
		}
		defer func() {
			_ = conn.CloseNow()
			close(serverDone)
		}()
		close(serverReady)
		// Keep the server reader active so the client's protocol Ping receives a
		// Pong.  Send more frames than the old bounded pump queue could hold
		// before the client starts consuming; the reader must continue draining
		// control frames instead of blocking on data delivery.
		go func() {
			for {
				if _, _, readErr := conn.Read(context.Background()); readErr != nil {
					return
				}
			}
		}()
		for i := 0; i < 128; i++ {
			writeCtx, cancelWrite := context.WithTimeout(context.Background(), time.Second)
			if writeErr := conn.Write(writeCtx, coderws.MessageText, []byte(`{"type":"response.output_text.delta","index":0}`)); writeErr != nil {
				cancelWrite()
				return
			}
			cancelWrite()
		}
		<-serverHold
	}))
	defer server.Close()

	dialCtx, cancelDial := context.WithTimeout(context.Background(), time.Second)
	client, _, err := coderws.Dial(dialCtx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	cancelDial()
	require.NoError(t, err)
	adapter := &coderOpenAIWSClientConn{conn: client}
	defer adapter.Close()
	<-serverReady

	// Give the server enough time to queue the burst in the transport before
	// probing.  The exact sleep is deliberately below the test timeout.
	time.Sleep(30 * time.Millisecond)
	pingCtx, cancelPing := context.WithTimeout(context.Background(), time.Second)
	require.NoError(t, adapter.Ping(pingCtx))
	cancelPing()
	readCtx, cancelRead := context.WithTimeout(context.Background(), time.Second)
	_, err = adapter.ReadMessage(readCtx)
	cancelRead()
	require.NoError(t, err)
	close(serverHold)
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("burst read-pump server did not terminate")
	}
}

func TestCoderOpenAIWSClientConn_GracefulCloseWithActiveReaderPump(t *testing.T) {
	serverDone := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := coderws.Accept(w, r, nil)
		if err != nil {
			serverDone <- err
			return
		}
		defer func() { _ = conn.CloseNow() }()
		// Keep a reader active so the peer can consume the close handshake.
		for {
			_, _, readErr := conn.Read(context.Background())
			if readErr != nil {
				serverDone <- readErr
				return
			}
		}
	}))
	defer server.Close()

	client, _, err := coderws.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	require.NoError(t, err)
	adapter := &coderOpenAIWSClientConn{conn: client}
	require.True(t, adapter.ensureReadPump())

	closeErr := adapter.CloseGracefully(coderws.StatusNormalClosure, "done")
	// coder/websocket may report the peer's close frame to the concurrently
	// running pump while Close waits for its handshake; the wire close is still
	// valid, so both nil and net.ErrClosed-style wrappers are acceptable here.
	_ = closeErr
	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not observe graceful close")
	}
}
