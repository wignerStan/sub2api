package repository

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/proxyurl"
	"github.com/Wei-Shaw/sub2api/internal/pkg/servertiming"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/imroc/req/v3"
)

// reqClientOptions 定义 req 客户端的构建参数
type reqClientOptions struct {
	ProxyURL       string        // 代理 URL（支持 http/https/socks5）
	Timeout        time.Duration // 请求超时时间
	Impersonate    bool          // 是否模拟 Chrome 浏览器指纹
	ForceHTTP2     bool          // 是否强制使用 HTTP/2
	SidecarEnabled bool
	SidecarBaseURL string
	SidecarToken   string
}

// sharedReqClients 存储按配置参数缓存的 req 客户端实例
//
// 性能优化说明：
// 原实现在每次 OAuth 刷新时都创建新的 req.Client：
// 1. claude_oauth_service.go: 每次刷新创建新客户端
// 2. openai_oauth_service.go: 每次刷新创建新客户端
// 3. gemini_oauth_client.go: 每次刷新创建新客户端
//
// 新实现使用 sync.Map 缓存客户端：
// 1. 相同配置（代理+超时+模拟设置）复用同一客户端
// 2. 复用底层连接池，减少 TLS 握手开销
// 3. LoadOrStore 保证并发安全，避免重复创建
var sharedReqClients sync.Map

// getSharedReqClient 获取共享的 req 客户端实例
// 性能优化：相同配置复用同一客户端，避免重复创建
func getSharedReqClient(opts reqClientOptions) (*req.Client, error) {
	key := buildReqClientKey(opts)
	if cached, ok := sharedReqClients.Load(key); ok {
		if c, ok := cached.(*req.Client); ok {
			return c, nil
		}
	}

	client := req.C().SetTimeout(opts.Timeout)
	if opts.ForceHTTP2 {
		client = client.EnableForceHTTP2()
	}
	if opts.Impersonate {
		client = client.ImpersonateChrome()
	}
	trimmed, _, err := proxyurl.Parse(opts.ProxyURL)
	if err != nil {
		return nil, err
	}
	if trimmed != "" {
		client.SetProxyURL(trimmed)
	}
	client = instrumentReqClient(client)
	if opts.SidecarEnabled {
		sidecarCfg := &config.Config{}
		sidecarCfg.Gateway.Sidecar.Enabled = true
		sidecarCfg.Gateway.Sidecar.BaseURL = opts.SidecarBaseURL
		sidecarCfg.Gateway.Sidecar.Token = opts.SidecarToken
		proxyForSidecar := trimmed
		client.GetTransport().WrapRoundTripFunc(func(rt http.RoundTripper) req.HttpRoundTripFunc {
			wrapped := service.NewSidecarAwareRoundTripper(sidecarCfg, rt, proxyForSidecar)
			return wrapped.RoundTrip
		})
	}

	actual, _ := sharedReqClients.LoadOrStore(key, client)
	if c, ok := actual.(*req.Client); ok {
		return c, nil
	}
	return client, nil
}

func instrumentReqClient(client *req.Client) *req.Client {
	if client == nil {
		return nil
	}
	client.GetTransport().WrapRoundTripFunc(func(rt http.RoundTripper) req.HttpRoundTripFunc {
		timed := servertiming.WrapRoundTripper(rt)
		return timed.RoundTrip
	})
	return client
}

func buildReqClientKey(opts reqClientOptions) string {
	return fmt.Sprintf("%s|%s|%t|%t|%t|%s|%s",
		strings.TrimSpace(opts.ProxyURL),
		opts.Timeout.String(),
		opts.Impersonate,
		opts.ForceHTTP2,
		opts.SidecarEnabled,
		strings.TrimSpace(opts.SidecarBaseURL),
		strings.TrimSpace(opts.SidecarToken),
	)
}

func sidecarOptsFromConfig(cfg *config.Config) reqClientOptions {
	if !service.SidecarTLSEnabled(cfg) {
		return reqClientOptions{}
	}
	return reqClientOptions{
		SidecarEnabled: true,
		SidecarBaseURL: cfg.Gateway.Sidecar.BaseURL,
		SidecarToken:   cfg.Gateway.Sidecar.Token,
	}
}

// CreatePrivacyReqClient creates an HTTP client for OpenAI privacy settings API
// This is exported for use by OpenAIPrivacyService
func CreatePrivacyReqClient(proxyURL string) (*req.Client, error) {
	return CreatePrivacyReqClientWithConfig(nil, proxyURL)
}

// NewPrivacyReqClientFactory returns a privacy client factory that sends
// official OpenAI OAuth hosts through the rustls sidecar when enabled.
func NewPrivacyReqClientFactory(cfg *config.Config) service.PrivacyClientFactory {
	return func(proxyURL string) (*req.Client, error) {
		return CreatePrivacyReqClientWithConfig(cfg, proxyURL)
	}
}

func CreatePrivacyReqClientWithConfig(cfg *config.Config, proxyURL string) (*req.Client, error) {
	opts := reqClientOptions{
		ProxyURL:    proxyURL,
		Timeout:     30 * time.Second,
		Impersonate: true, // unmatched hosts (tests / CF-only fallbacks) keep Chrome impersonation
	}
	sidecar := sidecarOptsFromConfig(cfg)
	opts.SidecarEnabled = sidecar.SidecarEnabled
	opts.SidecarBaseURL = sidecar.SidecarBaseURL
	opts.SidecarToken = sidecar.SidecarToken
	return getSharedReqClient(opts)
}
