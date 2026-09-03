package service

// PATCH hook: 默认 WS 建连器按 sidecar 配置选择。sidecar 启用时 Codex WS
// 握手改道本地 rustls sidecar（其 upstream WS 连接池按 thread scope 复用）；
// 未启用时保持上游原生 coder 拨号路径不变。逻辑在 openai_ws_client_sidecar.go
// （newOpenAIWSClientDialer），此处只保留 1–3 行的补丁点。

// openAIWSDefaultDialer returns the dialer for pool/passthrough dial sites:
// sidecar-aware when the sidecar runtime is configured, native otherwise.
func openAIWSDefaultDialer() openAIWSClientDialer {
	if cfg := sidecarRuntime(); cfg != nil {
		return newOpenAIWSClientDialer(cfg)
	}
	return newDefaultOpenAIWSClientDialer()
}
