package service

import (
	"os"
	"strings"
)

// SUB2API_PATCH 环境变量开关：所有 Go 侧补丁覆盖均由 env 触发，不新增配置文件字段，
// 便于与上游保持最小 diff（补丁纪律见 docs/PATCHES.md）。
func isSub2apiPatchEnabled() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv("SUB2API_PATCH")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

// sub2apiPatchDisableOpenAIHTTPPassthrough 报告该账号是否必须禁用 HTTP 自动透传。
// SUB2API_PATCH 启用时 OpenAI OAuth 账号强制 WS-only（WS 与 HTTP 互斥），
// Go 侧指纹拟态与身份收敛全部让位 Rust sidecar。
func sub2apiPatchDisableOpenAIHTTPPassthrough(a *Account) bool {
	return isSub2apiPatchEnabled() && a != nil && a.IsOpenAI() && a.IsOpenAIOAuthLike()
}

// sub2apiPatchForceOpenAIWSV2 报告该账号是否必须开启 Responses WebSocket v2。
func sub2apiPatchForceOpenAIWSV2(a *Account) bool {
	return isSub2apiPatchEnabled() && a != nil && a.IsOpenAI() && a.IsOpenAIOAuthLike()
}

// sub2apiPatchForceOpenAIWSModePassthrough 报告该账号 WSv2 ingress 模式是否强制 passthrough。
func sub2apiPatchForceOpenAIWSModePassthrough(a *Account) bool {
	return isSub2apiPatchEnabled() && a != nil && a.IsOpenAI() && a.IsOpenAIOAuthLike()
}
