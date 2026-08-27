package service

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// codexFingerprintIDsContextKey 是暂存在 gin context 的收敛 ID 集合键。
// 由 Forward（非透传）或 forwardOpenAIPassthrough（透传）解析后写入，请求
// 构造器读取用于出站头改写——请求体与出站头必须共享同一份 IDs，保证
// turn_id 等随机字段一致。
const codexFingerprintIDsContextKey = "codex_fingerprint_ids"

// stageCodexFingerprintIDs 将本 attempt 解析出的收敛 ID 暂存到 gin context。
// 必须无条件覆写（含 nil）：failover 从收敛账号切到 off 账号时，上一账号的
// IDs 不得残留并被误应用到新账号的出站头（typed-nil 由应用侧 nil 守卫吸收）。
func stageCodexFingerprintIDs(c *gin.Context, ids *codexFingerprintIDs) {
	if c != nil {
		c.Set(codexFingerprintIDsContextKey, ids)
	}
}

func stagedCodexFingerprintIDs(c *gin.Context, account *Account) *codexFingerprintIDs {
	if c == nil || account == nil || !account.UsesOpenAICodexProtocol() {
		return nil
	}
	value, ok := c.Get(codexFingerprintIDsContextKey)
	if !ok {
		return nil
	}
	ids, ok := value.(*codexFingerprintIDs)
	if !ok || ids == nil || ids.accountID != account.ID {
		return nil
	}
	return ids
}

// applyStagedCodexFingerprintHeaders 读取 context 暂存的收敛 ID 并改写出站头。
// 非透传与透传两个请求构造器共用本函数，防止应用语义漂移。仅解析该
// snapshot 的 OAuth 账号可读取，避免 stale context 跨账号 failover 泄漏。
func applyStagedCodexFingerprintHeaders(c *gin.Context, account *Account, h http.Header) {
	applyCodexFingerprintHeaders(h, stagedCodexFingerprintIDs(c, account))
}

// ensureStagedCodexFingerprintIDs 返回本 attempt 已暂存的收敛 ID。
// WS passthrough 不走 HTTP Forward 的解析 seam，未暂存时在此补解析，
// 避免出站 session/installation 仍是客户端值。
func ensureStagedCodexFingerprintIDs(c *gin.Context, account *Account) *codexFingerprintIDs {
	if ids := stagedCodexFingerprintIDs(c, account); ids != nil {
		return ids
	}
	var clientHeaders http.Header
	if c != nil && c.Request != nil {
		clientHeaders = c.Request.Header
	}
	ids := resolveCodexFingerprintIDsFromRequest(account, clientHeaders)
	stageCodexFingerprintIDs(c, ids)
	return ids
}

func applyStagedCodexFingerprintClientMetadata(c *gin.Context, account *Account, reqBody map[string]any) bool {
	return applyCodexFingerprintClientMetadata(reqBody, stagedCodexFingerprintIDs(c, account))
}

// applyStagedCodexFingerprintClientMetadataRaw 按暂存（未暂存则现场解析）的
// 收敛 ID 改写原始 JSON 帧/体中的 client_metadata。WS passthrough 不走 HTTP
// Forward 的解析 seam，必须 ensure 后再改写，否则帧体仍是客户端原值。
func applyStagedCodexFingerprintClientMetadataRaw(c *gin.Context, account *Account, body []byte) ([]byte, error) {
	if len(body) == 0 || account == nil || !account.IsOpenAIOAuth() {
		return body, nil
	}
	next, _, err := applyCodexFingerprintClientMetadataRaw(body, ensureStagedCodexFingerprintIDs(c, account))
	if err != nil {
		return nil, err
	}
	return next, nil
}

// applyStagedCodexFingerprintClientMetadataRawForFollowup rewrites a later WS
// frame with the connection's stable installation/session/thread IDs while
// giving each response.create its own turn identity. The first frame must use
// applyStagedCodexFingerprintClientMetadataRaw so its body and handshake
// compatibility headers share exactly the same turn fields.
func applyStagedCodexFingerprintClientMetadataRawForFollowup(
	c *gin.Context,
	account *Account,
	body []byte,
	newTurn bool,
) ([]byte, error) {
	if len(body) == 0 || account == nil || !account.IsOpenAIOAuth() {
		return body, nil
	}
	base := ensureStagedCodexFingerprintIDs(c, account)
	if base == nil {
		return body, nil
	}
	ids := *base
	// Body-session capture is frame-local. Reusing the first frame's value can
	// otherwise rewrite an unrelated prompt_cache_key on a later WS frame.
	ids.originalBodySessionID = ""
	ids.originalBodySessionIDCaptured = false
	if newTurn && (ids.mode == codexFingerprintSession || ids.mode == codexFingerprintFull) {
		ids.turnID = uuid.Must(uuid.NewV7()).String()
		ids.turnStartedAtUnixMs = time.Now().UnixMilli()
	}
	next, _, err := applyCodexFingerprintClientMetadataRaw(body, &ids)
	if err != nil {
		return nil, err
	}
	return next, nil
}

// validateNoDuplicateTopLevelJSONKeys rejects ambiguous JSON objects before a
// raw passthrough path evaluates or rewrites them. Different JSON consumers
// disagree on whether the first or last duplicate wins; allowing duplicates
// would let a sanitized client_metadata (or policy field) coexist with a
// second value that the upstream might interpret instead.
func validateNoDuplicateTopLevelJSONKeys(body []byte) error {
	i := 0
	for i < len(body) && isJSONWhitespace(body[i]) {
		i++
	}
	if i >= len(body) || body[i] != '{' {
		return nil
	}

	seen := make(map[string]struct{})
	depth := 0
	expectRootKey := false
	for i < len(body) {
		switch body[i] {
		case '{', '[':
			depth++
			if depth == 1 {
				expectRootKey = true
			}
			i++
		case '}', ']':
			depth--
			if depth < 0 {
				return fmt.Errorf("invalid JSON nesting")
			}
			i++
			if depth == 0 {
				return nil
			}
		case ',':
			if depth == 1 {
				expectRootKey = true
			}
			i++
		case '"':
			start := i
			i++
			for i < len(body) {
				if body[i] == '\\' {
					i += 2
					continue
				}
				if body[i] == '"' {
					i++
					break
				}
				i++
			}
			if i > len(body) || i == len(body) && body[i-1] != '"' {
				return fmt.Errorf("unterminated JSON string")
			}
			if depth == 1 && expectRootKey {
				var key string
				if err := json.Unmarshal(body[start:i], &key); err != nil {
					return fmt.Errorf("decode top-level JSON key: %w", err)
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate top-level JSON key %q", key)
				}
				seen[key] = struct{}{}
				expectRootKey = false
			}
		default:
			i++
		}
	}
	return fmt.Errorf("unterminated JSON object")
}

func isJSONWhitespace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}

// codexFingerprintMode 控制 OAuth 账号出站请求的设备指纹收敛强度。
// 多人共享同一 OAuth 账号时，每个用户的 Codex 客户端会携带各自不同的
// installation_id / session_id / thread_id，上游据此判定设备数和会话数。
// 收敛模式将这些标识改写为账号级恒定值，减少上游可见的设备/会话指纹。
type codexFingerprintMode string

const (
	// codexFingerprintOff 是历史透传值。解析与出站一律按 session 处理，
	// 避免缺种子 / 显式 off 把客户端 installation_id 和 session_id 放到上游。
	codexFingerprintOff codexFingerprintMode = "off"
	// codexFingerprintDevice 仅收敛 installation_id 为账号级恒定值。
	// 上游看到 1 台设备 + 多会话（每用户各自的 session）。
	codexFingerprintDevice codexFingerprintMode = "device"
	// codexFingerprintSession 收敛 installation_id + session_id，
	// thread_id 按客户端原始 thread-id 确定性派生；缺失 thread-id 时才回退到 session-id。
	// 上游看到 1 台设备 + 1 会话 + N 线程，并保留 root/subagent 的线程拓扑。
	codexFingerprintSession codexFingerprintMode = "session"
	// codexFingerprintFull 收敛所有标识：installation_id + session_id + thread_id。
	// 上游看到 1 台设备 + 1 会话 + 1 线程，最激进。
	codexFingerprintFull codexFingerprintMode = "full"
)

const (
	codexFingerprintModeExtraKey = "codex_fingerprint_mode"
	codexFingerprintSeedExtraKey = "codex_fingerprint_seed"
)

func canonicalCodexFingerprintSeed(value any) (string, bool) {
	raw, ok := value.(string)
	if !ok {
		return "", false
	}
	trimmed := strings.TrimSpace(raw)
	parsed, err := uuid.Parse(trimmed)
	if err != nil || parsed == uuid.Nil || trimmed != parsed.String() {
		return "", false
	}
	return trimmed, true
}

func newCodexFingerprintSeed() string {
	return uuid.NewString()
}

func stripCodexFingerprintSeed(extra map[string]any) map[string]any {
	if extra == nil {
		return nil
	}
	stripped := maps.Clone(extra)
	delete(stripped, codexFingerprintSeedExtraKey)
	return stripped
}

func defaultCodexFingerprintMode() codexFingerprintMode {
	if patchEnv := strings.TrimSpace(os.Getenv("SUB2API_PATCH_DEFAULT_CODEX_FINGERPRINT")); patchEnv != "" {
		if mode, ok := explicitCodexFingerprintMode(patchEnv); ok {
			return mode
		}
		if patchEnv == "0" || strings.EqualFold(patchEnv, "false") || strings.EqualFold(patchEnv, "off") {
			return codexFingerprintOff
		}
		if patchEnv == "1" || strings.EqualFold(patchEnv, "true") {
			return codexFingerprintSession
		}
	}
	return codexFingerprintSession
}

func explicitCodexFingerprintMode(raw string) (codexFingerprintMode, bool) {
	switch mode := codexFingerprintMode(strings.TrimSpace(raw)); mode {
	case codexFingerprintOff, codexFingerprintDevice, codexFingerprintSession, codexFingerprintFull:
		return mode, true
	default:
		return "", false
	}
}

func codexFingerprintModeFromExtra(extra map[string]any) codexFingerprintMode {
	if extra == nil {
		return defaultCodexFingerprintMode()
	}
	raw, _ := extra[codexFingerprintModeExtraKey].(string)
	if mode, ok := explicitCodexFingerprintMode(raw); ok {
		return mode
	}
	return defaultCodexFingerprintMode()
}

func persistDefaultCodexFingerprintMode(extra map[string]any) (map[string]any, codexFingerprintMode) {
	if extra == nil {
		extra = make(map[string]any, 2)
	}
	raw, _ := extra[codexFingerprintModeExtraKey].(string)
	if mode, ok := explicitCodexFingerprintMode(raw); ok && mode != codexFingerprintOff {
		return extra, mode
	}
	extra[codexFingerprintModeExtraKey] = string(codexFingerprintSession)
	return extra, codexFingerprintSession
}

func effectiveCodexFingerprintMode(mode codexFingerprintMode) codexFingerprintMode {
	switch mode {
	case codexFingerprintDevice, codexFingerprintSession, codexFingerprintFull:
		return mode
	default:
		return codexFingerprintSession
	}
}

func fallbackCodexFingerprintSeed(account *Account) string {
	var accountID int64
	if account != nil {
		accountID = account.ID
	}
	return deriveStableUUIDv4("sub2api:codex-fingerprint-seed:v2:" + strconv.FormatInt(accountID, 10))
}

func resolveCodexFingerprintSeed(account *Account) string {
	if seed, ok := codexFingerprintSeed(accountExtraOrNil(account)); ok {
		return seed
	}
	return fallbackCodexFingerprintSeed(account)
}

func accountExtraOrNil(account *Account) map[string]any {
	if account == nil {
		return nil
	}
	return account.Extra
}

func codexFingerprintModeRequiresSeed(mode codexFingerprintMode) bool {
	switch mode {
	case codexFingerprintDevice, codexFingerprintSession, codexFingerprintFull:
		return true
	default:
		return false
	}
}

func codexFingerprintSeed(extra map[string]any) (string, bool) {
	if extra == nil {
		return "", false
	}
	return canonicalCodexFingerprintSeed(extra[codexFingerprintSeedExtraKey])
}

func prepareCodexFingerprintExtraForCreate(platform, accountType string, extra map[string]any) map[string]any {
	prepared := stripCodexFingerprintSeed(extra)
	// Fork keeps fail-closed convergence (missing/empty/illegal/off -> session)
	// while adopting upstream's setup-token coverage (#5610 follow-up).
	if platform != PlatformOpenAI || (accountType != AccountTypeOAuth && accountType != AccountTypeSetupToken) {
		return prepared
	}
	prepared, mode := persistDefaultCodexFingerprintMode(prepared)
	if codexFingerprintModeRequiresSeed(mode) {
		prepared[codexFingerprintSeedExtraKey] = newCodexFingerprintSeed()
	}
	return prepared
}

func prepareCodexFingerprintExtraForUpdate(account *Account, extra map[string]any) map[string]any {
	prepared := stripCodexFingerprintSeed(extra)
	if account == nil || !account.IsOpenAIOAuthLike() {
		return prepared
	}
	prepared, mode := persistDefaultCodexFingerprintMode(prepared)
	if seed, ok := codexFingerprintSeed(account.Extra); ok {
		prepared[codexFingerprintSeedExtraKey] = seed
		return prepared
	}
	if codexFingerprintModeRequiresSeed(mode) {
		prepared[codexFingerprintSeedExtraKey] = newCodexFingerprintSeed()
	}
	return prepared
}

func sanitizedCodexFingerprintExtraUpdates(updates map[string]any) map[string]any {
	if updates == nil {
		return nil
	}
	sanitized := maps.Clone(updates)
	delete(sanitized, codexFingerprintSeedExtraKey)
	if raw, exists := sanitized[codexFingerprintModeExtraKey]; exists {
		rawMode, _ := raw.(string)
		mode, valid := explicitCodexFingerprintMode(rawMode)
		if !valid || mode == codexFingerprintOff {
			sanitized[codexFingerprintModeExtraKey] = string(codexFingerprintSession)
		}
	}
	return sanitized
}

// ShouldEnsureCodexFingerprintSeedForExtraUpdates reports whether a JSONB key-level
// extra update is enabling Codex fingerprint convergence and therefore must atomically
// preserve or create the system-managed per-account seed in the repository update.
// 只认 extra 里显式写入的 mode；缺省 session 不得把 billing probe 这类局部更新
// 误判成要改写种子。
func ShouldEnsureCodexFingerprintSeedForExtraUpdates(updates map[string]any) bool {
	if updates == nil {
		return false
	}
	raw, _ := updates[codexFingerprintModeExtraKey].(string)
	mode, ok := explicitCodexFingerprintMode(raw)
	if !ok {
		return false
	}
	return codexFingerprintModeRequiresSeed(mode)
}

// GetCodexFingerprintMode 从账号 extra JSON 读取指纹收敛模式。
//
// 缺省 / 空值 / 非法值 / 显式 off 一律按 session（设备+会话）处理。
// 出站不得因历史 off 或缺种子把客户端 installation/session 标识放到上游。
func (a *Account) GetCodexFingerprintMode() codexFingerprintMode {
	if a == nil || !a.IsOpenAIOAuthLike() {
		return codexFingerprintOff
	}
	return effectiveCodexFingerprintMode(codexFingerprintModeFromExtra(a.Extra))
}

func codexFingerprintDeployDomain() string {
	return strings.ToLower(strings.TrimSpace(os.Getenv("CODEX_FINGERPRINT_DEPLOY_DOMAIN")))
}

// deriveStableUUIDv4 从种子确定性派生一个 UUIDv4 格式的字符串。
// 同一种子永远返回同一值。
func deriveStableUUIDv4(seed string) string {
	h := sha256.Sum256([]byte(seed))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 1
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(b[0:4]),
		binary.BigEndian.Uint16(b[4:6]),
		binary.BigEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16])
}

// resolveConvergedInstallationID 返回账号级恒定的 installation_id。
// 从不把 openai_device_id 原文写出站；只从系统种子（加部署域）派生。
func resolveConvergedInstallationID(account *Account, seed string) string {
	if account == nil || seed == "" {
		return ""
	}
	base := "sub2api:codex-install-id:v2:" + seed
	if domain := codexFingerprintDeployDomain(); domain != "" {
		base += ":" + domain
	}
	return deriveStableUUIDv4(base)
}

// resolveConvergedSessionID 返回账号级恒定的 session_id。
func resolveConvergedSessionID(seed string) string {
	if seed == "" {
		return ""
	}
	return deriveStableUUIDv4("sub2api:codex-session-id:v2:" + seed)
}

// resolveConvergedThreadID 按客户端原始 thread-id 确定性派生 thread_id。
// 同一原始 thread 在同一账号种子下稳定映射，不同 root/subagent thread 保持不同。
// 调用方可在缺失 thread-id 时显式传入 session-id 作为兼容回退。
func resolveConvergedThreadID(seed, clientThreadID string) string {
	if seed == "" || clientThreadID == "" {
		return ""
	}
	return deriveStableUUIDv4("sub2api:codex-thread-id:v2:" + seed + ":" + clientThreadID)
}

// codexFingerprintIDs 收敛后的完整 ID 集合。
// 由 resolveCodexFingerprintIDs 一次性生成，同一个实例在头改写和体改写之间共享，
// 确保所有载体中的 turn_id 等随机字段一致。体改写时还会补记原始
// client_metadata.session_id，用于识别 root prompt_cache_key 的默认值。
type codexFingerprintIDs struct {
	accountID                     int64
	mode                          codexFingerprintMode
	seed                          string
	installationID                string
	sessionID                     string
	threadID                      string
	parentThreadID                string
	forkedFromThreadID            string
	turnID                        string
	windowID                      string
	windowNumber                  uint64
	turnStartedAtUnixMs           int64
	originalBodySessionID         string
	originalBodySessionIDCaptured bool
}

// extractClientWindowNumber extracts the client's current auto_compact window_number
// from x-codex-window-id (e.g. "<thread_id>:<window_number>" -> <window_number>).
func extractClientWindowNumber(h http.Header) uint64 {
	if h == nil {
		return 0
	}
	raw := strings.TrimSpace(h.Get("x-codex-window-id"))
	if raw == "" {
		raw = strings.TrimSpace(h.Get("window-id"))
	}
	if raw == "" {
		return 0
	}
	if idx := strings.LastIndex(raw, ":"); idx >= 0 {
		if num, err := strconv.ParseUint(strings.TrimSpace(raw[idx+1:]), 10, 64); err == nil {
			return num
		}
	} else if num, err := strconv.ParseUint(raw, 10, 64); err == nil {
		return num
	}
	return 0
}

// resolveCodexFingerprintIDsWithWindow 按收敛模式和当前窗口编号计算出站 ID 集合。
func resolveCodexFingerprintIDsWithWindow(account *Account, clientSessionID string, windowNumber uint64, mode codexFingerprintMode) *codexFingerprintIDs {
	if account == nil {
		return nil
	}
	mode = effectiveCodexFingerprintMode(mode)
	seed := resolveCodexFingerprintSeed(account)
	if seed == "" {
		seed = fallbackCodexFingerprintSeed(account)
	}

	ids := &codexFingerprintIDs{
		accountID:           account.ID,
		mode:                mode,
		seed:                seed,
		windowNumber:        windowNumber,
		turnStartedAtUnixMs: time.Now().UnixMilli(),
	}

	ids.installationID = resolveConvergedInstallationID(account, seed)
	if ids.installationID == "" {
		ids.installationID = deriveStableUUIDv4("sub2api:codex-install-id:v2:" + seed)
	}

	switch mode {
	case codexFingerprintDevice:
		return ids

	case codexFingerprintSession:
		ids.sessionID = resolveConvergedSessionID(seed)
		ids.threadID = resolveConvergedThreadID(seed, clientSessionID)
		if ids.threadID == "" {
			ids.threadID = ids.sessionID
		}
		ids.turnID = uuid.Must(uuid.NewV7()).String()
		ids.windowID = fmt.Sprintf("%s:%d", ids.threadID, windowNumber)
		return ids

	case codexFingerprintFull:
		ids.sessionID = resolveConvergedSessionID(seed)
		ids.threadID = ids.sessionID
		ids.turnID = uuid.Must(uuid.NewV7()).String()
		ids.windowID = fmt.Sprintf("%s:%d", ids.threadID, windowNumber)
		return ids
	}

	return nil
}

func resolveCodexFingerprintIDs(account *Account, clientSessionID string, mode codexFingerprintMode) *codexFingerprintIDs {
	return resolveCodexFingerprintIDsWithWindow(account, clientSessionID, 0, mode)
}

// extractClientSessionID 从请求头中提取客户端原始的会话标识。
func extractClientSessionID(h http.Header) string {
	if v := strings.TrimSpace(h.Get("session-id")); v != "" {
		return v
	}
	return strings.TrimSpace(h.Get("session_id"))
}

func codexFingerprintTurnMetadataString(h http.Header, key string) string {
	if h == nil {
		return ""
	}
	raw := strings.TrimSpace(h.Get("x-codex-turn-metadata"))
	if raw == "" || !gjson.Valid(raw) {
		return ""
	}
	return strings.TrimSpace(gjson.Get(raw, key).String())
}

func extractClientThreadID(h http.Header) string {
	if h == nil {
		return ""
	}
	if v := strings.TrimSpace(h.Get("thread-id")); v != "" {
		return v
	}
	if v := strings.TrimSpace(h.Get("thread_id")); v != "" {
		return v
	}
	return codexFingerprintTurnMetadataString(h, "thread_id")
}

func extractClientParentThreadID(h http.Header) string {
	if h == nil {
		return ""
	}
	if v := strings.TrimSpace(h.Get("x-codex-parent-thread-id")); v != "" {
		return v
	}
	return codexFingerprintTurnMetadataString(h, "parent_thread_id")
}

func extractClientForkedFromThreadID(h http.Header) string {
	return codexFingerprintTurnMetadataString(h, "forked_from_thread_id")
}

// resolveCodexFingerprintIDsFromRequest 从客户端原始请求头中提取 session-id 与 window-id，
// 结合账号配置一次性解析收敛 ID 集合。调用方应将返回的 ids 同时传给
// applyCodexFingerprintHeaders 和 applyCodexFingerprintClientMetadata。
func resolveCodexFingerprintIDsFromRequest(account *Account, clientHeaders http.Header) *codexFingerprintIDs {
	if account == nil || !account.IsOpenAIOAuth() {
		return nil
	}
	mode := effectiveCodexFingerprintMode(account.GetCodexFingerprintMode())
	clientSessionID := ""
	var windowNumber uint64
	if clientHeaders != nil {
		clientSessionID = extractClientSessionID(clientHeaders)
		windowNumber = extractClientWindowNumber(clientHeaders)
	}
	ids := resolveCodexFingerprintIDsWithWindow(account, clientSessionID, windowNumber, mode)
	if ids == nil || mode != codexFingerprintSession || clientHeaders == nil {
		return ids
	}

	// Session convergence must preserve Codex's graph: one session can contain a
	// root thread plus multiple subagent/fork threads. Derive each node from the
	// original thread identity, not from the shared session-id.
	if clientThreadID := extractClientThreadID(clientHeaders); clientThreadID != "" {
		ids.threadID = resolveConvergedThreadID(ids.seed, clientThreadID)
		ids.windowID = fmt.Sprintf("%s:%d", ids.threadID, windowNumber)
	}
	if parentThreadID := extractClientParentThreadID(clientHeaders); parentThreadID != "" {
		ids.parentThreadID = resolveConvergedThreadID(ids.seed, parentThreadID)
	}
	if forkedFromThreadID := extractClientForkedFromThreadID(clientHeaders); forkedFromThreadID != "" {
		ids.forkedFromThreadID = resolveConvergedThreadID(ids.seed, forkedFromThreadID)
	}
	return ids
}

// applyCodexFingerprintHeaders 按预计算的收敛 ID 改写出站 HTTP 头中的设备指纹。
func applyCodexFingerprintHeaders(h http.Header, ids *codexFingerprintIDs) {
	if h == nil || ids == nil {
		return
	}

	// 所有非 off 模式都收敛 installation_id
	h.Set("x-codex-installation-id", ids.installationID)

	if ids.mode == codexFingerprintDevice {
		rewriteCodexTurnMetadataFields(h, map[string]any{
			"installation_id": ids.installationID,
		})
		return
	}

	// session / full 模式：改写所有相关头
	h.Set("x-codex-window-id", ids.windowID)
	h.Set("x-client-request-id", ids.threadID)
	// 连字符形式和下划线形式都改写，保证一致
	h.Set("session-id", ids.sessionID)
	h.Set("session_id", ids.sessionID)
	h.Set("thread-id", ids.threadID)
	if ids.mode == codexFingerprintSession && ids.parentThreadID != "" && strings.TrimSpace(h.Get("x-codex-parent-thread-id")) != "" {
		h.Set("x-codex-parent-thread-id", ids.parentThreadID)
	}

	fields := map[string]any{
		"installation_id":         ids.installationID,
		"session_id":              ids.sessionID,
		"thread_id":               ids.threadID,
		"turn_id":                 ids.turnID,
		"window_id":               ids.windowID,
		"window_number":           ids.windowNumber,
		"turn_started_at_unix_ms": ids.turnStartedAtUnixMs,
	}
	if ids.mode == codexFingerprintSession {
		if ids.parentThreadID != "" {
			fields["parent_thread_id"] = ids.parentThreadID
		}
		if ids.forkedFromThreadID != "" {
			fields["forked_from_thread_id"] = ids.forkedFromThreadID
		}
	}
	rewriteCodexTurnMetadataFields(h, fields)
}

func isAllowedCodexClientMetadataKey(key string) bool {
	switch key {
	case "context_window_id",
		"parent_turn_id",
		"previous_window_id",
		"root_turn_id",
		"session_id",
		"thread_id",
		"turn_id",
		"window_id",
		"window_number",
		"ws_request_header_x_openai_internal_codex_responses_lite",
		"x-codex-installation-id",
		"x-codex-parent-thread-id",
		"x-codex-turn-metadata",
		"x-codex-turn-state",
		"x-codex-window-id",
		"x-codex-ws-stream-request-start-ms",
		"x-openai-subagent":
		return true
	default:
		return false
	}
}

func stripLeakedCodexClientMetadata(existing map[string]any) {
	if existing == nil {
		return
	}
	for key := range existing {
		if !isAllowedCodexClientMetadataKey(key) {
			delete(existing, key)
		}
	}
}

// sanitizeTurnMetadataWorkspaces strips associated_remote_urls (git remote) from each workspace
// while preserving commit hash and dirty status to prevent leaking private repository URLs.
func sanitizeTurnMetadataWorkspaces(raw any) any {
	if raw == nil {
		return nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]any, len(m))
	for repoPath, wsVal := range m {
		wsMap, ok := wsVal.(map[string]any)
		if !ok {
			continue
		}
		cleanWs := make(map[string]any, len(wsMap))
		for k, v := range wsMap {
			// Strip associated_remote_urls (git remote) to prevent leaking private repository URLs/tokens
			if k == "associated_remote_urls" {
				continue
			}
			cleanWs[k] = v
		}
		out[repoPath] = cleanWs
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func rebuildCodexTurnMetadata(originalRaw string, fields map[string]any) map[string]any {
	metadata := make(map[string]any, len(fields)+4)
	if strings.TrimSpace(originalRaw) != "" {
		var orig map[string]any
		if err := json.Unmarshal([]byte(originalRaw), &orig); err == nil {
			for k, v := range orig {
				if k == "workspaces" {
					if clean := sanitizeTurnMetadataWorkspaces(v); clean != nil {
						metadata[k] = clean
					}
				} else {
					metadata[k] = v
				}
			}
		}
	}
	for key, value := range fields {
		metadata[key] = value
	}
	return metadata
}

// rewriteCodexTurnMetadataFields writes converged identity fields into x-codex-turn-metadata
// while preserving sandbox/sandbox_mode and workspaces (with git remote stripped).
func rewriteCodexTurnMetadataFields(h http.Header, fields map[string]any) {
	if h == nil {
		return
	}
	origRaw := h.Get("x-codex-turn-metadata")
	if strings.TrimSpace(origRaw) == "" && len(fields) == 0 {
		return
	}
	metadata := rebuildCodexTurnMetadata(origRaw, fields)
	if len(metadata) == 0 {
		deleteHeaderAllForms(h, "x-codex-turn-metadata")
		return
	}
	rebuilt, err := json.Marshal(metadata)
	if err != nil {
		return
	}
	h.Set("x-codex-turn-metadata", string(rebuilt))
}

// applyCodexFingerprintClientMetadata 按预计算的收敛 ID 改写请求体中的 client_metadata。
// 使用与头改写相同的 ids 实例，确保 turn_id 等随机字段一致。
func applyCodexFingerprintClientMetadata(reqBody map[string]any, ids *codexFingerprintIDs) bool {
	if reqBody == nil || ids == nil {
		return false
	}

	captureCodexFingerprintOriginalBodySessionID(ids, reqBody["client_metadata"])
	existing, _ := reqBody["client_metadata"].(map[string]any)
	if existing == nil {
		existing = make(map[string]any)
	}

	modified := false
	if applyCodexFingerprintToClientMetadataMap(existing, ids) {
		reqBody["client_metadata"] = existing
		modified = true
	}
	if applyCodexFingerprintPromptCacheKey(reqBody, ids) {
		modified = true
	}
	return modified
}

// applyCodexFingerprintToClientMetadataMap 是 client_metadata 改写的共享核心，
// map 版（非透传，body 已解码）与 raw 字节版（透传热路径）都经由它，保证两条
// 路径的收敛语义永不漂移。
func applyCodexFingerprintToClientMetadataMap(existing map[string]any, ids *codexFingerprintIDs) bool {
	if existing == nil || ids == nil {
		return false
	}

	if ids.installationID != "" {
		existing["x-codex-installation-id"] = ids.installationID
	}

	if ids.mode == codexFingerprintDevice {
		rewriteClientMetadataEmbeddedTurnMetadata(existing, map[string]any{
			"installation_id": ids.installationID,
		})
		stripLeakedCodexClientMetadata(existing)
		return true
	}

	// session / full 模式
	existing["session_id"] = ids.sessionID
	existing["thread_id"] = ids.threadID
	existing["turn_id"] = ids.turnID
	existing["x-codex-window-id"] = ids.windowID
	existing["window_id"] = ids.windowID
	existing["window_number"] = float64(ids.windowNumber)
	if ids.mode == codexFingerprintSession && ids.parentThreadID != "" {
		if _, exists := existing["x-codex-parent-thread-id"]; exists {
			existing["x-codex-parent-thread-id"] = ids.parentThreadID
		}
	}

	fields := map[string]any{
		"installation_id":         ids.installationID,
		"session_id":              ids.sessionID,
		"thread_id":               ids.threadID,
		"turn_id":                 ids.turnID,
		"window_id":               ids.windowID,
		"window_number":           ids.windowNumber,
		"turn_started_at_unix_ms": ids.turnStartedAtUnixMs,
	}
	if ids.mode == codexFingerprintSession {
		if ids.parentThreadID != "" {
			fields["parent_thread_id"] = ids.parentThreadID
		}
		if ids.forkedFromThreadID != "" {
			fields["forked_from_thread_id"] = ids.forkedFromThreadID
		}
	}
	rewriteClientMetadataEmbeddedTurnMetadata(existing, fields)
	stripLeakedCodexClientMetadata(existing)
	return true
}

func captureCodexFingerprintOriginalBodySessionID(ids *codexFingerprintIDs, clientMetadata any) {
	if ids == nil || ids.originalBodySessionIDCaptured {
		return
	}
	ids.originalBodySessionIDCaptured = true
	if clientMetadata == nil {
		return
	}
	switch metadata := clientMetadata.(type) {
	case map[string]any:
		if sessionID, ok := metadata["session_id"].(string); ok {
			ids.originalBodySessionID = strings.TrimSpace(sessionID)
		}
	case map[string]string:
		ids.originalBodySessionID = strings.TrimSpace(metadata["session_id"])
	}
}

func captureCodexFingerprintOriginalBodySessionIDRaw(ids *codexFingerprintIDs, value gjson.Result) {
	if ids == nil || ids.originalBodySessionIDCaptured {
		return
	}
	ids.originalBodySessionIDCaptured = true
	if value.Exists() && value.Type == gjson.String {
		ids.originalBodySessionID = strings.TrimSpace(value.String())
	}
}

func shouldRewriteCodexFingerprintPromptCacheKey(ids *codexFingerprintIDs, promptCacheKey string) bool {
	if ids == nil || !ids.originalBodySessionIDCaptured || ids.originalBodySessionID == "" || ids.sessionID == "" {
		return false
	}
	if ids.mode != codexFingerprintSession && ids.mode != codexFingerprintFull {
		return false
	}
	return promptCacheKey == ids.originalBodySessionID
}

func applyCodexFingerprintPromptCacheKey(reqBody map[string]any, ids *codexFingerprintIDs) bool {
	if reqBody == nil {
		return false
	}
	promptCacheKey, ok := reqBody["prompt_cache_key"].(string)
	if !ok || strings.TrimSpace(promptCacheKey) == "" || !shouldRewriteCodexFingerprintPromptCacheKey(ids, promptCacheKey) {
		return false
	}
	if promptCacheKey == ids.sessionID {
		return false
	}
	reqBody["prompt_cache_key"] = ids.sessionID
	return true
}

// applyCodexFingerprintClientMetadataRaw 在原始 JSON 字节上改写 client_metadata，
// 供透传路径使用——透传是热路径，禁止对可能高达数十 MB 的 body 做全量
// Unmarshal（见 forwardOpenAIPassthrough 的轻量提取注释）。实现为：gjson 提取
// client_metadata 小对象单独解码，经共享核心改写后 sjson 一次性拼回，body
// 其余字节原样保留；root prompt_cache_key 仅在可证明是 body session 默认值时
// 做标量改写。语义与 applyCodexFingerprintClientMetadata 逐点一致（含
// "非对象值整体替换为收敛集合"的行为）。
func applyCodexFingerprintClientMetadataRaw(body []byte, ids *codexFingerprintIDs) ([]byte, bool, error) {
	if len(body) == 0 || ids == nil {
		return body, false, nil
	}
	// 非 JSON 对象的 body（数组/标量/畸形）没有 client_metadata 语义，
	// sjson 在这类根上写字段会改写整体结构，直接放行保持原样。
	root := gjson.ParseBytes(body)
	if !root.IsObject() {
		captureCodexFingerprintOriginalBodySessionIDRaw(ids, gjson.Result{})
		return body, false, nil
	}
	if err := validateNoDuplicateTopLevelJSONKeys(body); err != nil {
		return body, false, fmt.Errorf("validate fingerprint JSON object: %w", err)
	}

	existing := map[string]any{}
	if cm := gjson.GetBytes(body, "client_metadata"); cm.IsObject() {
		captureCodexFingerprintOriginalBodySessionIDRaw(ids, gjson.GetBytes(body, "client_metadata.session_id"))
		if err := json.Unmarshal([]byte(cm.Raw), &existing); err != nil {
			return body, false, fmt.Errorf("decode client_metadata for fingerprint: %w", err)
		}
	} else {
		captureCodexFingerprintOriginalBodySessionIDRaw(ids, gjson.Result{})
	}

	next := body
	modified := false
	if applyCodexFingerprintToClientMetadataMap(existing, ids) {
		raw, err := json.Marshal(existing)
		if err != nil {
			return body, false, fmt.Errorf("encode converged client_metadata: %w", err)
		}
		var setErr error
		next, setErr = sjson.SetRawBytes(body, "client_metadata", raw)
		if setErr != nil {
			return body, false, fmt.Errorf("splice converged client_metadata: %w", setErr)
		}
		modified = true
	}
	promptCacheKey := gjson.GetBytes(body, "prompt_cache_key")
	if promptCacheKey.Exists() && promptCacheKey.Type == gjson.String && strings.TrimSpace(promptCacheKey.String()) != "" && shouldRewriteCodexFingerprintPromptCacheKey(ids, promptCacheKey.String()) {
		rewritten, err := sjson.SetBytes(next, "prompt_cache_key", ids.sessionID)
		if err != nil {
			return body, false, fmt.Errorf("splice converged prompt_cache_key: %w", err)
		}
		next = rewritten
		modified = true
	}
	return next, modified, nil
}

// rewriteClientMetadataEmbeddedTurnMetadata 改写 client_metadata 中内嵌的
// x-codex-turn-metadata JSON 字符串里的指定字段。非法/非对象值会重建，
// 避免 flat client_metadata 与 embedded metadata 暴露两套身份。
func rewriteClientMetadataEmbeddedTurnMetadata(clientMetadata map[string]any, fields map[string]any) {
	if clientMetadata == nil {
		return
	}
	origRaw, _ := clientMetadata["x-codex-turn-metadata"].(string)
	metadata := rebuildCodexTurnMetadata(origRaw, fields)
	if len(metadata) == 0 {
		delete(clientMetadata, "x-codex-turn-metadata")
		return
	}
	if rebuilt, err := json.Marshal(metadata); err == nil {
		clientMetadata["x-codex-turn-metadata"] = string(rebuilt)
	}
}

// sanitizeCodexOutboundAssociationHeaders 删除/重建 Cookie、locale、timeout、
// Accept-Language、beta、attestation、客户端 turn-state / Accept 等关联通道。
// Accept 由 applyCodexOutboundAccept 按协议重建，不得转发客户端原值。
func sanitizeCodexOutboundAssociationHeaders(h http.Header) {
	if h == nil {
		return
	}
	for _, key := range []string{
		"Cookie",
		"Set-Cookie",
		"Accept",
		"openai-beta",
		"x-oai-attestation",
		"x-openai-attestation",
		"x-codex-attestation",
		"attestation",
		"x-attestation",
		"x-stainless-timeout",
		"x-stainless-read-timeout",
		"x-stainless-connect-timeout",
		"x-stainless-os",
		"x-stainless-arch",
		"x-stainless-lang",
		"x-stainless-runtime",
		"x-stainless-runtime-version",
		"x-request-timeout",
		"request-timeout",
		"grpc-timeout",
		"x-codex-beta-features",
		openAICodexTurnStateHeader,
	} {
		deleteHeaderAllForms(h, key)
	}
	h.Set("accept-language", "en-US")
}

func applyCodexOutboundAccept(h http.Header, compact bool) {
	if h == nil {
		return
	}
	deleteHeaderAllForms(h, "Accept")
	if compact {
		h.Set("accept", "application/json")
		return
	}
	h.Set("accept", "application/json, text/event-stream")
}

func applyCodexFingerprintToUsageProbeRequest(account *Account, h http.Header) {
	if h == nil {
		return
	}
	fpIDs := resolveCodexFingerprintIDsFromRequest(account, h)
	sanitizeCodexOutboundAssociationHeaders(h)
	applyCodexFingerprintHeaders(h, fpIDs)
	applyOpenAICodexBetaFeatures(nil, account, h)
	applyCodexOutboundAccept(h, false)
}
