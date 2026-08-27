//! Account Mimic and Realistic Workstation Simulation Engine.
//!
//! Enforces official OpenAI Codex CLI identity convergence, UUID derivation,
//! exact protocol-fidelity window_id/window_number preservation across compactions,
//! header normalization, tracking channel stripping, and realistic organic
//! client workstation simulation per account/group cluster on the egress boundary.

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{json, Value};

/// Derive a deterministic UUIDv4 from a namespace string, seed, and deployment salt.
pub fn derive_converged_uuid_v4(seed: &str, namespace: &str, salt: &str) -> String {
    let key = format!("sub2api:{namespace}:v2:{salt}:{seed}");
    let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, key.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash.as_ref()[..16]);
    // Set UUIDv4 version (4) and RFC 4122 variant (2)
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}

/// Derive a deterministic Thread ID from account seed, client session ID, and deployment salt.
pub fn derive_converged_thread_id(seed: &str, client_session_id: &str, salt: &str) -> String {
    let client_part = if client_session_id.trim().is_empty() {
        "default"
    } else {
        client_session_id.trim()
    };
    let key = format!("sub2api:codex-thread-id:v2:{salt}:{seed}:{client_part}");
    let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, key.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash.as_ref()[..16]);
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}

/// Extract exact client version from agent / User-Agent headers.
pub fn extract_client_version_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = headers.get("x-codex-client-version").or_else(|| headers.get("x-client-version")) {
        if let Ok(s) = v.to_str() {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    if let Some(ua) = headers.get(axum::http::header::USER_AGENT) {
        if let Ok(ua_str) = ua.to_str() {
            for part in ua_str.split(|c: char| c == '/' || c == ' ' || c == '(' || c == ')') {
                let ver: String = part
                    .trim_start_matches(|c: char| c == 'v' || c == 'V')
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
                    .collect();
                if ver.contains('.') && ver.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                    return Some(ver);
                }
            }
        }
    }
    None
}

/// Extract window number from raw `x-codex-window-id` string or JSON metadata.
///
/// In official Codex protocol, `x-codex-window-id = "<thread_id>:<window_number>"`.
/// Compaction increments `window_number` (0 -> 1 -> 2 ...).
pub fn extract_window_number(window_id_str: Option<&str>, metadata: Option<&Value>) -> u64 {
    // 1. Check window_id string suffix: e.g. "019...abc:2" -> 2
    if let Some(w_str) = window_id_str {
        if let Some(pos) = w_str.rfind(':') {
            if let Ok(num) = w_str[pos + 1..].trim().parse::<u64>() {
                return num;
            }
        } else if let Ok(num) = w_str.trim().parse::<u64>() {
            return num;
        }
    }
    // 2. Check metadata fields
    if let Some(meta) = metadata {
        if let Some(num) = meta.get("window_number").and_then(|v| v.as_u64()) {
            return num;
        }
        if let Some(w_val) = meta.get("window_id").or_else(|| meta.get("x-codex-window-id")).and_then(|v| v.as_str()) {
            if let Some(pos) = w_val.rfind(':') {
                if let Ok(num) = w_val[pos + 1..].trim().parse::<u64>() {
                    return num;
                }
            }
        }
    }
    0
}

const REALISTIC_USERNAMES: &[&str] = &[
    "alex", "sam", "jordan", "taylor", "morgan", "chris", "pat", "casey", "riley", "avery",
    "quinn", "jamie", "logan", "cameron", "drew", "skyler", "reese", "rowan", "ellis", "kendall",
    "harper", "finley", "dakota", "robin",
];

const REALISTIC_PROJECTS: &[&str] = &[
    "backend", "core-api", "frontend", "platform", "infra", "gateway", "services", "web-app",
    "microservices", "pipeline", "auth-service", "engine", "hub", "client", "agent-runner",
    "dashboard", "worker", "storage", "connector", "runtime", "data-pipeline", "server",
    "sdk", "toolkit", "dispatcher", "streamer", "proxy-service", "indexer", "scheduler",
    "controller",
];

/// Identity metadata generated for a turn, including realistic organic workstation simulation
/// and precise compaction window number preservation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConvergedIdentity {
    pub installation_id: String,
    pub session_id: String,
    pub thread_id: String,
    pub turn_id: String,
    pub window_id: String,
    pub window_number: u64,
    pub turn_started_at_unix_ms: i64,
    pub client_version: String,
    pub os: String,
    pub arch: String,
    pub terminal: String,
    pub cwd: String,
    pub git_branch: String,
}

impl ConvergedIdentity {
    pub fn new(
        seed: &str,
        client_session_id: Option<&str>,
        custom_device_id: Option<&str>,
        salt: &str,
        agent_version: Option<&str>,
        window_number: u64,
    ) -> Self {
        let installation_id = if let Some(dev_id) = custom_device_id.filter(|s| !s.trim().is_empty()) {
            derive_converged_uuid_v4(dev_id.trim(), "codex-device-pseudonym", salt)
        } else {
            derive_converged_uuid_v4(seed, "codex-install-id", salt)
        };
        let session_id = derive_converged_uuid_v4(seed, "codex-session-id", salt);
        let thread_id = derive_converged_thread_id(seed, client_session_id.unwrap_or(""), salt);
        let turn_id = uuid::Uuid::now_v7().to_string();
        let window_id = format!("{thread_id}:{window_number}");
        let turn_started_at_unix_ms = chrono::Utc::now().timestamp_millis();

        let hash = aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA256,
            format!("workstation:{salt}:{seed}").as_bytes(),
        );
        let h = hash.as_ref();

        let (os, arch) = match h[0] % 4 {
            0 | 1 => ("darwin".to_string(), "arm64".to_string()),
            2 => ("darwin".to_string(), "x86_64".to_string()),
            _ => ("linux".to_string(), "x86_64".to_string()),
        };

        let username = REALISTIC_USERNAMES[(h[1] as usize) % REALISTIC_USERNAMES.len()];
        let project = REALISTIC_PROJECTS[(h[2] as usize) % REALISTIC_PROJECTS.len()];

        let cwd = if os == "darwin" {
            match h[3] % 3 {
                0 => format!("/Users/{username}/Projects/{project}"),
                1 => format!("/Users/{username}/Developer/{project}"),
                _ => format!("/Users/{username}/code/{project}"),
            }
        } else {
            match h[3] % 3 {
                0 => format!("/home/{username}/workspace/{project}"),
                1 => format!("/home/{username}/dev/{project}"),
                _ => format!("/home/{username}/src/{project}"),
            }
        };

        let git_branch = match h[4] % 4 {
            0 => "main".to_string(),
            1 => "master".to_string(),
            2 => "develop".to_string(),
            _ => "testing".to_string(),
        };

        let terminal = if os == "darwin" {
            match h[5] % 4 {
                0 => "vscode-terminal",
                1 => "iTerm.app",
                2 => "Apple_Terminal",
                _ => "alacritty",
            }
        } else {
            match h[5] % 4 {
                0 => "vscode-terminal",
                1 => "xterm-256color",
                2 => "kitty",
                _ => "alacritty",
            }
        }
        .to_string();

        let client_version = agent_version
            .filter(|v| !v.trim().is_empty())
            .map(|v| v.trim().to_string())
            .unwrap_or_else(|| "0.1.183".to_string());

        Self {
            installation_id,
            session_id,
            thread_id,
            turn_id,
            window_id,
            window_number,
            turn_started_at_unix_ms,
            client_version,
            os,
            arch,
            terminal,
            cwd,
            git_branch,
        }
    }
}

/// Allowed keys in flat `client_metadata` (Strict Fail-Closed Whitelist).
/// Codex Core wire schema is Option<HashMap<String, String>>.
pub const ALLOWED_FLAT_CLIENT_METADATA_KEYS: &[&str] = &[
    "x-codex-installation-id",
    "session_id",
    "thread_id",
    "x-codex-window-id",
    "window_id",
    "window_number",
    "context_window_id",
    "previous_window_id",
    "turn_id",
    "x-openai-subagent",
    "x-codex-parent-thread-id",
    "parent_turn_id",
    "root_turn_id",
    "x-codex-turn-metadata",
    "ws_request_header_x_openai_internal_codex_responses_lite",
    "x-codex-turn-state",
    "x-codex-ws-stream-request-start-ms",
];

/// Sanitize workspace root path to ensure consistency with simulated workstation OS
/// while eliminating private physical paths and usernames.
pub fn sanitize_workspace_path(raw_path: &str, identity: &ConvergedIdentity) -> String {
    let proj_name = raw_path
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|p| !p.is_empty())
        .unwrap_or("project");
    let user = identity.cwd.split('/').nth(2).unwrap_or("developer");
    if identity.os == "darwin" {
        format!("/Users/{user}/Projects/{proj_name}")
    } else {
        format!("/home/{user}/workspace/{proj_name}")
    }
}

/// Sanitize client_metadata in place:
/// 1. Strict FAIL-CLOSED on flat client_metadata: retain ONLY official allowed keys.
/// 2. Open Schema on nested x-codex-turn-metadata (NOT fail-closed): strips git remote URLs,
///    makes workspace paths consistent with simulated OS, preserves all other rich metadata fields.
pub fn sanitize_client_metadata(metadata: &mut Value, identity: &ConvergedIdentity) {
    if let Value::Object(ref mut map) = metadata {
        // 1. Strict Fail-Closed on flat client_metadata
        map.retain(|key, _| ALLOWED_FLAT_CLIENT_METADATA_KEYS.contains(&key.as_str()));

        // 2. Open Schema on nested x-codex-turn-metadata: ONLY sanitize workspaces (strip git remotes & normalize path)
        if let Some(turn_meta_val) = map.get_mut("x-codex-turn-metadata") {
            if let Some(turn_meta_str) = turn_meta_val.as_str() {
                if let Ok(mut tm) = serde_json::from_str::<Value>(turn_meta_str) {
                    if let Some(tm_map) = tm.as_object_mut() {
                        if let Some(workspaces) = tm_map.get_mut("workspaces").and_then(|w| w.as_object_mut()) {
                            let mut sanitized_workspaces = serde_json::Map::new();
                            for (ws_path, ws_info) in workspaces.iter_mut() {
                                if let Some(ws_map) = ws_info.as_object_mut() {
                                    // Strip associated_remote_urls (git remote)
                                    ws_map.remove("associated_remote_urls");
                                }
                                let clean_path = sanitize_workspace_path(ws_path, identity);
                                sanitized_workspaces.insert(clean_path, ws_info.clone());
                            }
                            *workspaces = sanitized_workspaces;
                        }
                    }
                    if let Ok(sanitized_str) = serde_json::to_string(&tm) {
                        *turn_meta_val = json!(sanitized_str);
                    }
                }
            }
        }
    }
}

/// Transform HTTP JSON request body: apply fail-closed leak sanitization and identity convergence.
pub fn transform_request_body(
    body_bytes: &[u8],
    seed: &str,
    custom_device_id: Option<&str>,
    salt: &str,
    agent_version: Option<&str>,
    header_window_number: Option<u64>,
) -> Option<Vec<u8>> {
    if body_bytes.is_empty() {
        return None;
    }
    let mut val: Value = match serde_json::from_slice(body_bytes) {
        Ok(v) => v,
        Err(_) => return None, // Non-JSON, leave unmodified
    };

    let obj = match val.as_object_mut() {
        Some(obj) => obj,
        None => return None,
    };

    // Extract client session ID if provided by the client
    let client_session_id = obj
        .get("session_id")
        .and_then(|v| v.as_str())
        .or_else(|| {
            obj.get("client_metadata")
                .and_then(|m| m.get("session_id"))
                .and_then(|v| v.as_str())
        })
        .map(|s| s.to_string());

    let window_num = header_window_number.unwrap_or_else(|| {
        extract_window_number(
            obj.get("window_id").and_then(|v| v.as_str()),
            obj.get("client_metadata"),
        )
    });

    let identity = ConvergedIdentity::new(
        seed,
        client_session_id.as_deref(),
        custom_device_id,
        salt,
        agent_version,
        window_num,
    );

    // If client_metadata is present, sanitize and converge
    if let Some(metadata) = obj.get_mut("client_metadata") {
        sanitize_client_metadata(metadata, &identity);
    }

    // prompt_cache_key convergence is handled by the Go backend — sidecar does NOT touch it.

    serde_json::to_vec(&val).ok()
}

/// Transform WebSocket text frame (e.g. `response.create`): strip leaks and converge.
pub fn transform_ws_frame(
    frame_text: &str,
    seed: &str,
    custom_device_id: Option<&str>,
    salt: &str,
    agent_version: Option<&str>,
    header_window_number: Option<u64>,
) -> Option<String> {
    let mut val: Value = match serde_json::from_str(frame_text) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let obj = match val.as_object_mut() {
        Some(obj) => obj,
        None => return None,
    };

    let client_session_id = obj
        .get("session_id")
        .and_then(|v| v.as_str())
        .or_else(|| {
            obj.get("client_metadata")
                .and_then(|m| m.get("session_id"))
                .and_then(|v| v.as_str())
        })
        .or_else(|| {
            obj.get("response")
                .and_then(|r| r.get("client_metadata"))
                .and_then(|m| m.get("session_id"))
                .and_then(|v| v.as_str())
        })
        .map(|s| s.to_string());

    let window_num = header_window_number.unwrap_or_else(|| {
        let meta_opt = obj.get("client_metadata").or_else(|| {
            obj.get("response").and_then(|r| r.get("client_metadata"))
        });
        extract_window_number(
            obj.get("window_id").and_then(|v| v.as_str()),
            meta_opt,
        )
    });

    let identity = ConvergedIdentity::new(
        seed,
        client_session_id.as_deref(),
        custom_device_id,
        salt,
        agent_version,
        window_num,
    );

    let mut modified = false;

    if let Some(metadata) = obj.get_mut("client_metadata") {
        sanitize_client_metadata(metadata, &identity);
        modified = true;
    }
    if let Some(response) = obj.get_mut("response").and_then(|r| r.as_object_mut()) {
        if let Some(metadata) = response.get_mut("client_metadata") {
            sanitize_client_metadata(metadata, &identity);
            modified = true;
        }
    }

    if modified {
        serde_json::to_string(&val).ok()
    } else {
        None
    }
}

/// Allowed x- headers on Account/Status requests (/api/codex/..., /wham/..., /usage, /status).
/// Strict Fail-Closed for x- beginning headers.
pub const ALLOWED_ACCOUNT_X_HEADERS: &[&str] = &[
    "x-openai-fedramp",
];

/// Allowed x- headers on Inference/Responses requests (/responses, /responses/compact, WebSocket).
/// Strict Fail-Closed for x- beginning headers.
pub const ALLOWED_RESPONSES_X_HEADERS: &[&str] = &[
    "x-client-request-id",
    "x-codex-installation-id",
    "x-codex-window-id",
    "x-codex-turn-metadata",
    "x-codex-parent-thread-id",
    "x-openai-subagent",
    "x-codex-turn-state",
    "x-codex-routing-hint",
    "x-codex-beta-features",
    "x-openai-internal-codex-responses-lite",
    "x-openai-memgen-request",
    "x-openai-internal-codex-residency",
    "x-openai-fedramp",
];

/// Non-x- headers that are leaks or tracking channels.
pub fn is_leaked_non_x_header(key: &str) -> bool {
    matches!(
        key,
        "traceparent" | "tracestate" | "baggage" | "cookie" | "set-cookie" | "attestation"
    )
}

/// Sanitize and normalize outbound HTTP request headers.
/// Strict Fail-Closed is applied ONLY to headers beginning with `x-`.
/// Non-x headers pass through naturally, only stripping APM tracing and cookies.
pub fn sanitize_and_inject_headers(
    headers: &mut HeaderMap,
    seed: &str,
    client_session_id: Option<&str>,
    custom_device_id: Option<&str>,
    salt: &str,
    agent_version: Option<&str>,
    window_number: u64,
    is_responses_path: bool,
) {
    let identity = ConvergedIdentity::new(
        seed,
        client_session_id,
        custom_device_id,
        salt,
        agent_version,
        window_number,
    );

    let allowed_x_headers = if is_responses_path {
        ALLOWED_RESPONSES_X_HEADERS
    } else {
        ALLOWED_ACCOUNT_X_HEADERS
    };

    // 1. Strict Fail-Closed ONLY for x- headers; strip APM/tracking for non-x headers
    let keys_to_remove: Vec<HeaderName> = headers
        .keys()
        .filter(|name| {
            let key = name.as_str();
            if key.starts_with("x-") {
                !allowed_x_headers.contains(&key)
            } else {
                is_leaked_non_x_header(key)
            }
        })
        .cloned()
        .collect();
    for key in keys_to_remove {
        headers.remove(key);
    }

    // 2. Normalize or inject User-Agent header to strictly match simulated OS/arch
    let os_display = if identity.os == "darwin" { "Darwin" } else { "Linux" };
    let arch_display = &identity.arch;
    let ver = &identity.client_version;

    if let Some(ua_val) = headers.get_mut(axum::http::header::USER_AGENT) {
        if let Ok(ua_str) = ua_val.to_str() {
            if ua_str.starts_with("codex_cli_rs") {
                let new_ua = if identity.os == "darwin" {
                    format!("codex_cli_rs/{ver} (macOS 14.5.0; {arch_display}) vscode-terminal")
                } else {
                    format!("codex_cli_rs/{ver} (Ubuntu 22.04.4; {arch_display}) xterm-256color")
                };
                if let Ok(v) = HeaderValue::from_str(&new_ua) {
                    *ua_val = v;
                }
            } else {
                let new_ua = format!("OpenAI/Codex/{ver} ({os_display} {arch_display})");
                if let Ok(v) = HeaderValue::from_str(&new_ua) {
                    *ua_val = v;
                }
            }
        }
    } else {
        let new_ua = format!("OpenAI/Codex/{ver} ({os_display} {arch_display})");
        if let Ok(v) = HeaderValue::from_str(&new_ua) {
            headers.insert(axum::http::header::USER_AGENT, v);
        }
    }

    // 3. For Inference / Responses paths only: inject deterministic fallback headers if missing
    if is_responses_path {
        if !headers.contains_key("session-id") && !headers.contains_key("session_id") {
            if let Ok(v) = HeaderValue::from_str(&identity.session_id) {
                headers.insert(HeaderName::from_static("session-id"), v);
            }
        }
        if !headers.contains_key("thread-id") {
            if let Ok(v) = HeaderValue::from_str(&identity.thread_id) {
                headers.insert(HeaderName::from_static("thread-id"), v);
            }
        }
        if !headers.contains_key("x-codex-window-id") {
            if let Ok(v) = HeaderValue::from_str(&identity.window_id) {
                headers.insert(HeaderName::from_static("x-codex-window-id"), v);
            }
        }

        if let Some(turn_meta_val) = headers.get_mut("x-codex-turn-metadata") {
            if let Ok(turn_meta_str) = turn_meta_val.to_str() {
                if let Ok(mut tm) = serde_json::from_str::<Value>(turn_meta_str) {
                    if let Some(tm_map) = tm.as_object_mut() {
                        if let Some(workspaces) = tm_map.get_mut("workspaces").and_then(|w| w.as_object_mut()) {
                            let mut sanitized_workspaces = serde_json::Map::new();
                            for (ws_path, ws_info) in workspaces.iter_mut() {
                                if let Some(ws_map) = ws_info.as_object_mut() {
                                    ws_map.remove("associated_remote_urls");
                                }
                                let clean_path = sanitize_workspace_path(ws_path, &identity);
                                sanitized_workspaces.insert(clean_path, ws_info.clone());
                            }
                            *workspaces = sanitized_workspaces;
                        }
                    }
                    if let Ok(sanitized_str) = serde_json::to_string(&tm) {
                        if let Ok(v) = HeaderValue::from_str(&sanitized_str) {
                            *turn_meta_val = v;
                        }
                    }
                }
            }
        } else {
            let turn_metadata = json!({
                "installation_id": identity.installation_id,
                "session_id": identity.session_id,
                "thread_id": identity.thread_id,
                "turn_id": identity.turn_id,
                "window_id": identity.window_id,
                "window_number": identity.window_number,
                "turn_started_at_unix_ms": identity.turn_started_at_unix_ms,
            });
            if let Ok(json_str) = serde_json::to_string(&turn_metadata) {
                if let Ok(v) = HeaderValue::from_str(&json_str) {
                    headers.insert(HeaderName::from_static("x-codex-turn-metadata"), v);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_uuid_convergence_with_salt() {
        let salt1 = "deploy_salt_prod";
        let salt2 = "deploy_salt_staging";

        let id1 = derive_converged_uuid_v4("group_123", "codex-install-id", salt1);
        let id2 = derive_converged_uuid_v4("group_123", "codex-install-id", salt1);
        assert_eq!(id1, id2, "same seed & salt must produce identical installation_id");
        assert_eq!(id1.chars().nth(14), Some('4'), "must be UUIDv4");

        // Cloned DB with different deployment salt produces independent UUIDs
        let id_cloned = derive_converged_uuid_v4("group_123", "codex-install-id", salt2);
        assert_ne!(id1, id_cloned, "different salt must isolate cloned DBs");

        let th1 = derive_converged_thread_id("group_123", "client_sess_1", salt1);
        let th2 = derive_converged_thread_id("group_123", "client_sess_1", salt1);
        assert_eq!(th1, th2, "same client session must produce identical thread_id");
    }

    #[test]
    fn window_number_preserves_protocol_fidelity_across_compaction() {
        let identity_init = ConvergedIdentity::new("seed_compaction", Some("sess"), None, "salt", None, 0);
        assert_eq!(identity_init.window_number, 0);
        assert!(identity_init.window_id.ends_with(":0"));

        // After compaction advances to window 2
        let identity_compacted = ConvergedIdentity::new("seed_compaction", Some("sess"), None, "salt", None, 2);
        assert_eq!(identity_compacted.window_number, 2);
        assert!(identity_compacted.window_id.ends_with(":2"));
        assert_eq!(identity_compacted.thread_id, identity_init.thread_id, "thread_id remains stable across compaction");
    }

    #[test]
    fn extract_window_number_from_headers_and_metadata() {
        assert_eq!(extract_window_number(Some("019abc-def:3"), None), 3);
        assert_eq!(extract_window_number(Some("019abc-def:0"), None), 0);
        assert_eq!(extract_window_number(Some("5"), None), 5);

        let meta = json!({
            "window_number": 4,
            "window_id": "thread:4"
        });
        assert_eq!(extract_window_number(None, Some(&meta)), 4);
    }

    #[test]
    fn groups_have_distinct_organic_environments() {
        let env_a = ConvergedIdentity::new("group_team_alpha", None, None, "salt", Some("0.1.144"), 0);
        let env_b = ConvergedIdentity::new("group_finance_infra", None, None, "salt", Some("0.1.144"), 0);

        // Both are valid, realistic environments
        assert!(env_a.cwd.starts_with("/Users/") || env_a.cwd.starts_with("/home/"));
        assert!(env_b.cwd.starts_with("/Users/") || env_b.cwd.starts_with("/home/"));

        // Different groups have distinct paths and identities
        assert_ne!(env_a.installation_id, env_b.installation_id);
        assert_ne!(env_a.cwd, env_b.cwd);
        assert_eq!(env_a.client_version, "0.1.144");
        assert_eq!(env_b.client_version, "0.1.144");
    }

    #[test]
    fn exact_agent_header_version_extraction() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::USER_AGENT,
            HeaderValue::from_static("codex_cli_rs/0.144.1"),
        );
        let ver = extract_client_version_from_headers(&headers);
        assert_eq!(ver, Some("0.144.1".to_string()));

        let mut headers_oai = HeaderMap::new();
        headers_oai.insert(
            axum::http::header::USER_AGENT,
            HeaderValue::from_static("OpenAI/Codex/0.1.183 (Darwin arm64)"),
        );
        let ver_oai = extract_client_version_from_headers(&headers_oai);
        assert_eq!(ver_oai, Some("0.1.183".to_string()));
    }

    #[test]
    fn custom_device_id_is_pseudonymized() {
        let identity = ConvergedIdentity::new("seed", None, Some("raw_hardware_id_abc"), "salt", None, 0);
        assert_ne!(identity.installation_id, "raw_hardware_id_abc");
        assert_eq!(identity.installation_id.chars().nth(14), Some('4'));
    }

    #[test]
    fn fail_closed_metadata_sanitization_and_mimic() {
        let identity = ConvergedIdentity::new("test_seed", Some("client_sess"), None, "salt", Some("0.1.135"), 1);
        let mut meta = json!({
            "cwd": "/Users/victim/secret_project",
            "workspace": "/develop/proprietary",
            "git_branch": "feature/leak",
            "terminal": "iterm2",
            "mcp": { "secret": "token" },
            "custom_instructions": "do not leak",
            "unknown_future_telemetry": "should_be_dropped",
            "window_number": 1,
            "session_id": "client_original_session",
            "thread_id": "client_original_thread",
        });

        sanitize_client_metadata(&mut meta, &identity);

        // Leaked/non-standard keys are stripped from flat client_metadata (Fail-Closed)
        assert!(meta.get("workspace").is_none());
        assert!(meta.get("mcp").is_none());
        assert!(meta.get("custom_instructions").is_none());
        assert!(meta.get("unknown_future_telemetry").is_none()); // strict fail-closed on flat client_metadata
        assert!(meta.get("cwd").is_none());
        assert!(meta.get("git_branch").is_none());
        assert!(meta.get("terminal").is_none());

        // Identity fields are NOT overwritten by sidecar — pass through for Go to handle
        assert_eq!(meta.get("session_id").unwrap(), "client_original_session");
        assert_eq!(meta.get("thread_id").unwrap(), "client_original_thread");
        assert_eq!(meta.get("window_number").unwrap(), 1);
    }

    #[test]
    fn headers_sanitization_preserves_turn_state_and_strips_tracking() {
        let mut headers = HeaderMap::new();
        headers.insert(HeaderName::from_static("traceparent"), HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"));
        headers.insert(HeaderName::from_static("cookie"), HeaderValue::from_static("oai_session=leaked_cookie"));
        headers.insert(HeaderName::from_static("x-codex-turn-state"), HeaderValue::from_static("server_turn_state_token_123"));
        headers.insert(HeaderName::from_static("x-codex-window-id"), HeaderValue::from_static("client_th:2"));
        headers.insert(axum::http::header::USER_AGENT, HeaderValue::from_static("OpenAI/Codex/0.1.183 (Unknown 1.0)"));

        sanitize_and_inject_headers(&mut headers, "seed", Some("sess"), None, "salt", Some("0.1.183"), 2, true);

        assert!(headers.get("traceparent").is_none());
        assert!(headers.get("cookie").is_none());
        // x-codex-turn-state MUST be preserved for server routing!
        assert_eq!(headers.get("x-codex-turn-state").unwrap().to_str().unwrap(), "server_turn_state_token_123");
        assert!(headers.get("session-id").is_some());
        assert!(headers.get("x-codex-turn-metadata").is_some());
        assert!(headers.get("x-codex-window-id").unwrap().to_str().unwrap().ends_with(":2"));

        // User-Agent normalized to reflect simulated OS and arch
        let ua = headers.get(axum::http::header::USER_AGENT).unwrap().to_str().unwrap();
        assert!(ua.contains("Darwin") || ua.contains("Linux"));
    }

    #[test]
    fn transform_request_body_roundtrip() {
        let input = json!({
            "model": "gpt-4o",
            "session_id": "client_session_abc",
            "prompt_cache_key": "client_session_abc",
            "client_metadata": {
                "session_id": "client_session_abc",
                "cwd": "/home/dev/repo",
                "git_branch": "feature/123",
                "custom_instructions": "secret",
                "window_number": 2,
            }
        });
        let raw = serde_json::to_vec(&input).unwrap();
        let transformed = transform_request_body(&raw, "seed_42", None, "salt_1", Some("0.1.183"), None).unwrap();
        let parsed: Value = serde_json::from_slice(&transformed).unwrap();

        assert_eq!(parsed.get("model").unwrap(), "gpt-4o");
        let meta = parsed.get("client_metadata").unwrap();

        // Non-standard flat keys stripped
        assert!(meta.get("cwd").is_none());
        assert!(meta.get("git_branch").is_none());
        assert!(meta.get("custom_instructions").is_none());

        // Identity fields pass through untouched — Go handles convergence
        assert_eq!(meta.get("session_id").unwrap(), "client_session_abc");
        assert_eq!(meta.get("window_number").unwrap(), 2);

        // prompt_cache_key is NOT rewritten by sidecar — Go handles it
        assert_eq!(parsed.get("prompt_cache_key").unwrap(), "client_session_abc");
    }

    #[test]
    fn transform_ws_frame_roundtrip() {
        let input = json!({
            "type": "response.create",
            "client_metadata": {
                "cwd": "/tmp/leak",
                "workspace": "/home/user",
                "session_id": "ws_client_sess",
                "window_number": 1,
            }
        });
        let raw_str = serde_json::to_string(&input).unwrap();
        let transformed = transform_ws_frame(&raw_str, "seed_ws", None, "salt_ws", Some("0.1.183"), None).unwrap();
        let parsed: Value = serde_json::from_str(&transformed).unwrap();

        let meta = parsed.get("client_metadata").unwrap();
        // Non-standard flat keys stripped
        assert!(meta.get("cwd").is_none());
        assert!(meta.get("workspace").is_none());

        // Identity fields pass through untouched — Go handles convergence
        assert_eq!(meta.get("session_id").unwrap(), "ws_client_sess");
        assert_eq!(meta.get("window_number").unwrap(), 1);
    }

    #[test]
    fn workspaces_strip_remote_url_and_preserve_sandbox() {
        let identity = ConvergedIdentity::new("test_seed", Some("client_sess"), None, "salt", Some("0.1.183"), 1);
        let turn_meta_raw = json!({
            "installation_id": "inst_123",
            "session_id": "sess_123",
            "sandbox": "seatbelt",
            "sandbox_mode": "danger-full-access",
            "workspaces": {
                "/Users/alice/proprietary/project": {
                    "associated_remote_urls": {
                        "origin": "https://token:secret@github.com/secret-org/proprietary-repo.git"
                    },
                    "latest_git_commit_hash": "a1b2c3d4e5f67890",
                    "has_changes": false
                }
            }
        });

        let mut meta = json!({
            "session_id": "sess_123",
            "x-codex-turn-metadata": serde_json::to_string(&turn_meta_raw).unwrap(),
        });

        sanitize_client_metadata(&mut meta, &identity);

        let sanitized_tm_str = meta.get("x-codex-turn-metadata").unwrap().as_str().unwrap();
        let sanitized_tm: Value = serde_json::from_str(sanitized_tm_str).unwrap();

        // sandbox & sandbox_mode are preserved!
        assert_eq!(sanitized_tm.get("sandbox").unwrap(), "seatbelt");
        assert_eq!(sanitized_tm.get("sandbox_mode").unwrap(), "danger-full-access");

        // workspaces associated_remote_urls is stripped, while commit hash & has_changes are kept, and path is sanitized
        let workspaces = sanitized_tm.get("workspaces").unwrap().as_object().unwrap();
        let (ws_path, ws_info) = workspaces.iter().next().unwrap();
        assert!(ws_path.ends_with("/project"));
        assert!(ws_info.get("associated_remote_urls").is_none());
        assert_eq!(ws_info.get("latest_git_commit_hash").unwrap(), "a1b2c3d4e5f67890");
        assert_eq!(ws_info.get("has_changes").unwrap(), false);
    }

    #[test]
    fn git_branch_uses_normal_names() {
        for seed_idx in 0..20 {
            let identity = ConvergedIdentity::new(&format!("seed_{seed_idx}"), None, None, "salt", None, 0);
            assert!(
                matches!(identity.git_branch.as_str(), "main" | "master" | "develop" | "testing"),
                "git_branch '{}' must be one of standard normal branches",
                identity.git_branch
            );
        }
    }

    #[test]
    fn user_agent_and_workspace_path_are_mutually_consistent() {
        for seed_idx in 0..10 {
            let seed = format!("seed_consistency_{seed_idx}");
            let identity = ConvergedIdentity::new(&seed, None, None, "salt", Some("0.1.183"), 0);

            // Workspace path
            let ws_path = sanitize_workspace_path("/Users/raw_user/private_dir/my_tool", &identity);
            if identity.os == "darwin" {
                assert!(ws_path.starts_with("/Users/"), "Darwin must produce /Users/ path: {}", ws_path);
            } else {
                assert!(ws_path.starts_with("/home/"), "Linux must produce /home/ path: {}", ws_path);
            }

            // User-Agent
            let mut headers = HeaderMap::new();
            headers.insert(axum::http::header::USER_AGENT, HeaderValue::from_static("OpenAI/Codex/0.1.183 (Unknown)"));
            sanitize_and_inject_headers(&mut headers, &seed, None, None, "salt", Some("0.1.183"), 0, true);

            let ua = headers.get(axum::http::header::USER_AGENT).unwrap().to_str().unwrap();
            if identity.os == "darwin" {
                assert!(ua.contains("Darwin"), "Darwin OS must reflect in User-Agent: {}", ua);
            } else {
                assert!(ua.contains("Linux"), "Linux OS must reflect in User-Agent: {}", ua);
            }
        }
    }

    #[test]
    fn account_vs_inference_header_fail_closed() {
        let mut account_headers = HeaderMap::new();
        account_headers.insert(HeaderName::from_static("authorization"), HeaderValue::from_static("Bearer token123"));
        account_headers.insert(HeaderName::from_static("chatgpt-account-id"), HeaderValue::from_static("acc_org_123"));
        account_headers.insert(HeaderName::from_static("x-openai-fedramp"), HeaderValue::from_static("true"));
        account_headers.insert(HeaderName::from_static("x-codex-window-id"), HeaderValue::from_static("thread_123:0"));
        account_headers.insert(HeaderName::from_static("x-codex-turn-metadata"), HeaderValue::from_static("{}"));
        account_headers.insert(HeaderName::from_static("traceparent"), HeaderValue::from_static("00-trace-01"));
        account_headers.insert(HeaderName::from_static("x-oai-attestation"), HeaderValue::from_static("attest_token"));
        account_headers.insert(HeaderName::from_static("x-custom-leak"), HeaderValue::from_static("drop_me"));

        // Account path (e.g. /wham/usage, /api/codex/usage, /status):
        sanitize_and_inject_headers(&mut account_headers, "seed", None, None, "salt", Some("0.1.183"), 0, false);

        assert!(account_headers.get("authorization").is_some());
        assert!(account_headers.get("chatgpt-account-id").is_some());
        assert!(account_headers.get("x-openai-fedramp").is_some());
        assert!(account_headers.get("user-agent").is_some());
        // All unallowed x- headers and tracking headers MUST be stripped on account path
        assert!(account_headers.get("x-codex-window-id").is_none());
        assert!(account_headers.get("x-codex-turn-metadata").is_none());
        assert!(account_headers.get("x-custom-leak").is_none());
        assert!(account_headers.get("traceparent").is_none());
        assert!(account_headers.get("x-oai-attestation").is_none());

        let mut inference_headers = HeaderMap::new();
        inference_headers.insert(HeaderName::from_static("authorization"), HeaderValue::from_static("Bearer token123"));
        inference_headers.insert(HeaderName::from_static("chatgpt-account-id"), HeaderValue::from_static("acc_org_123"));
        inference_headers.insert(HeaderName::from_static("originator"), HeaderValue::from_static("codex_cli_rs"));
        inference_headers.insert(HeaderName::from_static("session-id"), HeaderValue::from_static("sess_123"));
        inference_headers.insert(HeaderName::from_static("thread-id"), HeaderValue::from_static("thread_123"));
        inference_headers.insert(HeaderName::from_static("x-codex-window-id"), HeaderValue::from_static("thread_123:0"));
        inference_headers.insert(HeaderName::from_static("x-codex-turn-state"), HeaderValue::from_static("state_token"));
        inference_headers.insert(HeaderName::from_static("traceparent"), HeaderValue::from_static("00-trace-01"));
        inference_headers.insert(HeaderName::from_static("x-oai-attestation"), HeaderValue::from_static("attest_token"));

        // Inference path (e.g. /responses, /responses/compact):
        sanitize_and_inject_headers(&mut inference_headers, "seed", None, None, "salt", Some("0.1.183"), 0, true);

        assert!(inference_headers.get("authorization").is_some());
        assert!(inference_headers.get("chatgpt-account-id").is_some());
        assert!(inference_headers.get("originator").is_some());
        assert!(inference_headers.get("session-id").is_some());
        assert!(inference_headers.get("thread-id").is_some());
        assert!(inference_headers.get("x-codex-window-id").is_some());
        assert!(inference_headers.get("x-codex-turn-state").is_some());
        assert!(inference_headers.get("x-codex-turn-metadata").is_some());
        // Tracking & attestation stripped
        assert!(inference_headers.get("traceparent").is_none());
        assert!(inference_headers.get("x-oai-attestation").is_none());
    }
}
