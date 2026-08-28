//! Deterministic UUID derivation, client version extraction, window number extraction, and workspace path sanitization.

use axum::http::HeaderMap;
use serde_json::Value;

use super::types::ConvergedIdentity;

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
    if let Some(v) = headers
        .get("x-codex-client-version")
        .or_else(|| headers.get("x-client-version"))
    {
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
        if let Some(w_val) = meta
            .get("window_id")
            .or_else(|| meta.get("x-codex-window-id"))
            .and_then(|v| v.as_str())
        {
            if let Some(pos) = w_val.rfind(':') {
                if let Ok(num) = w_val[pos + 1..].trim().parse::<u64>() {
                    return num;
                }
            }
        }
        if let Some(turn_meta_str) = meta.get("x-codex-turn-metadata").and_then(|v| v.as_str()) {
            if let Ok(tm) = serde_json::from_str::<Value>(turn_meta_str) {
                if let Some(num) = tm.get("window_number").and_then(|v| v.as_u64()) {
                    return num;
                }
                if let Some(w_val) = tm.get("window_id").and_then(|v| v.as_str()) {
                    if let Some(pos) = w_val.rfind(':') {
                        if let Ok(num) = w_val[pos + 1..].trim().parse::<u64>() {
                            return num;
                        }
                    }
                }
            }
        }
    }
    0
}

/// Sanitize workspace root path to ensure consistency with simulated workstation OS
/// while eliminating private physical paths and usernames.
pub fn sanitize_workspace_path(raw_path: &str, identity: &ConvergedIdentity) -> String {
    let normalized = raw_path.replace('\\', "/");
    let proj_name = normalized
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
