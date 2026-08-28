//! HTTP and WebSocket request headers sanitization, normalization, and fingerprint verification.

use axum::http::{HeaderMap, HeaderName, HeaderValue};

use super::identity::sanitize_workspace_path;
use super::metadata::{parse_turn_metadata_object, parse_wire_u64};
use super::types::{
    ConvergedIdentity, MimicError, UnknownFieldPolicy, ALLOWED_ACCOUNT_X_HEADERS,
    ALLOWED_RESPONSES_X_HEADERS, EXPLICITLY_STRIPPED_ATTESTATION_NAMES,
    EXPLICITLY_STRIPPED_ROUTING_CONTROL_NAMES, EXPLICITLY_STRIPPED_TRACE_AND_TRACKING_NAMES,
    UPSTREAM_EXPLICITLY_STRIPPED_ACCOUNT_X_HEADERS,
    UPSTREAM_EXPLICITLY_STRIPPED_RESPONSES_X_HEADERS,
};

/// Check if a non-x- header matches explicit leak / tracking channel enums.
pub fn is_leaked_non_x_header(key: &str) -> bool {
    EXPLICITLY_STRIPPED_ATTESTATION_NAMES.contains(&key)
        || EXPLICITLY_STRIPPED_TRACE_AND_TRACKING_NAMES.contains(&key)
}

/// Sanitize and normalize outbound HTTP request headers (test helper for default non-compact paths).
#[cfg(test)]
pub fn sanitize_and_inject_headers(
    headers: &mut HeaderMap,
    seed: &str,
    client_session_id: Option<&str>,
    custom_device_id: Option<&str>,
    salt: &str,
    agent_version: Option<&str>,
    window_number: u64,
    is_responses_path: bool,
    policy: UnknownFieldPolicy,
) -> Result<(), MimicError> {
    sanitize_and_inject_headers_for_request(
        headers,
        seed,
        client_session_id,
        custom_device_id,
        salt,
        agent_version,
        window_number,
        is_responses_path,
        false,
        policy,
    )
}

/// Request-aware variant used by the tunnel so compact JSON requests are not
/// forced onto the normal Responses SSE transport.
pub fn sanitize_and_inject_headers_for_request(
    headers: &mut HeaderMap,
    seed: &str,
    client_session_id: Option<&str>,
    custom_device_id: Option<&str>,
    salt: &str,
    agent_version: Option<&str>,
    window_number: u64,
    is_responses_path: bool,
    is_compact_path: bool,
    policy: UnknownFieldPolicy,
) -> Result<(), MimicError> {
    let identity = ConvergedIdentity::new(
        seed,
        client_session_id,
        custom_device_id,
        salt,
        agent_version,
        window_number,
    );

    // 0. Normal Responses requests stream SSE. /responses/compact is a
    // JSON request/response and must retain the JSON Accept contract.
    if is_responses_path {
        if is_compact_path {
            headers.insert(
                axum::http::header::ACCEPT,
                HeaderValue::from_static("application/json"),
            );
        } else {
            if let Some(accept_val) = headers
                .get(axum::http::header::ACCEPT)
                .and_then(|v| v.to_str().ok())
            {
                let lower = accept_val.to_ascii_lowercase();
                if lower.contains("application/json") && !lower.contains("text/event-stream") {
                    return Err(MimicError::ForbiddenAcceptHeader(accept_val.to_string()));
                }
            }
            headers.insert(
                axum::http::header::ACCEPT,
                HeaderValue::from_static("text/event-stream"),
            );
        }
    }

    let (allowed_x_headers, stripped_x_headers) = if is_responses_path {
        (
            ALLOWED_RESPONSES_X_HEADERS,
            UPSTREAM_EXPLICITLY_STRIPPED_RESPONSES_X_HEADERS,
        )
    } else {
        (
            ALLOWED_ACCOUNT_X_HEADERS,
            UPSTREAM_EXPLICITLY_STRIPPED_ACCOUNT_X_HEADERS,
        )
    };

    let mut keys_to_remove: Vec<HeaderName> = Vec::new();

    for name in headers.keys() {
        let key = name.as_str();
        if key.starts_with("x-") {
            if allowed_x_headers.contains(&key) {
                // In allowlist -> keep
            } else if stripped_x_headers.contains(&key)
                || EXPLICITLY_STRIPPED_ATTESTATION_NAMES.contains(&key)
                || EXPLICITLY_STRIPPED_ROUTING_CONTROL_NAMES.contains(&key)
                || EXPLICITLY_STRIPPED_TRACE_AND_TRACKING_NAMES.contains(&key)
            {
                // In explicit strip list -> strip normally
                keys_to_remove.push(name.clone());
            } else {
                // Unknown extra x- header: follow policy
                match policy {
                    UnknownFieldPolicy::Forbidden => {
                        return Err(MimicError::ForbiddenHeader(key.to_string()));
                    }
                    UnknownFieldPolicy::Strip => {
                        keys_to_remove.push(name.clone());
                    }
                }
            }
        } else if is_leaked_non_x_header(key) {
            // Non-x header in explicit strip list -> strip normally
            keys_to_remove.push(name.clone());
        }
    }

    for key in keys_to_remove {
        headers.remove(key);
    }

    // 2. Normalize or inject User-Agent header to strictly match simulated OS/arch
    let os_display = if identity.os == "darwin" {
        "Darwin"
    } else {
        "Linux"
    };
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

    // 3. For Inference / Responses paths only: validate required headers and reject divergence with 403
    if is_responses_path {
        // Enforce required session-id header
        let session_val = match headers
            .get("session-id")
            .or_else(|| headers.get("session_id"))
            .and_then(|v| v.to_str().ok())
        {
            Some(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => {
                return Err(MimicError::ForbiddenMissingFingerprint(
                    "session-id header is required on responses path".to_string(),
                ));
            }
        };

        if let (Some(s1), Some(s2)) = (
            headers.get("session-id").and_then(|v| v.to_str().ok()),
            headers.get("session_id").and_then(|v| v.to_str().ok()),
        ) {
            if s1.trim() != s2.trim() {
                return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                    "session-id '{s1}' and session_id '{s2}' headers diverge"
                )));
            }
        }

        // Enforce required x-codex-window-id header
        let win_val = match headers
            .get("x-codex-window-id")
            .and_then(|v| v.to_str().ok())
        {
            Some(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => {
                return Err(MimicError::ForbiddenMissingFingerprint(
                    "x-codex-window-id header is required on responses path".to_string(),
                ));
            }
        };

        let (win_tid, win_num) = if let Some(pos) = win_val.rfind(':') {
            let tid = &win_val[..pos];
            let num_str = &win_val[pos + 1..];
            match num_str.trim().parse::<u64>() {
                Ok(n) => (tid.to_string(), n),
                Err(_) => {
                    return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                        "x-codex-window-id header '{win_val}' has non-numeric window suffix"
                    )));
                }
            }
        } else {
            return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                "x-codex-window-id header '{win_val}' does not follow <thread_id>:<window_number> format"
            )));
        };

        // Check thread-id header divergence if present
        if let Some(th_hdr) = headers
            .get("thread-id")
            .or_else(|| headers.get("thread_id"))
            .and_then(|v| v.to_str().ok())
        {
            if th_hdr.trim() != win_tid {
                return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                    "thread-id header '{th_hdr}' diverges from x-codex-window-id thread prefix '{win_tid}'"
                )));
            }
        }

        // Normalize canonical header casing
        headers.remove("session_id");
        if let Ok(v) = HeaderValue::from_str(&session_val) {
            headers.insert(HeaderName::from_static("session-id"), v);
        }
        headers.remove("thread_id");
        if let Ok(v) = HeaderValue::from_str(&win_tid) {
            headers.insert(HeaderName::from_static("thread-id"), v);
        }
        if let Ok(v) = HeaderValue::from_str(&win_val) {
            headers.insert(HeaderName::from_static("x-codex-window-id"), v);
        }

        // Ensure originator and version headers
        headers.insert(
            HeaderName::from_static("originator"),
            HeaderValue::from_static("codex_cli_rs"),
        );
        if let Ok(v) = HeaderValue::from_str(&identity.client_version) {
            headers.insert(HeaderName::from_static("version"), v);
        }

        let hdr_parent_thread = headers
            .get("x-codex-parent-thread-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string());
        if let Some(ref p_th) = hdr_parent_thread {
            if uuid::Uuid::parse_str(p_th).is_err() {
                return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                    "x-codex-parent-thread-id header '{p_th}' is not a valid UUID"
                )));
            }
        }
        let hdr_subagent = headers
            .get("x-openai-subagent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string());

        // Validate or generate valid UUID for x-client-request-id
        let needs_client_req_id = match headers
            .get("x-client-request-id")
            .and_then(|v| v.to_str().ok())
        {
            Some(s) => uuid::Uuid::parse_str(s).is_err(),
            None => true,
        };
        if needs_client_req_id {
            let req_id = uuid::Uuid::new_v4().to_string();
            if let Ok(v) = HeaderValue::from_str(&req_id) {
                headers.insert(HeaderName::from_static("x-client-request-id"), v);
            }
        }

        // Check divergence in x-codex-turn-metadata if present
        if let Some(turn_meta_val) = headers.get_mut("x-codex-turn-metadata") {
            let turn_meta_str = turn_meta_val.to_str().map_err(|_| {
                MimicError::InvalidJson(
                    "x-codex-turn-metadata header must contain UTF-8 JSON".to_string(),
                )
            })?;
            let mut tm = parse_turn_metadata_object(turn_meta_str)?;
            let tm_map = tm
                .as_object_mut()
                .expect("parse_turn_metadata_object returned a non-object");

            if let Some(tm_sess) = tm_map.get("session_id").and_then(|v| v.as_str()) {
                if tm_sess != session_val {
                    return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                        "x-codex-turn-metadata session_id '{tm_sess}' diverges from session-id header '{session_val}'"
                    )));
                }
            }
            if let Some(tm_th) = tm_map.get("thread_id").and_then(|v| v.as_str()) {
                if tm_th != win_tid {
                    return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                        "x-codex-turn-metadata thread_id '{tm_th}' diverges from x-codex-window-id prefix '{win_tid}'"
                    )));
                }
            }
            if let Some(tm_parent) = tm_map.get("parent_thread_id").and_then(|v| v.as_str()) {
                if let Some(ref hp) = hdr_parent_thread {
                    if tm_parent != hp {
                        return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                            "x-codex-turn-metadata parent_thread_id '{tm_parent}' diverges from header '{hp}'"
                        )));
                    }
                }
            }
            if let Some(tm_sub) = tm_map.get("subagent_header").and_then(|v| v.as_str()) {
                if let Some(ref hs) = hdr_subagent {
                    if tm_sub != hs {
                        return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                            "x-codex-turn-metadata subagent_header '{tm_sub}' diverges from header '{hs}'"
                        )));
                    }
                }
            }
            if let Some(tm_win) = tm_map.get("window_id").and_then(|v| v.as_str()) {
                if tm_win != win_val {
                    return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                        "x-codex-turn-metadata window_id '{tm_win}' diverges from x-codex-window-id header '{win_val}'"
                    )));
                }
            }
            if let Some(tm_wnum_value) = tm_map.get("window_number") {
                let tm_wnum = parse_wire_u64(tm_wnum_value).ok_or_else(|| {
                    MimicError::ForbiddenDivergingFingerprint(
                        "x-codex-turn-metadata window_number is not an unsigned integer"
                            .to_string(),
                    )
                })?;
                if tm_wnum != win_num {
                    return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                        "x-codex-turn-metadata window_number '{tm_wnum}' diverges from x-codex-window-id suffix '{win_num}'"
                    )));
                }
            }
            if let Some(tm_prev) = tm_map.get("previous_window_id").and_then(|v| v.as_str()) {
                if win_num == 0 {
                    return Err(MimicError::ForbiddenDivergingFingerprint(
                        "x-codex-turn-metadata previous_window_id cannot exist when window_number is 0"
                            .to_string(),
                    ));
                }
                let exp_prev = format!("{}:{}", win_tid, win_num - 1);
                if tm_prev != exp_prev {
                    return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                        "x-codex-turn-metadata previous_window_id '{tm_prev}' diverges from expected '{exp_prev}'"
                    )));
                }
            }

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

            let sanitized_str = serde_json::to_string(&tm)
                .map_err(|error| MimicError::InvalidJson(error.to_string()))?;
            *turn_meta_val =
                HeaderValue::from_bytes(sanitized_str.as_bytes()).map_err(|error| {
                    MimicError::InvalidJson(format!(
                        "x-codex-turn-metadata cannot be encoded as an HTTP header: {error}"
                    ))
                })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod hardening_tests {
    use super::*;

    const THREAD_ID: &str = "11111111-1111-4111-8111-111111111111";

    fn response_headers(turn_metadata: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("session-id", HeaderValue::from_static("session-1"));
        headers.insert(
            "x-codex-window-id",
            HeaderValue::from_static("11111111-1111-4111-8111-111111111111:2"),
        );
        headers.insert(
            "x-codex-turn-metadata",
            HeaderValue::from_str(turn_metadata).expect("valid test header"),
        );
        headers
    }

    fn sanitize(headers: &mut HeaderMap) -> Result<(), MimicError> {
        sanitize_and_inject_headers_for_request(
            headers,
            "seed",
            Some("session-1"),
            None,
            "salt",
            Some("0.1.183"),
            2,
            true,
            false,
            UnknownFieldPolicy::Forbidden,
        )
    }

    #[test]
    fn rejects_malformed_turn_metadata_header() {
        let mut headers = response_headers("{");
        let err = sanitize(&mut headers).unwrap_err();
        assert!(matches!(err, MimicError::InvalidJson(_)));
    }

    #[test]
    fn validates_string_encoded_turn_metadata_window_number() {
        let mismatch = serde_json::json!({
            "session_id": "session-1",
            "thread_id": THREAD_ID,
            "window_id": format!("{THREAD_ID}:2"),
            "window_number": "3"
        })
        .to_string();
        let mut headers = response_headers(&mismatch);
        let err = sanitize(&mut headers).unwrap_err();
        assert!(matches!(err, MimicError::ForbiddenDivergingFingerprint(_)));

        let matching = serde_json::json!({
            "session_id": "session-1",
            "thread_id": THREAD_ID,
            "window_id": format!("{THREAD_ID}:2"),
            "window_number": "2"
        })
        .to_string();
        let mut headers = response_headers(&matching);
        sanitize(&mut headers).unwrap();
    }
}

#[cfg(test)]
mod routing_hint_tests {
    use super::*;

    #[test]
    fn strips_routing_hint_before_sidecar_egress() {
        const THREAD_ID: &str = "11111111-1111-4111-8111-111111111111";
        let mut headers = HeaderMap::new();
        headers.insert("session-id", HeaderValue::from_static("session-1"));
        headers.insert("thread-id", HeaderValue::from_static(THREAD_ID));
        headers.insert(
            "x-codex-window-id",
            HeaderValue::from_static("11111111-1111-4111-8111-111111111111:0"),
        );
        headers.insert(
            "x-codex-routing-hint",
            HeaderValue::from_static("client-controlled-route"),
        );

        sanitize_and_inject_headers_for_request(
            &mut headers,
            "seed",
            Some("session-1"),
            None,
            "salt",
            Some("0.1.183"),
            0,
            true,
            false,
            UnknownFieldPolicy::Forbidden,
        )
        .expect("routing hint is explicitly stripped, not rejected");

        assert!(headers.get("x-codex-routing-hint").is_none());
    }
}
