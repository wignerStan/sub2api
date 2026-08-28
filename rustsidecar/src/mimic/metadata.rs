//! Client metadata sanitization, fingerprint divergence verification, and workspace path normalization.

use serde_json::{json, Value};

use super::identity::sanitize_workspace_path;
use super::types::{
    ConvergedIdentity, MimicError, UnknownFieldPolicy, ALLOWED_FLAT_CLIENT_METADATA_KEYS,
    EXPLICITLY_STRIPPED_ATTESTATION_NAMES, EXPLICITLY_STRIPPED_TRACE_AND_TRACKING_NAMES,
    UPSTREAM_EXPLICITLY_STRIPPED_FLAT_CLIENT_METADATA_KEYS,
};

/// Sanitize client_metadata in place:
/// 1. Allowed keys (in ALLOWED_FLAT_CLIENT_METADATA_KEYS): kept.
/// 2. Explicitly stripped keys (in UPSTREAM_EXPLICITLY_STRIPPED_FLAT_CLIENT_METADATA_KEYS / EXPLICITLY_STRIPPED_*): stripped normally.
/// 3. Unknown extra field: follows UnknownFieldPolicy (Forbidden returns 403, Strip drops the field).
/// 4. Open Schema on nested x-codex-turn-metadata: ONLY sanitize workspaces (strip git remotes & normalize path).
pub fn sanitize_client_metadata(
    metadata: &mut Value,
    identity: &ConvergedIdentity,
    policy: UnknownFieldPolicy,
) -> Result<(), MimicError> {
    if let Value::Object(ref mut map) = metadata {
        let mut keys_to_remove: Vec<String> = Vec::new();

        for key in map.keys() {
            if ALLOWED_FLAT_CLIENT_METADATA_KEYS.contains(&key.as_str()) {
                // In allowlist -> keep
            } else if UPSTREAM_EXPLICITLY_STRIPPED_FLAT_CLIENT_METADATA_KEYS.contains(&key.as_str())
                || EXPLICITLY_STRIPPED_TRACE_AND_TRACKING_NAMES.contains(&key.as_str())
                || EXPLICITLY_STRIPPED_ATTESTATION_NAMES.contains(&key.as_str())
            {
                // In explicit strip list -> strip normally
                keys_to_remove.push(key.clone());
            } else {
                // Unknown extra field: follow policy
                match policy {
                    UnknownFieldPolicy::Forbidden => {
                        return Err(MimicError::ForbiddenMetadataKey(key.clone()));
                    }
                    UnknownFieldPolicy::Strip => {
                        keys_to_remove.push(key.clone());
                    }
                }
            }
        }

        for key in keys_to_remove {
            map.remove(&key);
        }

        // 4. Validate fingerprint consistency across flat client_metadata fields (Do not align; reject divergence with 403)
        let flat_session = map.get("session_id").and_then(|v| v.as_str()).map(|s| s.to_string());
        let flat_thread = map.get("thread_id").and_then(|v| v.as_str()).map(|s| s.to_string());
        let flat_install = map.get("x-codex-installation-id").or_else(|| map.get("installation_id")).and_then(|v| v.as_str()).map(|s| s.to_string());
        let flat_parent_thread = map.get("x-codex-parent-thread-id").or_else(|| map.get("parent_thread_id")).and_then(|v| v.as_str()).map(|s| s.to_string());
        let flat_subagent = map.get("x-openai-subagent").or_else(|| map.get("subagent_header")).and_then(|v| v.as_str()).map(|s| s.to_string());
        let flat_win_id = map.get("window_id").or_else(|| map.get("x-codex-window-id")).and_then(|v| v.as_str()).map(|s| s.to_string());
        let flat_win_num = map.get("window_number").and_then(|v| {
            v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
        });
        let flat_prev_win = map.get("previous_window_id").or_else(|| map.get("context_window_id")).and_then(|v| v.as_str()).map(|s| s.to_string());

        // Validate parent_thread_id UUID format if present
        if let Some(ref p_th) = flat_parent_thread {
            if uuid::Uuid::parse_str(p_th).is_err() {
                return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                    "flat parent_thread_id '{p_th}' is not a valid UUID"
                )));
            }
        }

        if let Some(ref win_id) = flat_win_id {
            if let Some(pos) = win_id.rfind(':') {
                let win_tid = &win_id[..pos];
                let win_num_str = &win_id[pos + 1..];
                if let Ok(parsed_num) = win_num_str.trim().parse::<u64>() {
                    if let Some(ref th) = flat_thread {
                        if th != win_tid {
                            return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                                "flat thread_id '{th}' diverges from window_id prefix '{win_tid}'"
                            )));
                        }
                    }
                    if let Some(wnum) = flat_win_num {
                        if wnum != parsed_num {
                            return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                                "flat window_number '{wnum}' diverges from window_id suffix '{parsed_num}'"
                            )));
                        }
                    }
                    if let Some(ref prev) = flat_prev_win {
                        if parsed_num == 0 {
                            return Err(MimicError::ForbiddenDivergingFingerprint(
                                "previous_window_id cannot exist when window_number is 0".to_string(),
                            ));
                        }
                        let exp_prev = format!("{}:{}", win_tid, parsed_num - 1);
                        if prev != &exp_prev {
                            return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                                "flat previous_window_id '{prev}' diverges from expected '{exp_prev}'"
                            )));
                        }
                    }
                } else {
                    return Err(MimicError::ForbiddenDivergingFingerprint(
                        "window_id does not have a valid numeric suffix".to_string(),
                    ));
                }
            } else {
                return Err(MimicError::ForbiddenDivergingFingerprint(
                    "window_id does not follow <thread_id>:<window_number> format".to_string(),
                ));
            }
        }

        // 5. Open Schema on nested x-codex-turn-metadata: sanitize workspaces, validate divergence
        if let Some(turn_meta_val) = map.get_mut("x-codex-turn-metadata") {
            if let Some(turn_meta_str) = turn_meta_val.as_str() {
                if let Ok(mut tm) = serde_json::from_str::<Value>(turn_meta_str) {
                    if let Some(tm_map) = tm.as_object_mut() {
                        if let Some(tm_sess) = tm_map.get("session_id").and_then(|v| v.as_str()) {
                            if let Some(ref fsess) = flat_session {
                                if tm_sess != fsess {
                                    return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                                        "turn_metadata session_id '{tm_sess}' diverges from flat session_id '{fsess}'"
                                    )));
                                }
                            }
                        }
                        if let Some(tm_th) = tm_map.get("thread_id").and_then(|v| v.as_str()) {
                            if let Some(ref fth) = flat_thread {
                                if tm_th != fth {
                                    return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                                        "turn_metadata thread_id '{tm_th}' diverges from flat thread_id '{fth}'"
                                    )));
                                }
                            }
                        }
                        if let Some(tm_inst) = tm_map.get("installation_id").and_then(|v| v.as_str()) {
                            if let Some(ref finst) = flat_install {
                                if tm_inst != finst {
                                    return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                                        "turn_metadata installation_id '{tm_inst}' diverges from flat installation_id '{finst}'"
                                    )));
                                }
                            }
                        }
                        if let Some(tm_parent) = tm_map.get("parent_thread_id").and_then(|v| v.as_str()) {
                            if let Some(ref fparent) = flat_parent_thread {
                                if tm_parent != fparent {
                                    return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                                        "turn_metadata parent_thread_id '{tm_parent}' diverges from flat parent_thread_id '{fparent}'"
                                    )));
                                }
                            }
                        }
                        if let Some(tm_sub) = tm_map.get("subagent_header").and_then(|v| v.as_str()) {
                            if let Some(ref fsub) = flat_subagent {
                                if tm_sub != fsub {
                                    return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                                        "turn_metadata subagent_header '{tm_sub}' diverges from flat subagent '{fsub}'"
                                    )));
                                }
                            }
                        }
                        if let Some(tm_win) = tm_map.get("window_id").and_then(|v| v.as_str()) {
                            if let Some(ref fwin) = flat_win_id {
                                if tm_win != fwin {
                                    return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                                        "turn_metadata window_id '{tm_win}' diverges from flat window_id '{fwin}'"
                                    )));
                                }
                            }
                        }
                        if let Some(tm_wnum) = tm_map.get("window_number").and_then(|v| v.as_u64()) {
                            if let Some(fwnum) = flat_win_num {
                                if tm_wnum != fwnum {
                                    return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                                        "turn_metadata window_number '{tm_wnum}' diverges from flat window_number '{fwnum}'"
                                    )));
                                }
                            }
                            if let Some(tm_prev) = tm_map.get("previous_window_id").and_then(|v| v.as_str()) {
                                if tm_wnum == 0 {
                                    return Err(MimicError::ForbiddenDivergingFingerprint(
                                        "turn_metadata previous_window_id cannot exist when window_number is 0".to_string(),
                                    ));
                                }
                                let tm_th = tm_map.get("thread_id").and_then(|v| v.as_str()).unwrap_or("");
                                if !tm_th.is_empty() {
                                    let exp_prev = format!("{}:{}", tm_th, tm_wnum - 1);
                                    if tm_prev != exp_prev {
                                        return Err(MimicError::ForbiddenDivergingFingerprint(format!(
                                            "turn_metadata previous_window_id '{tm_prev}' diverges from expected '{exp_prev}'"
                                        )));
                                    }
                                }
                            }
                        }

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
    Ok(())
}
