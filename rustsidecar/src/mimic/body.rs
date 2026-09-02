//! Request body and WebSocket frame validation plus metadata leak sanitization.

use serde_json::Value;

use super::identity::extract_window_number;
use super::metadata::sanitize_client_metadata;
use super::types::{ConvergedIdentity, MimicError, UnknownFieldPolicy};

/// Transform an HTTP JSON body without changing the identity already established by the Go gateway.
pub fn transform_request_body(
    body_bytes: &[u8],
    seed: &str,
    custom_device_id: Option<&str>,
    salt: &str,
    agent_version: Option<&str>,
    header_window_number: Option<u64>,
    policy: UnknownFieldPolicy,
) -> Result<Option<Vec<u8>>, MimicError> {
    if body_bytes.is_empty() {
        return Ok(None);
    }
    let mut val: Value = match serde_json::from_slice(body_bytes) {
        Ok(v) => v,
        Err(_) => return Ok(None), // Non-JSON, leave unmodified
    };

    let obj = match val.as_object_mut() {
        Some(obj) => obj,
        None => return Ok(None),
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

    let mut modified = false;

    // If client_metadata is present, validate, sanitize, and converge
    if let Some(metadata) = obj.get_mut("client_metadata") {
        sanitize_client_metadata(metadata, &identity, policy)?;
        modified = true;
    }

    if modified {
        serde_json::to_vec(&val)
            .map(Some)
            .map_err(|e| MimicError::InvalidJson(e.to_string()))
    } else {
        Ok(None)
    }
}

/// Transform a WebSocket text frame (e.g. `response.create`) without re-converging identity.
pub fn transform_ws_frame(
    frame_text: &str,
    seed: &str,
    custom_device_id: Option<&str>,
    salt: &str,
    agent_version: Option<&str>,
    header_window_number: Option<u64>,
    policy: UnknownFieldPolicy,
) -> Result<Option<String>, MimicError> {
    if frame_text.is_empty() {
        return Ok(None);
    }
    let mut val: Value = match serde_json::from_str(frame_text) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    let obj = match val.as_object_mut() {
        Some(obj) => obj,
        None => return Ok(None),
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
        let meta_opt = obj
            .get("client_metadata")
            .or_else(|| obj.get("response").and_then(|r| r.get("client_metadata")));
        extract_window_number(obj.get("window_id").and_then(|v| v.as_str()), meta_opt)
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
        sanitize_client_metadata(metadata, &identity, policy)?;
        modified = true;
    }
    if let Some(response) = obj.get_mut("response").and_then(|r| r.as_object_mut()) {
        if let Some(metadata) = response.get_mut("client_metadata") {
            sanitize_client_metadata(metadata, &identity, policy)?;
            modified = true;
        }
    }

    if modified {
        serde_json::to_string(&val)
            .map(Some)
            .map_err(|e| MimicError::InvalidJson(e.to_string()))
    } else {
        Ok(None)
    }
}
