//! sub2api-sidecar: TLS-disguise & Account Mimic Egress Shim for OpenAI OAuth Traffic.
//!
//! Go forwards official OAuth hosts (chatgpt.com / chat.openai.com / auth.openai.com).
//! This sidecar handles:
//! 1. Direct PostgreSQL DB lookup with Moka in-memory cache and PG LISTEN/NOTIFY invalidation.
//! 2. Realistic workstation client simulation (OS, arch, cwd, git branch, terminal, exact agent version).
//! 3. Exact protocol-fidelity window_id/window_number preservation across compactions.
//! 4. Gateway-established identity validation, header normalization, and metadata leak sanitization.
//! 5. Official Codex rustls 0.23 + aws-lc-rs TLS disguise.
//! 6. AES-256-GCM E2EE loopback security.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ws::{CloseFrame as AxumCloseFrame, Message as AxumMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{Request, State};
use axum::http::header::{ACCEPT_ENCODING, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, HOST, TRANSFER_ENCODING, UPGRADE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::Router;
use codex_http_client::OutboundProxyPolicy;
use codex_http_client::{HttpClient, HttpClientBuilder};
use codex_websocket_client::{WebSocketConnector, WebSocketTlsMode};
use futures::{SinkExt, StreamExt};
use tokio::sync::RwLock;
use tokio_tungstenite::tungstenite::Error as TsError;
use tokio_tungstenite::tungstenite::Message as TsMessage;
use tokio_tungstenite::tungstenite::handshake::client::Request as TsRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use base64::Engine;

mod db;
mod e2ee;
mod mimic;
mod upstream;

use db::{AccountProfile, DbProxyResolver};
use mimic::{MimicError, UnknownFieldPolicy};
use upstream::allowed_codex_upstream_url;

const E2EE_HEADER: &str = "x-s2s-enc";
const CONTROL_PREFIX: &str = "x-upstream-";
const TOKEN_HEADER: &str = "x-s2s-token";
const UPSTREAM_URL_HEADER: &str = "x-upstream-url";
const UPSTREAM_PROXY_HEADER: &str = "x-upstream-proxy";
const ACCOUNT_ID_HEADER: &str = "x-account-id";

fn is_hop_by_hop(name: &HeaderName) -> bool {
    let name = name.as_str().to_ascii_lowercase();
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
    )
}

#[derive(Clone)]
struct AppState {
    token: String,
    deployment_salt: String,
    unknown_field_policy: UnknownFieldPolicy,
    clients: Arc<RwLock<HashMap<String, HttpClient>>>,
    db: DbProxyResolver,
    debug: bool,
}

impl AppState {
    async fn client_for(&self, proxy: Option<String>) -> Result<HttpClient, Response> {
        let key = proxy.clone().unwrap_or_default();
        if let Some(client) = self.clients.read().await.get(&key) {
            return Ok(client.clone());
        }
        let mut builder = HttpClientBuilder::new()
            .with_rustls_tls()
            .without_request_logging();
        if let Some(ref url) = proxy {
            builder = builder.with_proxy(url.clone());
        }
        let client = builder.build_direct().map_err(|error| {
            tracing::warn!(error = %error, "proxy client build failed");
            StatusCode::BAD_GATEWAY.into_response()
        })?;
        self.clients.write().await.insert(key, client.clone());
        Ok(client)
    }
}

fn check_token(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    match headers.get(TOKEN_HEADER).and_then(|v| v.to_str().ok()) {
        Some(token) if token == state.token => Ok(()),
        _ => Err(StatusCode::UNAUTHORIZED.into_response()),
    }
}

async fn resolve_account_and_proxy(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(AccountProfile, Option<String>), Response> {
    let mut resolved_profile = None;
    let mut resolved_proxy = None;

    if let Some(val) = headers.get(ACCOUNT_ID_HEADER).or_else(|| headers.get("x-upstream-account-id")) {
        if let Ok(account_id_str) = val.to_str() {
            if let Ok(account_id) = account_id_str.trim().parse::<i64>() {
                if state.db.is_configured() {
                    match state.db.resolve_account_profile(account_id).await {
                        Ok(Some(profile)) => {
                            if let Some(ref p_url) = profile.proxy_url {
                                resolved_proxy = Some(normalize_proxy_url(p_url.clone())?);
                            }
                            resolved_profile = Some(profile);
                        }
                        Ok(None) => {}
                        Err(err) => {
                            tracing::warn!(account_id, error = %err, "db account lookup failed, falling back to headers");
                        }
                    }
                }
                if resolved_profile.is_none() {
                    resolved_profile = Some(AccountProfile {
                        account_id,
                        proxy_url: None,
                        fingerprint_seed: format!("account:{account_id}"),
                        custom_installation_id: None,
                    });
                }
            }
        }
    }

    if resolved_proxy.is_none() {
        resolved_proxy = decode_proxy(headers)?;
    }

    let profile = resolved_profile.unwrap_or_else(|| AccountProfile {
        account_id: 0,
        proxy_url: resolved_proxy.clone(),
        fingerprint_seed: "default_seed".to_string(),
        custom_installation_id: None,
    });

    Ok((profile, resolved_proxy))
}

fn decode_proxy(headers: &HeaderMap) -> Result<Option<String>, Response> {
    let Some(value) = headers.get(UPSTREAM_PROXY_HEADER) else {
        return Ok(None);
    };
    let value_str = value
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value_str)
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
    let proxy_url = String::from_utf8(decoded)
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
    normalize_proxy_url(proxy_url).map(Some)
}

fn normalize_proxy_url(proxy_url: String) -> Result<String, Response> {
    let parsed = reqwest::Url::parse(&proxy_url).map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
    match parsed.scheme() {
        "http" | "https" | "socks5" | "socks5h" => {}
        _ => return Err(StatusCode::BAD_REQUEST.into_response()),
    }
    // Proxy selectors are rebuilt by the authenticated Go loopback client or
    // loaded from the local account DB. Loopback proxies are therefore valid
    // and common (Clash, SSH tunnels, local SOCKS forwarders).
    if parsed.host_str().is_none() {
        return Err(StatusCode::BAD_REQUEST.into_response());
    }
    Ok(parsed.to_string())
}

#[cfg(test)]
mod proxy_url_tests {
    use super::*;

    #[test]
    fn allows_trusted_loopback_proxies() {
        for raw in [
            "http://127.0.0.1:8080",
            "socks5h://localhost:1080",
            "socks5://[::1]:1080",
        ] {
            assert!(normalize_proxy_url(raw.to_string()).is_ok(), "{raw}");
        }
    }

    #[test]
    fn rejects_invalid_proxy_targets() {
        for raw in ["ftp://127.0.0.1:21", "http://", "://bad"] {
            assert!(normalize_proxy_url(raw.to_string()).is_err(), "{raw}");
        }
    }
}

fn classify_upstream_target(target: &str) -> (bool, bool) {
    let path = reqwest::Url::parse(target)
        .ok()
        .map(|url| url.path().trim_end_matches('/').to_ascii_lowercase())
        .unwrap_or_default();
    let is_compact_path =
        path.ends_with("/responses/compact") || path.ends_with("/codex/compact");
    let is_responses_path = is_compact_path
        || path.contains("/responses")
        || path.contains("/completions")
        || path.contains("/chat/");
    (is_responses_path, is_compact_path)
}

fn forwarded_headers(
    headers: &HeaderMap,
    profile: &AccountProfile,
    salt: &str,
    is_responses_path: bool,
    is_compact_path: bool,
    policy: UnknownFieldPolicy,
) -> Result<(HeaderMap, Option<String>, u64), MimicError> {
    let mut out = HeaderMap::new();
    let mut client_session_id = None;
    let agent_version = mimic::extract_client_version_from_headers(headers);
    let raw_window_id = headers.get("x-codex-window-id").and_then(|v| v.to_str().ok());
    let window_number = mimic::extract_window_number(raw_window_id, None);

    for (name, value) in headers {
        if is_hop_by_hop(name) || name.as_str().starts_with(CONTROL_PREFIX) {
            continue;
        }
        if name == HOST
            || name == ACCEPT_ENCODING
            || name == CONTENT_LENGTH
            || name == HeaderName::from_static("sec-websocket-extensions")
            || name.as_str().starts_with("x-s2s-")
            || name == ACCOUNT_ID_HEADER
        {
            continue;
        }
        if name == "session-id" || name == "session_id" {
            if let Ok(s) = value.to_str() {
                client_session_id = Some(s.to_string());
            }
        }
        out.insert(name.clone(), value.clone());
    }

    // Apply strict account mimic, tracking header stripping & exact window number normalization
    mimic::sanitize_and_inject_headers_for_request(
        &mut out,
        &profile.fingerprint_seed,
        client_session_id.as_deref(),
        profile.custom_installation_id.as_deref(),
        salt,
        agent_version.as_deref(),
        window_number,
        is_responses_path,
        is_compact_path,
        policy,
    )?;

    Ok((out, agent_version, window_number))
}

fn strip_response_encoding(headers: &mut HeaderMap) {
    headers.remove(CONTENT_ENCODING);
    headers.remove(CONTENT_LENGTH);
    headers.remove(TRANSFER_ENCODING);
    // Strip upstream tracking/cookie/routing headers from egress response to prevent downstream leakage
    headers.remove(axum::http::header::SET_COOKIE);
    headers.remove(HeaderName::from_static("cf-ray"));
    headers.remove(HeaderName::from_static("cf-cache-status"));
    headers.remove(HeaderName::from_static("x-envoy-upstream-service-time"));
    headers.remove(HeaderName::from_static("x-openai-backend"));
    headers.remove(HeaderName::from_static("x-codex-routing-hint"));
}

async fn http_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum_request: Request<Body>,
) -> Response {
    if let Err(response) = check_token(&state, &headers) {
        return response;
    }
    let Some(target) = headers.get(UPSTREAM_URL_HEADER).and_then(|v| v.to_str().ok()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !allowed_codex_upstream_url(target) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let (profile, proxy) = match resolve_account_and_proxy(&state, &headers).await {
        Ok(res) => res,
        Err(response) => return response,
    };

    let client = match state.client_for(proxy.clone()).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let (is_responses_path, is_compact_path) = classify_upstream_target(target);
    let (forwarded, agent_version, window_number) =
        match forwarded_headers(&headers, &profile, &state.deployment_salt, is_responses_path, is_compact_path, state.unknown_field_policy) {
            Ok(res) => res,
            Err(err) => return err.into_response(),
        };
    let method = axum_request.method().clone();

    let mut builder = match method {
        Method::GET => client.get(target),
        Method::POST => client.post(target),
        Method::DELETE => client.delete(target),
        Method::HEAD => client.head(target),
        _ => client.request(method.clone(), target),
    };
    builder = builder.headers(forwarded);
    builder = builder.header(ACCEPT_ENCODING, "identity");

    // Read body to apply metadata sanitization and convergence if JSON
    let body_bytes = match axum::body::to_bytes(axum_request.into_body(), 64 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let transformed_body = match mimic::transform_request_body(
        &body_bytes,
        &profile.fingerprint_seed,
        profile.custom_installation_id.as_deref(),
        &state.deployment_salt,
        agent_version.as_deref(),
        Some(window_number),
        state.unknown_field_policy,
    ) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => body_bytes.to_vec(),
        Err(err) => return err.into_response(),
    };

    let start = std::time::Instant::now();
    if state.debug {
        tracing::info!(
            target = %target,
            method = %method,
            account_id = profile.account_id,
            proxy = ?proxy,
            agent_version = ?agent_version,
            window_number,
            body_len = transformed_body.len(),
            "sidecar http_tunnel forward request"
        );
        if let Ok(body_str) = std::str::from_utf8(&transformed_body) {
            tracing::info!(body = %body_str, "sidecar http_tunnel transformed request body");
        }
    }

    // Metadata normalization can change the body length, so never reuse a
    // client-supplied Content-Length after rebuilding the outbound request.
    builder = builder.header(CONTENT_LENGTH, transformed_body.len() as u64);
    builder = builder.body(transformed_body);

    let response = match builder.send().await {
        Ok(response) => {
            if state.debug {
                tracing::info!(
                    target = %target,
                    status = %response.status(),
                    elapsed_ms = start.elapsed().as_millis(),
                    headers = ?response.headers(),
                    "sidecar http_tunnel upstream response"
                );
            }
            response
        }
        Err(error) => {
            tracing::warn!(error = %error, target, "upstream request failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let status = response.status();
    let mut response_headers = response.headers().clone();
    strip_response_encoding(&mut response_headers);
    let mut response_builder = Response::builder().status(status);
    for (name, value) in &response_headers {
        response_builder = response_builder.header(name, value);
    }
    let out_body = Body::from_stream(response.bytes_stream().map(|result| {
        result.map_err(|error| std::io::Error::other(error))
    }));
    response_builder
        .body(out_body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn http_tunnel_e2ee(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum_request: Request<Body>,
) -> Response {
    if let Err(response) = check_token(&state, &headers) {
        return response;
    }
    let key = match e2ee::derive_key_from_token(state.token.as_bytes()) {
        Ok(key) => key,
        Err(error) => {
            tracing::error!(error = %error, "e2ee key derivation failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let Some(target) = headers.get(UPSTREAM_URL_HEADER).and_then(|v| v.to_str().ok()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !allowed_codex_upstream_url(target) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let (profile, proxy) = match resolve_account_and_proxy(&state, &headers).await {
        Ok(res) => res,
        Err(response) => return response,
    };
    let client = match state.client_for(proxy.clone()).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let (is_responses_path, is_compact_path) = classify_upstream_target(target);
    let (forwarded, agent_version, window_number) =
        match forwarded_headers(&headers, &profile, &state.deployment_salt, is_responses_path, is_compact_path, state.unknown_field_policy) {
            Ok(res) => res,
            Err(err) => return err.into_response(),
        };
    let method = axum_request.method().clone();

    let mut builder = match method {
        Method::GET => client.get(target),
        Method::POST => client.post(target),
        Method::DELETE => client.delete(target),
        Method::HEAD => client.head(target),
        _ => client.request(method.clone(), target),
    };
    builder = builder.headers(forwarded);
    builder = builder.header(ACCEPT_ENCODING, "identity");

    // Read sealed E2EE request body and decrypt. HTTP bodies are complete
    // record streams; leftover bytes therefore indicate a truncated request.
    let sealed_bytes = match axum::body::to_bytes(axum_request.into_body(), 64 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let plain_body = if sealed_bytes.is_empty() {
        Vec::new()
    } else {
        match e2ee::open_record_stream(&key, &sealed_bytes) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "e2ee decode failed");
                return StatusCode::BAD_REQUEST.into_response();
            }
        }
    };

    // Apply metadata sanitization & convergence on decrypted body with exact agent version & window_number
    let transformed_body = match mimic::transform_request_body(
        &plain_body,
        &profile.fingerprint_seed,
        profile.custom_installation_id.as_deref(),
        &state.deployment_salt,
        agent_version.as_deref(),
        Some(window_number),
        state.unknown_field_policy,
    ) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => plain_body,
        Err(err) => return err.into_response(),
    };

    let start = std::time::Instant::now();
    if state.debug {
        tracing::info!(
            target = %target,
            method = %method,
            account_id = profile.account_id,
            proxy = ?proxy,
            agent_version = ?agent_version,
            window_number,
            body_len = transformed_body.len(),
            "sidecar http_tunnel_e2ee forward request"
        );
        if let Ok(body_str) = std::str::from_utf8(&transformed_body) {
            tracing::info!(body = %body_str, "sidecar http_tunnel_e2ee transformed request body");
        }
    }

    // The inbound loopback body is ciphertext and metadata normalization can
    // also change plaintext length. Always describe the actual upstream body.
    builder = builder.header(CONTENT_LENGTH, transformed_body.len() as u64);
    builder = builder.body(transformed_body);

    let response = match builder.send().await {
        Ok(response) => {
            if state.debug {
                tracing::info!(
                    target = %target,
                    status = %response.status(),
                    elapsed_ms = start.elapsed().as_millis(),
                    headers = ?response.headers(),
                    "sidecar http_tunnel_e2ee upstream response"
                );
            }
            response
        }
        Err(error) => {
            tracing::warn!(error = %error, target, "upstream request failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let status = response.status();
    let mut response_headers = response.headers().clone();
    strip_response_encoding(&mut response_headers);
    let mut response_builder = Response::builder().status(status);
    response_builder = response_builder.header(E2EE_HEADER, "1");
    for (name, value) in &response_headers {
        response_builder = response_builder.header(name, value);
    }
    let key_for_resp = key;
    let out_body = Body::from_stream(response.bytes_stream().map(move |result| {
        let key = key_for_resp;
        result
            .map(|chunk| e2ee::seal_chunk(&key, &chunk))
            .map_err(|error| std::io::Error::other(error))
            .and_then(|r| r.map_err(|e| std::io::Error::other(e)))
    }));
    response_builder
        .body(out_body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn ts_to_axum(message: TsMessage) -> Option<AxumMessage> {
    match message {
        TsMessage::Text(text) => Some(AxumMessage::Text(text.to_string().into())),
        TsMessage::Binary(bytes) => Some(AxumMessage::Binary(bytes)),
        TsMessage::Ping(bytes) => Some(AxumMessage::Ping(bytes)),
        TsMessage::Pong(bytes) => Some(AxumMessage::Pong(bytes)),
        TsMessage::Close(frame) => Some(AxumMessage::Close(frame.map(|frame| AxumCloseFrame {
            code: frame.code.into(),
            reason: frame.reason.to_string().into(),
        }))),
        TsMessage::Frame(_) => None,
    }
}

fn axum_to_ts(message: AxumMessage) -> Option<TsMessage> {
    match message {
        AxumMessage::Text(text) => Some(TsMessage::text(text.to_string())),
        AxumMessage::Binary(bytes) => Some(TsMessage::binary(bytes)),
        AxumMessage::Ping(bytes) => Some(TsMessage::Ping(bytes)),
        AxumMessage::Pong(bytes) => Some(TsMessage::Pong(bytes)),
        AxumMessage::Close(frame) => Some(TsMessage::Close(frame.map(|frame| {
            tokio_tungstenite::tungstenite::protocol::frame::CloseFrame {
                code: frame.code.into(),
                reason: frame.reason.to_string().into(),
            }
        }))),
    }
}

fn websocket_connect_error_response(error: TsError) -> Response {
    match error {
        TsError::Http(upstream) => {
            let status = upstream.status();
            let mut response_headers = upstream.headers().clone();
            strip_response_encoding(&mut response_headers);
            let body = upstream.into_body().unwrap_or_default();
            let mut response_builder = Response::builder().status(status);
            for (name, value) in &response_headers {
                if is_hop_by_hop(name)
                    || name.as_str().starts_with("sec-websocket-")
                    || name.as_str().starts_with(CONTROL_PREFIX)
                    || name.as_str().starts_with("x-s2s-")
                {
                    continue;
                }
                response_builder = response_builder.header(name, value);
            }
            response_builder
                .body(Body::from(body))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
        }
        _ => (
            StatusCode::BAD_GATEWAY,
            "upstream websocket handshake failed",
        )
            .into_response(),
    }
}

#[cfg(test)]
mod websocket_connect_error_tests {
    use super::*;

    #[tokio::test]
    async fn forwards_quota_handshake_rejection() {
        let body = br#"{"error":{"type":"usage_limit_reached","message":"quota exhausted"}}"#.to_vec();
        let upstream = axum::http::Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("content-type", "application/json")
            .header("retry-after", "18000")
            .header("x-request-id", "req_quota")
            .header(CONNECTION, "close")
            .header("sec-websocket-accept", "must-not-leak")
            .header("x-s2s-token", "must-not-leak")
            .body(Some(body.clone()))
            .expect("valid upstream rejection");

        let response = websocket_connect_error_response(TsError::Http(Box::new(upstream)));

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response.headers().get("retry-after").and_then(|v| v.to_str().ok()),
            Some("18000")
        );
        assert_eq!(
            response.headers().get("x-request-id").and_then(|v| v.to_str().ok()),
            Some("req_quota")
        );
        assert!(response.headers().get(CONNECTION).is_none());
        assert!(response.headers().get("sec-websocket-accept").is_none());
        assert!(response.headers().get("x-s2s-token").is_none());
        let actual = axum::body::to_bytes(response.into_body(), 8 * 1024)
            .await
            .expect("read response body");
        assert_eq!(actual.as_ref(), body.as_slice());
    }

    #[tokio::test]
    async fn sanitizes_non_http_connect_failure() {
        let response = websocket_connect_error_response(TsError::Io(std::io::Error::other(
            "proxy credential detail",
        )));

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let actual = axum::body::to_bytes(response.into_body(), 8 * 1024)
            .await
            .expect("read response body");
        assert_eq!(actual.as_ref(), b"upstream websocket handshake failed");
    }
}

async fn pump_ws(
    client: WebSocket,
    upstream: codex_websocket_client::WebSocketConnection,
    e2ee_key: Option<[u8; 32]>,
    profile: AccountProfile,
    salt: String,
    agent_version: Option<String>,
    header_window_number: Option<u64>,
    policy: UnknownFieldPolicy,
) {
    let seal_ts = |message: TsMessage| -> TsMessage {
        match (&e2ee_key, message) {
            (Some(key), TsMessage::Text(text)) => match e2ee::seal(key, text.as_bytes()) {
                Ok(sealed) => TsMessage::Binary(sealed.into()),
                Err(err) => {
                    tracing::warn!(error = %err, "e2ee server WS frame encryption failed");
                    TsMessage::Close(Some(tokio_tungstenite::tungstenite::protocol::frame::CloseFrame {
                        code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy,
                        reason: "e2ee frame encryption failed".into(),
                    }))
                }
            },
            (Some(key), TsMessage::Binary(bytes)) => match e2ee::seal(key, &bytes) {
                Ok(sealed) => TsMessage::Binary(sealed.into()),
                Err(err) => {
                    tracing::warn!(error = %err, "e2ee server WS frame encryption failed");
                    TsMessage::Close(Some(tokio_tungstenite::tungstenite::protocol::frame::CloseFrame {
                        code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy,
                        reason: "e2ee frame encryption failed".into(),
                    }))
                }
            },
            (_, message) => message,
        }
    };

    let profile_for_upstream = profile.clone();
    let salt_for_upstream = salt.clone();
    let version_for_upstream = agent_version.clone();
    let open_and_transform_ts = move |message: TsMessage| -> TsMessage {
        let plain_msg = match (&e2ee_key, message) {
            (Some(key), TsMessage::Text(text)) => match e2ee::open(key, text.as_bytes()) {
                Ok(plain) => match String::from_utf8(plain) {
                    Ok(text) => TsMessage::text(text),
                    Err(e) => TsMessage::Binary(e.into_bytes().into()),
                },
                Err(err) => {
                    tracing::warn!(error = %err, "e2ee client WS frame authentication failed");
                    TsMessage::Close(Some(tokio_tungstenite::tungstenite::protocol::frame::CloseFrame {
                        code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy,
                        reason: "invalid encrypted websocket frame".into(),
                    }))
                }
            },
            (Some(key), TsMessage::Binary(bytes)) => match e2ee::open(key, &bytes) {
                Ok(plain) => match String::from_utf8(plain) {
                    Ok(text) => TsMessage::text(text),
                    Err(e) => TsMessage::Binary(e.into_bytes().into()),
                },
                Err(err) => {
                    tracing::warn!(error = %err, "e2ee client WS frame authentication failed");
                    TsMessage::Close(Some(tokio_tungstenite::tungstenite::protocol::frame::CloseFrame {
                        code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy,
                        reason: "invalid encrypted websocket frame".into(),
                    }))
                }
            },
            (_, message) => message,
        };

        // Apply metadata sanitization and convergence on client WS frame with exact agent version & window number
        match plain_msg {
            TsMessage::Text(text) => {
                match mimic::transform_ws_frame(
                    &text,
                    &profile_for_upstream.fingerprint_seed,
                    profile_for_upstream.custom_installation_id.as_deref(),
                    &salt_for_upstream,
                    version_for_upstream.as_deref(),
                    header_window_number,
                    policy,
                ) {
                    Ok(Some(transformed)) => TsMessage::text(transformed),
                    Ok(None) => TsMessage::Text(text),
                    Err(err) => {
                        tracing::warn!(error = %err, "forbidden client WS frame payload");
                        TsMessage::Close(Some(tokio_tungstenite::tungstenite::protocol::frame::CloseFrame {
                            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy,
                            reason: err.to_string().into(),
                        }))
                    }
                }
            }
            other => other,
        }
    };

    let (mut client_sink, mut client_stream) = client.split();
    let (mut upstream_sink, mut upstream_stream) = upstream.split();

    let to_upstream = async {
        while let Some(message) = client_stream.next().await {
            match message {
                Ok(message) => {
                    let is_close = matches!(&message, AxumMessage::Close(_));
                    let Some(ts) = axum_to_ts(message) else { continue };
                    let ts = open_and_transform_ts(ts);
                    if upstream_sink.send(ts).await.is_err() {
                        break;
                    }
                    if is_close {
                        let _ = upstream_sink.close().await;
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = upstream_sink.flush().await;
    };
    let to_client = async {
        while let Some(message) = upstream_stream.next().await {
            match message {
                Ok(message) => {
                    let is_close = matches!(&message, TsMessage::Close(_));
                    let message = seal_ts(message);
                    if let Some(message) = ts_to_axum(message) {
                        if client_sink.send(message).await.is_err() {
                            break;
                        }
                        if is_close {
                            let _ = client_sink.close().await;
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
        let _ = client_sink.close().await;
    };

    tokio::pin!(to_upstream);
    tokio::pin!(to_client);

    tokio::select! {
        _ = &mut to_client => {
            // Upstream finished producing responses/errors and closed the stream.
        }
        _ = &mut to_upstream => {
            // Client finished sending request(s); wait for upstream to complete response stream.
            to_client.await;
        }
    }
}

async fn ws_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if let Err(response) = check_token(&state, &headers) {
        return response;
    }
    let Some(target) = headers.get(UPSTREAM_URL_HEADER).and_then(|v| v.to_str().ok()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !allowed_codex_upstream_url(target) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Ok(all_target) = target.parse::<axum::http::Uri>() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (profile, proxy) = match resolve_account_and_proxy(&state, &headers).await {
        Ok(res) => res,
        Err(response) => return response,
    };
    let is_responses_path = true;
    let is_compact_path = false;
    let (forwarded, agent_version, window_number) =
        match forwarded_headers(&headers, &profile, &state.deployment_salt, is_responses_path, is_compact_path, state.unknown_field_policy) {
            Ok(res) => res,
            Err(err) => return err.into_response(),
        };
    let e2ee_key = match headers.get(E2EE_HEADER).and_then(|v| v.to_str().ok()) {
        Some("1") => match e2ee::derive_key_from_token(state.token.as_bytes()) {
            Ok(key) => Some(key),
            Err(error) => {
                tracing::error!(error = %error, "e2ee websocket key derivation failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        },
        _ => None,
    };
    let is_e2ee = e2ee_key.is_some();
    if state.debug {
        tracing::info!(
            target = %target,
            account_id = profile.account_id,
            proxy = ?proxy,
            agent_version = ?agent_version,
            window_number,
            "sidecar ws_tunnel connecting upstream"
        );
    }

    // Complete the upstream handshake before accepting the local WebSocket.
    // Otherwise a quota/rate-limit HTTP rejection is converted into an
    // upgraded loopback socket that immediately disappears without a close
    // frame, which Codex misclassifies as a retryable transport reset.
    let connector = match WebSocketConnector::new_with_tls_mode(
        &codex_http_client::HttpClientFactory::new(OutboundProxyPolicy::ReqwestDefault),
        WebSocketTlsMode::ExplicitCodexTls,
    ) {
        Ok(connector) => connector,
        Err(error) => {
            tracing::warn!(error = %error, "failed to build WS TLS config");
            return (
                StatusCode::BAD_GATEWAY,
                "upstream websocket connector unavailable",
            )
                .into_response();
        }
    };
    let mut request = TsRequest::new(());
    *request.method_mut() = Method::GET;
    *request.uri_mut() = all_target.clone();
    if let Some(authority) = all_target.authority() {
        let Ok(host) = HeaderValue::from_str(authority.as_str()) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        request.headers_mut().insert(HOST, host);
    }
    request.headers_mut().insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    request.headers_mut().insert(UPGRADE, HeaderValue::from_static("websocket"));
    for (name, value) in &forwarded {
        let Some(name) = HeaderName::from_bytes(name.as_str().as_bytes()).ok() else {
            continue;
        };
        let Ok(value) = value.to_str().map(|v| HeaderValue::from_str(v).unwrap_or_else(|_| HeaderValue::from_static(""))) else {
            continue;
        };
        request.headers_mut().insert(name, value);
    }
    let (connection, _) = match connector
        .connect_via(request, WebSocketConfig::default(), proxy)
        .await
    {
        Ok(connection) => connection,
        Err(error) => {
            tracing::warn!(error = %error, "upstream WS connect failed");
            return websocket_connect_error_response(error);
        }
    };
    if state.debug {
        tracing::info!("sidecar ws_tunnel upstream connected successfully");
    }

    let profile_for_ws = profile.clone();
    let salt_for_ws = state.deployment_salt.clone();
    let policy_for_ws = state.unknown_field_policy;
    let mut response = ws.on_upgrade(move |socket| async move {
        pump_ws(
            socket,
            connection,
            e2ee_key,
            profile_for_ws,
            salt_for_ws,
            agent_version,
            Some(window_number),
            policy_for_ws,
        )
        .await;
    }).into_response();

    if is_e2ee {
        if let Ok(val) = HeaderValue::from_str("1") {
            if let Ok(name) = HeaderName::from_bytes(E2EE_HEADER.as_bytes()) {
                response.headers_mut().insert(name, val);
            }
        }
    }
    response
}

async fn healthz() -> &'static str {
    "ok\n"
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let token = std::env::var("SUB2API_SIDECAR_TOKEN").unwrap_or_default();
    if token.is_empty() {
        tracing::error!("SUB2API_SIDECAR_TOKEN must be set");
        std::process::exit(1);
    }
    let addr = std::env::var("SUB2API_SIDECAR_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:21333".to_string());
    let addr: std::net::SocketAddr = addr
        .parse()
        .unwrap_or_else(|_| "127.0.0.1:21333".parse().unwrap());
    if !addr.ip().is_loopback() {
        let allow_non_loopback = std::env::var("SUB2API_SIDECAR_ALLOW_NON_LOOPBACK")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if !allow_non_loopback {
            tracing::error!(
                %addr,
                "sidecar must bind loopback unless SUB2API_SIDECAR_ALLOW_NON_LOOPBACK=1"
            );
            std::process::exit(1);
        }
    }

    let deployment_salt = std::env::var("SUB2API_DEPLOYMENT_SALT").unwrap_or_else(|_| {
        let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, format!("salt:{token}").as_bytes());
        d.as_ref().iter().map(|b| format!("{:02x}", b)).collect::<String>()
    });

    let unknown_field_policy = UnknownFieldPolicy::from_env();
    tracing::info!(?unknown_field_policy, "unknown wire field policy configured");

    let db_url = std::env::var("DATABASE_URL")
        .ok()
        .or_else(|| std::env::var("SUB2API_DATABASE_URL").ok());
    let db = DbProxyResolver::new(db_url);
    if db.is_configured() {
        tracing::info!("direct database account proxy & fingerprint resolution enabled");
    }

    let debug = std::env::var("SUB2API_SIDECAR_DEBUG")
        .or_else(|_| std::env::var("GATEWAY_SIDECAR_DEBUG"))
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if debug {
        tracing::info!("sidecar debug wire capture mode enabled");
    }

    let state = AppState {
        token,
        deployment_salt,
        unknown_field_policy,
        clients: Arc::new(RwLock::new(HashMap::new())),
        db,
        debug,
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route(
            "/v1/http",
            any(|state: State<AppState>, headers: HeaderMap, req: Request<Body>| async move {
                if headers.get(E2EE_HEADER).and_then(|v| v.to_str().ok()) == Some("1") {
                    http_tunnel_e2ee(state, headers, req).await
                } else {
                    http_tunnel(state, headers, req).await
                }
            }),
        )
        .route("/v1/ws", get(ws_tunnel))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|error| {
            tracing::error!(error = %error, %addr, "bind failed");
            std::process::exit(1);
        });
    tracing::info!(%addr, "sub2api-sidecar listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown signal received, terminating gracefully");
        })
        .await
        .expect("server error");
}
