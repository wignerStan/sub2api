//! sub2api-sidecar: TLS-disguise egress shim for sub2api's OpenAI OAuth traffic.
//!
//! Listens on loopback and re-emits HTTP/WS requests toward chatgpt.com using the
//! exact client stack shipped by openai/codex (codex-http-client, codex-websocket-client,
//! rustls 0.23 + aws-lc-rs), so the observed TLS ClientHello matches official Codex.
//! Business logic stays in the Go process; this binary only disguises transport.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ws::{CloseFrame as AxumCloseFrame, Message as AxumMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{Request, State};
use axum::http::header::{ACCEPT_ENCODING, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, HOST, TRANSFER_ENCODING, UPGRADE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use codex_http_client::OutboundProxyPolicy;
use codex_http_client::{HttpClient, HttpClientBuilder};
use codex_websocket_client::{WebSocketConnector, WebSocketTlsMode};
use futures::{SinkExt, StreamExt};
use tokio::sync::RwLock;
use tokio_tungstenite::tungstenite::Message as TsMessage;
use tokio_tungstenite::tungstenite::handshake::client::Request as TsRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

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

const CONTROL_PREFIX: &str = "x-upstream-";
const TOKEN_HEADER: &str = "x-s2s-token";
const UPSTREAM_URL_HEADER: &str = "x-upstream-url";
const UPSTREAM_PROXY_HEADER: &str = "x-upstream-proxy";

#[derive(Clone)]
struct AppState {
    token: String,
    clients: Arc<RwLock<HashMap<String, HttpClient>>>,
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
        // 构建失败(如代理 URL 非法)必须显式失败,绝不静默回退裸 reqwest:
        // 静默直连会绕过代理与 codex rustls 伪装栈,违背 sidecar 初衷。
        let client = builder
            .build_direct()
            .map_err(|error| {
                tracing::warn!(error = %error, proxy, "proxy client build failed");
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

fn decode_proxy(headers: &HeaderMap) -> Result<Option<String>, Response> {
    let Some(value) = headers.get(UPSTREAM_PROXY_HEADER) else {
        return Ok(None);
    };
    let raw = value
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
    if raw.is_empty() {
        return Ok(None);
    }
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, raw)
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
    let url = String::from_utf8(bytes).map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
    Ok(Some(url))
}

fn forwarded_headers(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        if is_hop_by_hop(name) || name.as_str().starts_with(CONTROL_PREFIX) {
            continue;
        }
        if name == HOST
            || name == ACCEPT_ENCODING
            || name == HeaderName::from_static("sec-websocket-extensions")
            || name.as_str().starts_with("x-s2s-")
        {
            continue;
        }
        out.insert(name.clone(), value.clone());
    }
    out
}

fn strip_response_encoding(headers: &mut HeaderMap) {
    headers.remove(CONTENT_ENCODING);
    headers.remove(CONTENT_LENGTH);
    headers.remove(TRANSFER_ENCODING);
}

async fn http_tunnel(State(state): State<AppState>, headers: HeaderMap, axum_request: Request<Body>) -> Response {
    tracing::info!(target = "sub2api_sidecar.perf", "http_tunnel enter");
    if let Err(response) = check_token(&state, &headers) {
        return response;
    }
    let Some(target) = headers.get(UPSTREAM_URL_HEADER).and_then(|v| v.to_str().ok()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let proxy = match decode_proxy(&headers) {
        Ok(proxy) => proxy,
        Err(response) => return response,
    };

    let client = match state.client_for(proxy).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let forwarded = forwarded_headers(&headers);
    let method = axum_request.method().clone();

    let mut builder = match method {
        Method::GET => client.get(target),
        Method::POST => client.post(target),
        Method::DELETE => client.delete(target),
        Method::HEAD => client.head(target),
        _ => client.request(method, target),
    };
    builder = builder.headers(forwarded);
    builder = builder.header(ACCEPT_ENCODING, "identity");

    let body_stream = axum_request
        .into_body()
        .into_data_stream()
        .map(|result| result.map_err(|error| std::io::Error::other(error)));
    let body = reqwest::Body::wrap_stream(body_stream);
    builder = builder.body(body);

    let response = match builder.send().await {
        Ok(response) => {
            tracing::info!(target = "sub2api_sidecar.perf", status = %response.status(), "upstream responded");
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

async fn pump_ws(client: WebSocket, upstream: codex_websocket_client::WebSocketConnection) {
    let (mut client_sink, mut client_stream) = client.split();
    let (mut upstream_sink, mut upstream_stream) = upstream.split();
    let to_upstream = async {
        while let Some(message) = client_stream.next().await {
            match message {
                Ok(message) => {
                    if let Some(message) = axum_to_ts(message) {
                        if upstream_sink.send(message).await.is_err() {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    };
    let to_client = async {
        while let Some(message) = upstream_stream.next().await {
            match message {
                Ok(message) => {
                    if let Some(message) = ts_to_axum(message) {
                        if client_sink.send(message).await.is_err() {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    };
    tokio::select! {
        _ = to_upstream => {}
        _ = to_client => {}
    }
}

async fn ws_tunnel(State(state): State<AppState>, headers: HeaderMap, ws: WebSocketUpgrade) -> Response {
    if let Err(response) = check_token(&state, &headers) {
        return response;
    }
    let Some(target) = headers.get(UPSTREAM_URL_HEADER).and_then(|v| v.to_str().ok()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(all_target) = target.parse::<axum::http::Uri>() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let proxy = match decode_proxy(&headers) {
        Ok(proxy) => proxy,
        Err(response) => return response,
    };
    let forwarded = forwarded_headers(&headers);

    ws.on_upgrade(move |socket| async move {
        let connector = match WebSocketConnector::new_with_tls_mode(
            &codex_http_client::HttpClientFactory::new(OutboundProxyPolicy::ReqwestDefault),
            WebSocketTlsMode::ExplicitCodexTls,
        ) {
            Ok(connector) => connector,
            Err(error) => {
                tracing::warn!(error = %error, "failed to build WS TLS config");
                return;
            }
        };
        let mut request = TsRequest::new(());
        *request.method_mut() = Method::GET;
        *request.uri_mut() = all_target.clone();
        if let Some(authority) = all_target.authority() {
            let Ok(host) = HeaderValue::from_str(authority.as_str()) else {
                return;
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
                return;
            }
        };
        pump_ws(socket, connection).await;
    })
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

    let state = AppState {
        token,
        clients: Arc::new(RwLock::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/http", post(http_tunnel))
        .route("/v1/ws", get(ws_tunnel))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|error| {
            tracing::error!(error = %error, %addr, "bind failed");
            std::process::exit(1);
        });
    tracing::info!(%addr, "sub2api-sidecar listening");
    axum::serve(listener, app).await.expect("server error");
}