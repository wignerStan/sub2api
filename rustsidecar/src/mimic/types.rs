//! Types, policies, errors, and wire schema constants for Codex mimicry.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

pub const REALISTIC_USERNAMES: &[&str] = &[
    "alex", "sam", "jordan", "taylor", "morgan", "chris", "pat", "casey", "riley", "avery",
    "quinn", "jamie", "logan", "cameron", "drew", "skyler", "reese", "rowan", "ellis", "kendall",
    "harper", "finley", "dakota", "robin",
];

pub const REALISTIC_PROJECTS: &[&str] = &[
    "backend",
    "core-api",
    "frontend",
    "platform",
    "infra",
    "gateway",
    "services",
    "web-app",
    "microservices",
    "pipeline",
    "auth-service",
    "engine",
    "hub",
    "client",
    "agent-runner",
    "dashboard",
    "worker",
    "storage",
    "connector",
    "runtime",
    "data-pipeline",
    "server",
    "sdk",
    "toolkit",
    "dispatcher",
    "streamer",
    "proxy-service",
    "indexer",
    "scheduler",
    "controller",
];

pub const REALISTIC_GIT_BRANCHES: &[&str] = &[
    "main",
    "master",
    "develop",
    "testing",
    "docs",
    "codex-audit",
    "feature/api-v2",
    "fix/cache-sync",
    "refactor/core",
    "chore/deps",
    "staging",
    "dev",
];

/// Identity metadata generated for a turn, including realistic organic workstation simulation
/// and precise compaction window number preservation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
        use crate::mimic::identity::{derive_converged_thread_id, derive_converged_uuid_v4};

        let installation_id =
            if let Some(dev_id) = custom_device_id.filter(|s| !s.trim().is_empty()) {
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

        let day_bucket = (chrono::Utc::now().timestamp().max(0) / 86400) as u64;
        let branch_jitter = h[4] as u64;
        let branch_idx = ((day_bucket + branch_jitter) as usize) % REALISTIC_GIT_BRANCHES.len();
        let git_branch = REALISTIC_GIT_BRANCHES[branch_idx].to_string();

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

/// Upstream-audited allowed flat client_metadata keys (used in exact snapshot fidelity testing).
#[cfg(test)]
pub const UPSTREAM_ALLOWED_FLAT_CLIENT_METADATA_KEYS: &[&str] = &[
    "parent_turn_id",
    "root_turn_id",
    "session_id",
    "thread_id",
    "turn_id",
    "ws_request_header_x_openai_internal_codex_responses_lite",
    "x-codex-installation-id",
    "x-codex-parent-thread-id",
    "x-codex-turn-metadata",
    "x-codex-turn-state",
    "x-codex-window-id",
    "x-codex-ws-stream-request-start-ms",
    "x-openai-subagent",
];

/// Upstream-audited explicitly stripped flat client_metadata keys (APM / tracing channels).
pub const UPSTREAM_EXPLICITLY_STRIPPED_FLAT_CLIENT_METADATA_KEYS: &[&str] = &[
    "ws_request_header_traceparent",
    "ws_request_header_tracestate",
];

/// sub2api-specific extensions to flat client_metadata keys (normalized from TurnMetadata).
#[cfg(test)]
pub const SUB2API_EXTENDED_FLAT_CLIENT_METADATA_KEYS: &[&str] = &[
    "context_window_id",
    "previous_window_id",
    "window_id",
    "window_number",
];

/// Allowed keys in flat `client_metadata` (Strict Whitelist).
/// Codex Core wire schema is Option<HashMap<String, String>>.
pub const ALLOWED_FLAT_CLIENT_METADATA_KEYS: &[&str] = &[
    "context_window_id",
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
    "x-openai-subagent",
];

/// Strategy for handling unrecognized/unknown wire metadata fields and headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnknownFieldPolicy {
    /// Direct reject with HTTP 403 Forbidden (Strict Fail-Closed Default).
    #[default]
    Forbidden,
    /// Strip unknown field silently without rejecting the request.
    Strip,
}

impl UnknownFieldPolicy {
    /// Resolve strategy from environment variables (defaults to Forbidden).
    pub fn from_env() -> Self {
        let val = std::env::var("SIDECAR_UNKNOWN_FIELD_POLICY")
            .or_else(|_| std::env::var("SUB2API_SIDECAR_UNKNOWN_FIELD_POLICY"))
            .or_else(|_| std::env::var("GATEWAY_SIDECAR_UNKNOWN_FIELD_POLICY"))
            .unwrap_or_else(|_| "forbidden".to_string())
            .to_ascii_lowercase();

        match val.trim() {
            "strip" | "drop" => Self::Strip,
            _ => Self::Forbidden, // default
        }
    }
}

/// Sidecar mimicry and validation errors.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MimicError {
    ForbiddenHeader(String),
    ForbiddenMetadataKey(String),
    ForbiddenAcceptHeader(String),
    ForbiddenMissingFingerprint(String),
    ForbiddenDivergingFingerprint(String),
    InvalidJson(String),
}

impl std::fmt::Display for MimicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForbiddenHeader(hdr) => write!(f, "Forbidden: unrecognized wire x- header '{hdr}'"),
            Self::ForbiddenMetadataKey(key) => write!(f, "Forbidden: unrecognized wire client_metadata key '{key}'"),
            Self::ForbiddenAcceptHeader(acc) => write!(f, "Forbidden: Accept header '{acc}' is blocked, only 'text/event-stream' is supported for OAuth accounts"),
            Self::ForbiddenMissingFingerprint(msg) => write!(f, "Forbidden: missing required fingerprint item: {msg}"),
            Self::ForbiddenDivergingFingerprint(msg) => write!(f, "Forbidden: diverging fingerprint item: {msg}"),
            Self::InvalidJson(err) => write!(f, "Invalid JSON body: {err}"),
        }
    }
}

impl std::error::Error for MimicError {}

impl IntoResponse for MimicError {
    fn into_response(self) -> Response {
        (StatusCode::FORBIDDEN, self.to_string()).into_response()
    }
}

/// Upstream-audited allowed account x- headers.
#[cfg(test)]
pub const UPSTREAM_ALLOWED_ACCOUNT_X_HEADERS: &[&str] = &["x-openai-fedramp"];

/// Upstream-audited explicitly stripped account x- headers.
pub const UPSTREAM_EXPLICITLY_STRIPPED_ACCOUNT_X_HEADERS: &[&str] = &[];

/// sub2api extended account x- headers.
#[cfg(test)]
pub const SUB2API_EXTENDED_ACCOUNT_X_HEADERS: &[&str] = &[];

/// Allowed account x- headers (Strict Whitelist).
pub const ALLOWED_ACCOUNT_X_HEADERS: &[&str] = &["x-openai-fedramp"];

/// Upstream-audited allowed responses x- headers.
#[cfg(test)]
pub const UPSTREAM_ALLOWED_RESPONSES_X_HEADERS: &[&str] = &[
    "x-client-request-id",
    "x-codex-beta-features",
    "x-codex-parent-thread-id",
    "x-codex-turn-metadata",
    "x-codex-turn-state",
    "x-codex-window-id",
    "x-openai-fedramp",
    "x-openai-internal-codex-residency",
    "x-openai-internal-codex-responses-lite",
    "x-openai-memgen-request",
    "x-openai-subagent",
    "x-responsesapi-include-timing-metrics",
];

/// Upstream-audited explicitly stripped responses x- headers.
pub const UPSTREAM_EXPLICITLY_STRIPPED_RESPONSES_X_HEADERS: &[&str] =
    &["x-codex-routing-hint", "x-oai-attestation"];

/// sub2api extended responses x- headers.
#[cfg(test)]
pub const SUB2API_EXTENDED_RESPONSES_X_HEADERS: &[&str] = &[
    "x-codex-installation-id",
    "x-codex-ws-stream-request-start-ms",
];

/// Allowed responses x- headers (Strict Whitelist).
pub const ALLOWED_RESPONSES_X_HEADERS: &[&str] = &[
    "x-client-request-id",
    "x-codex-beta-features",
    "x-codex-installation-id",
    "x-codex-parent-thread-id",
    "x-codex-turn-metadata",
    "x-codex-turn-state",
    "x-codex-window-id",
    "x-codex-ws-stream-request-start-ms",
    "x-openai-fedramp",
    "x-openai-internal-codex-residency",
    "x-openai-internal-codex-responses-lite",
    "x-openai-memgen-request",
    "x-openai-subagent",
    "x-responsesapi-include-timing-metrics",
];

/// Explicitly stripped attestation header / field names.
pub const EXPLICITLY_STRIPPED_ATTESTATION_NAMES: &[&str] = &[
    "x-oai-attestation",
    "x-openai-attestation",
    "x-codex-attestation",
    "attestation",
    "x-attestation",
];

/// Explicitly stripped APM tracing / tracking / cookie header & field names.
pub const EXPLICITLY_STRIPPED_TRACE_AND_TRACKING_NAMES: &[&str] = &[
    "ws_request_header_traceparent",
    "ws_request_header_tracestate",
    "traceparent",
    "tracestate",
    "baggage",
    "cookie",
    "set-cookie",
    "x-codex-routing-hint",
];
