//! Strict Allowlist for sidecar `x-upstream-url`.
//!
//! Enforces:
//! 1. Official OpenAI OAuth host validation (ChatGPT + auth.openai.com).
//! 2. Strict path allowlisting (/responses, /models, /compact, /call_proxy, /usage, /files, /oauth).
//! 3. SSRF and private/loopback IP rejection.

pub fn allowed_codex_upstream_url(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(trimmed) else {
        return false;
    };
    match url.scheme() {
        "https" | "wss" => {}
        _ => return false,
    }
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    if !is_openai_oauth_tls_host(host) {
        return false;
    }

    let path = url.path();
    is_allowed_codex_path(host, path)
}

fn is_openai_oauth_tls_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "chatgpt.com"
        || host.ends_with(".chatgpt.com")
        || host == "chat.openai.com"
        || host.ends_with(".chat.openai.com")
        || host == "auth.openai.com"
        || host.ends_with(".auth.openai.com")
}

fn is_allowed_codex_path(host: &str, path: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let path = path.trim();

    if host == "auth.openai.com" || host.ends_with(".auth.openai.com") {
        return path == "/oauth/token"
            || path == "/api/v1/oauth/token"
            || path == "/api/accounts/v1/user-auth-credential/whoami"
            || path == "/api/accounts/v1/user-auth-credential/revoke"
            || path.starts_with("/oauth/")
            || path.starts_with("/api/accounts/");
    }

    // ChatGPT / Codex paths
    path == "/backend-api/codex/responses"
        || path == "/backend-api/codex/models"
        || path == "/backend-api/codex/compact"
        || path == "/backend-api/codex/call_proxy"
        || path == "/backend-api/wham/usage"
        || path.starts_with("/backend-api/wham/")
        || path == "/backend-api/files"
        || path.starts_with("/backend-api/files/")
        || path == "/backend-api/conversation"
        || path.starts_with("/backend-api/conversation/")
        || path.starts_with("/backend-api/codex/")
        || path == "/backend-api/settings/account_user_setting"
        || path.starts_with("/backend-api/settings/")
        || path.starts_with("/backend-api/accounts/")
        || path == "/backend-api/subscriptions"
        || path.starts_with("/backend-api/subscriptions/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_openai_oauth_https_and_wss() {
        for raw in [
            "https://chatgpt.com/backend-api/codex/responses",
            "https://chatgpt.com/backend-api/codex/models",
            "https://chatgpt.com/backend-api/codex/compact",
            "https://chatgpt.com/backend-api/wham/usage",
            "https://chatgpt.com/backend-api/files",
            "https://chatgpt.com/backend-api/files/file-123/content",
            "wss://chatgpt.com/backend-api/codex/call_proxy",
            "https://ab.chatgpt.com/backend-api/codex/responses?stream=true",
            "https://chat.openai.com/backend-api/codex/responses",
            "https://auth.openai.com/oauth/token",
            "https://auth.openai.com/api/accounts/v1/user-auth-credential/whoami",
            "https://chatgpt.com/backend-api/settings/account_user_setting?feature=training_allowed&value=false",
            "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27",
            "https://chatgpt.com/backend-api/subscriptions",
        ] {
            assert!(allowed_codex_upstream_url(raw), "{raw}");
        }
    }

    #[test]
    fn rejects_ssrf_and_non_oauth_hosts() {
        for raw in [
            "",
            "https://api.openai.com/v1/models",
            "http://chatgpt.com/backend-api/codex/responses",
            "ws://chatgpt.com/backend-api/codex/call_proxy",
            "https://chatgpt.com.evil.example/backend-api/codex/responses",
            "https://notchatgpt.com/backend-api/codex/responses",
            "https://auth.openai.com.evil.example/oauth/token",
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1:8080/backend-api/codex/responses",
            "https://user:pass@chatgpt.com/backend-api/codex/responses",
            "https://chatgpt.com/admin/delete-everything",
            "https://chatgpt.com/random-unknown-endpoint",
        ] {
            assert!(!allowed_codex_upstream_url(raw), "{raw}");
        }
    }
}
