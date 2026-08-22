//! Allowlist for sidecar `x-upstream-url`.
//!
//! Go already restricts which requests are forwarded here. This check is
//! defense in depth: a stolen `x-s2s-token` must not SSRF arbitrary URLs
//! or exfiltrate Authorization headers to an attacker-controlled host.
//!
//! Official OpenAI OAuth TLS hosts (ChatGPT + auth.openai.com) are allowed so
//! every Codex-CLI-equivalent call can reuse rustls. api.openai.com stays out.

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
    is_openai_oauth_tls_host(host)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_openai_oauth_https_and_wss() {
        for raw in [
            "https://chatgpt.com/backend-api/codex/responses",
            "https://chatgpt.com/backend-api/codex/models",
            "https://chatgpt.com/backend-api/wham/usage",
            "https://chatgpt.com/backend-api/files",
            "https://chatgpt.com/",
            "wss://chatgpt.com/backend-api/codex/call_proxy",
            "https://ab.chatgpt.com/backend-api/codex/responses?stream=true",
            "https://chat.openai.com/backend-api/codex/responses",
            "https://auth.openai.com/oauth/token",
            "https://auth.openai.com/api/accounts/v1/user-auth-credential/whoami",
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
        ] {
            assert!(!allowed_codex_upstream_url(raw), "{raw}");
        }
    }
}
