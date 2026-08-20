//! Allowlist for sidecar `x-upstream-url`.
//!
//! Go already restricts which requests are forwarded here. This check is
//! defense in depth: a stolen `x-s2s-token` must not SSRF arbitrary URLs
//! or exfiltrate Authorization headers to an attacker-controlled host.

const CODEX_PATH_PREFIX: &str = "/backend-api/codex";

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
    let host = host.to_ascii_lowercase();
    if host != "chatgpt.com" && !host.ends_with(".chatgpt.com") {
        return false;
    }
    let cleaned = clean_url_path(url.path());
    cleaned == CODEX_PATH_PREFIX || cleaned.starts_with(&format!("{CODEX_PATH_PREFIX}/"))
}

fn clean_url_path(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            let _ = out.pop();
            continue;
        }
        out.push(seg);
    }
    if out.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", out.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_chatgpt_codex_https_and_wss() {
        for raw in [
            "https://chatgpt.com/backend-api/codex/responses",
            "https://chatgpt.com/backend-api/codex/models",
            "https://chatgpt.com/backend-api/codex/responses/compact",
            "wss://chatgpt.com/backend-api/codex/call_proxy",
            "https://ab.chatgpt.com/backend-api/codex/responses?stream=true",
            "https://chatgpt.com/backend-api/codex",
        ] {
            assert!(allowed_codex_upstream_url(raw), "{raw}");
        }
    }

    #[test]
    fn rejects_ssrf_and_non_codex() {
        for raw in [
            "",
            "https://api.openai.com/v1/models",
            "https://chatgpt.com/backend-api/wham/usage",
            "http://chatgpt.com/backend-api/codex/responses",
            "ws://chatgpt.com/backend-api/codex/call_proxy",
            "https://chatgpt.com/backend-api/codex/../wham/usage",
            "https://chatgpt.com.evil.example/backend-api/codex/responses",
            "https://notchatgpt.com/backend-api/codex/responses",
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1:8080/backend-api/codex/responses",
            "https://user:pass@chatgpt.com/backend-api/codex/responses",
            "https://chatgpt.com/backend-api/codexfoo/responses",
        ] {
            assert!(!allowed_codex_upstream_url(raw), "{raw}");
        }
    }
}
