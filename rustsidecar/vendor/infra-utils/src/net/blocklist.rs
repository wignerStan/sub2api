//! Detection of bot-protection block pages from HTTP responses.

/// Patterns that indicate a bot-detection block page.
const BLOCK_PATTERNS: &[&str] = &[
    "cf-challenge",
    "cf-browser-verification",
    "just a moment",
    "checking your browser",
    "please wait",
    "cf_chl_opt",
    "challenge-platform",
    "ray id",
    "enable javascript",
];

/// Check if an HTTP response body looks like a bot-detection block page.
#[must_use]
pub fn is_blocked_response(status: u16, body: &str) -> bool {
    if status == 403 || status == 503 {
        let lower = body.to_ascii_lowercase();
        return BLOCK_PATTERNS.iter().any(|p| lower.contains(p));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_cf_challenge() {
        assert!(is_blocked_response(403, "<html>cf-challenge verify</html>"));
    }

    #[test]
    fn detects_503_just_a_moment() {
        assert!(is_blocked_response(503, "<title>Just a Moment...</title>"));
    }

    mod negative {
        use super::*;

        #[test]
        fn allows_normal_response() {
            assert!(!is_blocked_response(200, "<html>hello world</html>"));
        }

        #[test]
        fn allows_403_non_cf() {
            assert!(!is_blocked_response(403, "<html>Not Found</html>"));
        }

        #[test]
        fn ignores_normal_503() {
            assert!(!is_blocked_response(
                503,
                "<html>Service Temporarily Unavailable</html>"
            ));
        }

        #[test]
        fn ignores_block_patterns_on_200() {
            assert!(
                !is_blocked_response(200, "cf-challenge verify"),
                "block patterns on 200 should be ignored"
            );
        }

        #[test]
        fn ignores_block_patterns_on_404() {
            assert!(
                !is_blocked_response(404, "please wait while we process"),
                "block patterns on 404 should be ignored"
            );
        }

        #[test]
        fn ignores_similar_but_not_matching() {
            assert!(
                !is_blocked_response(403, "cf-verify-page"),
                "cf-verify-page should not match any block pattern"
            );
        }

        #[test]
        fn ignores_empty_body() {
            assert!(
                !is_blocked_response(403, ""),
                "empty body should not be blocked"
            );
        }
    }

    mod edge {
        use super::*;

        #[test]
        fn detects_case_insensitive() {
            assert!(is_blocked_response(403, "<HTML>CF-CHALLENGE</HTML>"));
        }

        #[test]
        fn detects_embedded_in_large_body() {
            let body = format!(
                "{}Checking Your Browser{}",
                "x".repeat(10000),
                "y".repeat(10000)
            );
            assert!(is_blocked_response(503, &body));
        }

        #[test]
        fn detects_multiple_patterns_present() {
            assert!(is_blocked_response(403, "cf-challenge and just a moment"));
        }

        #[test]
        fn detects_enable_javascript() {
            assert!(is_blocked_response(
                503,
                "Please Enable JavaScript to continue"
            ));
        }
    }
}
