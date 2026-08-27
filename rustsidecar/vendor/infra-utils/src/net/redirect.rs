//! Outbound redirect-target validation.
//!
//! [`SafeRedirectTarget`] validates a `Location` header value the way
//! [`crate::net::url_ext::join_same_origin`] validates a relative reference,
//! but for the cross-origin case redirects actually need: it resolves the
//! location against the current URL, parses it as an [`HttpUrl`], and applies
//! an origin policy. Use this in a redirect-follow loop to reject scheme
//! downgrades, protocol-smuggling (`//evil`, `javascript:`, `file:`), and
//! origin escapes before the next hop is fetched.
//!
//! Pure (no DNS): the resolved-IP SSRF check lives in [`crate::net::ssrf`] +
//! the safe-egress executor; this is the syntactic + origin gate that runs
//! first, on every hop.

use crate::net::url_ext::{HttpUrl, UrlError};

/// The origin policy a redirect must satisfy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectOriginPolicy {
    /// Reject any redirect that leaves the current origin (scheme + host +
    /// port). Strictest: use for fetches that must never leave the initial
    /// service.
    SameOrigin,
    /// Allow redirects to any `http`/`https` origin. The URL is still parsed
    /// and must be a valid [`HttpUrl`]; the resolved-IP check (SSRF) is the
    /// caller's job per hop.
    AnyHttpOrigin,
}

/// A redirect-target validation error.
#[derive(Debug, thiserror::Error)]
pub enum RedirectTargetError {
    /// The `Location` could not be parsed / joined into a valid URL reference.
    #[error("invalid redirect location: {0}")]
    Invalid(#[from] UrlError),
    /// The resolved target left the allowed origin (policy = `SameOrigin`).
    #[error("redirect escapes origin: resolved {resolved}, expected {expected}")]
    DifferentOrigin {
        /// The origin the redirect resolved to.
        resolved: String,
        /// The origin the policy required.
        expected: String,
    },
}

impl From<url::ParseError> for RedirectTargetError {
    fn from(err: url::ParseError) -> Self {
        Self::Invalid(UrlError::Parse(err))
    }
}

/// Validate a redirect `Location` against the current URL under a policy.
///
/// Resolves `location` (absolute or relative) against `current`, parses the
/// result as an [`HttpUrl`] (http/https with a host), and — for
/// [`RedirectOriginPolicy::SameOrigin`] — checks the origin matches
/// `current`. Returns the validated target URL to fetch next.
///
/// # Errors
///
/// [`RedirectTargetError::Invalid`] for an unparseable/non-http location;
/// [`RedirectTargetError::DifferentOrigin`] for a same-origin-policy escape.
///
/// # Examples
///
/// ```
/// use utils::net::redirect::{RedirectOriginPolicy, safe_redirect_target};
/// use utils::net::url_ext::HttpUrl;
///
/// let current = HttpUrl::parse("https://api.example.com/v1").unwrap();
/// // Relative redirect, same origin — accepted.
/// let next = safe_redirect_target(&current, "/v2", RedirectOriginPolicy::SameOrigin).unwrap();
/// assert_eq!(next.as_url().as_str(), "https://api.example.com/v2");
/// // Cross-origin redirect under SameOrigin — rejected.
/// let err = safe_redirect_target(&current, "https://evil.com/x", RedirectOriginPolicy::SameOrigin).unwrap_err();
/// assert!(matches!(err, utils::net::redirect::RedirectTargetError::DifferentOrigin { .. }));
/// ```
pub fn safe_redirect_target(
    current: &HttpUrl,
    location: &str,
    policy: RedirectOriginPolicy,
) -> Result<HttpUrl, RedirectTargetError> {
    match policy {
        // Any http(s) origin: join + parse only (the Layer-0 primitive).
        RedirectOriginPolicy::AnyHttpOrigin => {
            crate::net::url_ext::join_and_parse(current, location)
                .map_err(RedirectTargetError::Invalid)
        },
        // Same origin: delegate to the Layer-0 same-origin join, mapping its
        // error back. (No re-implementation of the join or origin compare.)
        RedirectOriginPolicy::SameOrigin => {
            crate::net::url_ext::join_same_origin(current, location).map_err(|e| match e {
                UrlError::DifferentOrigin { resolved } => {
                    // expected = current's origin string (built only on reject).
                    let expected = crate::net::origin::PublicHttpOrigin::from_url(current).as_str();
                    RedirectTargetError::DifferentOrigin { resolved, expected }
                },
                other => RedirectTargetError::Invalid(other),
            })
        },
    }
}

#[cfg(test)]
mod tests {
    //! Boundary + edge-negative proof for redirect-target validation.
    //!
    //! Oracle: RFC 7231 allows relative and absolute `Location` values; a
    //! same-origin policy must reject scheme/host/port changes and protocol
    //! smuggling (`//evil`, `javascript:`, `file:`), while accepting same-origin
    //! relative redirects. AnyHttpOrigin still rejects non-http schemes.

    use super::*;

    fn base() -> HttpUrl {
        HttpUrl::parse("https://api.example.com/v1/start").unwrap()
    }

    #[test]
    fn same_origin_relative_redirect_accepted() {
        let next = safe_redirect_target(&base(), "/v2", RedirectOriginPolicy::SameOrigin).unwrap();
        assert_eq!(next.as_url().as_str(), "https://api.example.com/v2");
    }

    #[test]
    fn same_origin_relative_with_query_accepted() {
        let next =
            safe_redirect_target(&base(), "next?page=2", RedirectOriginPolicy::SameOrigin).unwrap();
        assert_eq!(
            next.as_url().as_str(),
            "https://api.example.com/v1/next?page=2"
        );
    }

    #[test]
    fn same_origin_scheme_relative_rejected_as_escape() {
        // `//evil.com` would change the host → DifferentOrigin, not a smuggled URL.
        let err = safe_redirect_target(&base(), "//evil.com/x", RedirectOriginPolicy::SameOrigin)
            .unwrap_err();
        assert!(matches!(err, RedirectTargetError::DifferentOrigin { .. }));
    }

    #[test]
    fn same_origin_cross_host_rejected() {
        let err = safe_redirect_target(
            &base(),
            "https://evil.com/x",
            RedirectOriginPolicy::SameOrigin,
        )
        .unwrap_err();
        assert!(matches!(err, RedirectTargetError::DifferentOrigin { .. }));
    }

    #[test]
    fn same_origin_scheme_downgrade_rejected() {
        // http vs https is a different origin (scheme is part of origin).
        let err = safe_redirect_target(
            &base(),
            "http://api.example.com/v1",
            RedirectOriginPolicy::SameOrigin,
        )
        .unwrap_err();
        assert!(matches!(err, RedirectTargetError::DifferentOrigin { .. }));
    }

    #[test]
    fn same_origin_port_change_rejected() {
        let err = safe_redirect_target(
            &base(),
            "https://api.example.com:8443/v1",
            RedirectOriginPolicy::SameOrigin,
        )
        .unwrap_err();
        assert!(matches!(err, RedirectTargetError::DifferentOrigin { .. }));
    }

    #[test]
    fn non_http_scheme_rejected_under_any_policy() {
        // `javascript:` / `file:` are not http(s) — HttpUrl::parse rejects them.
        let err = safe_redirect_target(
            &base(),
            "javascript:alert(1)",
            RedirectOriginPolicy::AnyHttpOrigin,
        )
        .unwrap_err();
        assert!(matches!(err, RedirectTargetError::Invalid(_)));
    }

    #[test]
    fn any_origin_accepts_cross_host() {
        let next = safe_redirect_target(
            &base(),
            "https://other.example/y",
            RedirectOriginPolicy::AnyHttpOrigin,
        )
        .unwrap();
        assert_eq!(next.as_url().as_str(), "https://other.example/y");
    }
}
