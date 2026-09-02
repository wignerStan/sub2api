//! `PublicHttpOrigin` — a validated `http(s)://host[:port]` origin value type.
//!
//! An *origin* (RFC 6454) is `scheme://host[:port]`; a bare `String` lets a
//! scheme change (`http` vs `https`) or a host swap slip through an origin
//! comparison. [`PublicHttpOrigin`] parses to a canonical origin and is the
//! value type compared in same-origin / allowed-origin checks.
//!
//! Pure: validates scheme (http/https) + non-empty host + port. The
//! *public-IP* part of "public" (the resolved IP is global, not private) is
//! the safe-egress executor's per-hop job via [`crate::net::ssrf`]; this type
//! is the syntactic origin gate that runs first.

use crate::net::url_ext::HttpUrl;

/// Errors from [`PublicHttpOrigin::parse`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OriginError {
    /// The URL was not a valid http(s) URL with a host.
    #[error("invalid http(s) origin")]
    Invalid,
    /// The origin string was malformed.
    #[error("origin parse error: {0}")]
    Parse(String),
}

/// A validated `http(s)://host[:port]` origin.
///
/// Construct via [`PublicHttpOrigin::parse`] (from a URL string) or
/// [`PublicHttpOrigin::from_url`] (from an [`HttpUrl`]). Two origins compare
/// equal only when scheme + host + port all match.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicHttpOrigin {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl PublicHttpOrigin {
    /// Parse an absolute `http(s)` URL into a canonical origin.
    ///
    /// # Errors
    ///
    /// [`OriginError::Invalid`] for a non-http(s) / hostless URL;
    /// [`OriginError::Parse`] for a malformed string.
    ///
    /// # Examples
    ///
    /// ```
    /// use utils::net::origin::PublicHttpOrigin;
    /// let o = PublicHttpOrigin::parse("https://api.example.com:8443/v1").unwrap();
    /// assert_eq!(o.as_str(), "https://api.example.com:8443");
    /// ```
    pub fn parse(input: &str) -> Result<Self, OriginError> {
        let url = crate::net::url_ext::HttpUrl::parse(input).map_err(|_| OriginError::Invalid)?;
        if url.host_str().is_empty() {
            return Err(OriginError::Invalid);
        }
        Ok(Self::from_url(&url))
    }

    /// Build a canonical origin from an [`HttpUrl`].
    #[must_use]
    pub fn from_url(url: &HttpUrl) -> Self {
        Self {
            scheme: url.scheme().to_owned(),
            host: url.host_str().to_owned(),
            port: url.port(),
        }
    }

    /// The scheme (`http` or `https`).
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The explicit port, if the origin carries one.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    /// The default port for this origin's scheme (`80` / `443`).
    #[must_use]
    pub fn default_port(&self) -> u16 {
        default_port_for_scheme(self.scheme())
    }

    /// The effective port (explicit, else the scheme default).
    #[must_use]
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or_else(|| self.default_port())
    }

    /// Render the canonical origin string (`scheme://host[:port]`).
    #[must_use]
    pub fn as_str(&self) -> String {
        match self.port {
            Some(p) => format!("{}://{}:{p}", self.scheme, self.host),
            None => format!("{}://{}", self.scheme, self.host),
        }
    }
}

/// Default port for an http(s) scheme.
///
/// The single source of truth for the `80`/`443` default. Reachable without
/// owning a [`PublicHttpOrigin`] (callers holding only a scheme slice — e.g.
/// from [`HttpUrl::scheme`](crate::net::url_ext::HttpUrl::scheme) in a tight
/// loop) get the same value as the typed method, with no allocation and no
/// type conversion.
#[must_use]
pub fn default_port_for_scheme(scheme: &str) -> u16 {
    if scheme == "https" { 443 } else { 80 }
}

impl std::fmt::Display for PublicHttpOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_origin_stripping_path_and_query() {
        let o = PublicHttpOrigin::parse("https://api.example.com:8443/v1?x=1").unwrap();
        assert_eq!(o.scheme(), "https");
        assert_eq!(o.host(), "api.example.com");
        assert_eq!(o.port(), Some(8443));
        assert_eq!(o.as_str(), "https://api.example.com:8443");
    }

    #[test]
    fn origin_without_explicit_port_uses_default() {
        let o = PublicHttpOrigin::parse("https://api.example.com").unwrap();
        assert_eq!(o.port(), None);
        assert_eq!(o.effective_port(), 443);
        assert_eq!(o.as_str(), "https://api.example.com");
    }

    #[test]
    fn http_default_port_is_80() {
        let o = PublicHttpOrigin::parse("http://api.example.com").unwrap();
        assert_eq!(o.effective_port(), 80);
    }

    #[test]
    fn origin_equality_is_scheme_host_port() {
        // https vs http differ (scheme is part of origin).
        assert_ne!(
            PublicHttpOrigin::parse("https://a.test").unwrap(),
            PublicHttpOrigin::parse("http://a.test").unwrap()
        );
        // Port differs.
        assert_ne!(
            PublicHttpOrigin::parse("https://a.test:1").unwrap(),
            PublicHttpOrigin::parse("https://a.test:2").unwrap()
        );
        // Same origin.
        assert_eq!(
            PublicHttpOrigin::parse("https://a.test/x").unwrap(),
            PublicHttpOrigin::parse("https://a.test/y").unwrap()
        );
    }

    #[test]
    fn rejects_non_http_scheme() {
        assert!(PublicHttpOrigin::parse("ftp://a.test").is_err());
    }

    // -- property tests (P7) -------------------------------------------------

    proptest::proptest! {
        /// A well-formed http(s) origin parses and preserves scheme + host.
        #[test]
        fn origin_parse_preserves_scheme_and_host(host in "[a-z][a-z0-9-]{0,8}\\.example") {
            for scheme in ["http", "https"] {
                let input = format!("{scheme}://{host}/deep/path?q=1#frag");
                let origin = PublicHttpOrigin::parse(&input).expect("valid origin parses");
                assert_eq!(origin.scheme(), scheme);
                assert_eq!(origin.host(), host);
            }
        }

        /// Two origins from paths on the same scheme+host+port are equal
        /// regardless of path/query.
        #[test]
        fn origin_equality_ignores_path_and_query(
            host in "[a-z][a-z0-9-]{0,8}\\.example",
            p1 in "[a-z]{1,5}",
            p2 in "[a-z]{1,5}"
        ) {
            let a = PublicHttpOrigin::parse(&format!("https://{host}/{p1}")).unwrap();
            let b = PublicHttpOrigin::parse(&format!("https://{host}/{p2}")).unwrap();
            assert_eq!(a, b, "same scheme+host+port must compare equal");
        }
    }
}
