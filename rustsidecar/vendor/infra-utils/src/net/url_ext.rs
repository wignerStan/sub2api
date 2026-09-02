//! URL helpers that return STRONGER types, not `Url::parse` renames.
//!
//! The rule: wrap `Url::parse` only when the wrapper returns a stronger type
//! that encodes a policy. [`HttpUrl`] is an absolute `http`/`https` URL with a
//! host — the smallest type safe to fetch. [`join_same_origin`] wraps
//! `Url::join` and rejects inputs that escape the base origin (`//evil.com`,
//! `http://evil.com`), which `Url::join` silently allows.
//!
//! `Url::parse` validates syntax but does NOT mean "safe to fetch"; callers
//! needing fetch safety compose [`HttpUrl`] with the SSRF resolver in [`crate
//! ::net::ssrf`] (and, for the connect/fetch step, an egress client in
//! `egress-client`).

use std::fmt;

// `Url` appears in the stronger `HttpUrl` API, but this module does not
// re-export the external namespace. A caller that needs to name or construct a
// raw URL depends on `url` directly.
use url::Url;

/// Errors from [`HttpUrl`] construction / [`join_same_origin`].
#[derive(Debug, thiserror::Error)]
pub enum UrlError {
    /// Input was empty or whitespace-only.
    #[error("cannot parse url: empty input")]
    Empty,
    /// `url::Url::parse` returned a syntax error.
    #[error("cannot parse url: {0}")]
    Parse(#[from] url::ParseError),
    /// Parsed OK but the scheme is not `http` or `https`.
    #[error("unsupported scheme: {0}")]
    UnsupportedScheme(String),
    /// Parsed OK but no host component present.
    #[error("cannot parse url: empty host")]
    NoHost,
    /// A [`join_same_origin`] input resolved to a different origin than the base.
    #[error("join escaped base origin: {resolved}")]
    DifferentOrigin {
        /// The resolved (wrong-origin) URL string.
        resolved: String,
    },
}

/// An absolute `http`/`https` URL with a non-empty host.
///
/// Construct via [`HttpUrl::parse`]. Once constructed, the type guarantees the
/// scheme and host — the smallest URL type that is meaningful to fetch. This is
/// the input to the SSRF resolution path in [`crate::net::ssrf`].
///
/// Not a fetch-safety guarantee on its own: a public-looking domain may still
/// resolve to a private IP. Pair with `ResolvedPublicHttpTarget` (in the
/// tokio-backed egress layer) for that.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpUrl(Url);

impl HttpUrl {
    /// Parse an absolute `http`/`https` URL, requiring a non-empty host.
    ///
    /// Rejects empty input, non-http schemes, and missing hosts in one call —
    /// the OWASP "enforce scheme + host" baseline.
    ///
    /// # Errors
    ///
    /// [`UrlError::Empty`] on blank input, [`UrlError::Parse`] on syntax errors,
    /// [`UrlError::UnsupportedScheme`] on non-http schemes, [`UrlError::NoHost`]
    /// when the host component is absent.
    pub fn parse(input: &str) -> Result<Self, UrlError> {
        if input.trim().is_empty() {
            return Err(UrlError::Empty);
        }
        let url = Url::parse(input)?;
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(UrlError::UnsupportedScheme(scheme.to_owned()));
        }
        if url.host_str().is_none_or(str::is_empty) {
            return Err(UrlError::NoHost);
        }
        Ok(Self(url))
    }

    /// Borrow the underlying [`Url`].
    #[must_use]
    pub fn as_url(&self) -> &Url {
        &self.0
    }

    /// Consume into the underlying [`Url`].
    #[must_use]
    pub fn into_url(self) -> Url {
        self.0
    }

    /// The URL scheme (`http` or `https`).
    #[must_use]
    pub fn scheme(&self) -> &str {
        self.0.scheme()
    }

    /// The host string, guaranteed non-empty by construction.
    #[must_use]
    pub fn host_str(&self) -> &str {
        // SAFETY: parse() rejects empty/absent hosts, and Url is immutable here.
        self.0.host_str().unwrap_or("")
    }

    /// The explicit port, if present in the URL.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.0.port()
    }
}

impl fmt::Display for HttpUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<Url> for HttpUrl {
    fn as_ref(&self) -> &Url {
        &self.0
    }
}

/// Join `location` onto `base` and re-parse the result as an [`HttpUrl`].
///
/// The pure join+parse step shared by [`join_same_origin`] and (via
/// `redirect.rs`) `safe_redirect_target`. Rejects non-http(s)/hostless targets
/// via the [`HttpUrl::parse`] gate.
pub(crate) fn join_and_parse(base: &HttpUrl, location: &str) -> Result<HttpUrl, UrlError> {
    let resolved = base.0.join(location)?;
    HttpUrl::parse(resolved.as_str())
}

/// Join `input` onto `base` and require the result to stay on the same origin.
///
/// `Url::join` intentionally lets scheme-relative (`//evil.com/x`) and absolute
/// (`http://evil.com/x`) inputs replace the base scheme/host — a real bug source
/// for redirect/link resolution. This wrapper runs the join then re-checks
/// scheme + host + port, returning [`UrlError::DifferentOrigin`] on escape.
///
/// # Errors
///
/// [`UrlError::Parse`] if `input` is not a valid URL reference;
/// [`UrlError::DifferentOrigin`] if the resolved URL's scheme/host/port differ
/// from `base`.
pub fn join_same_origin(base: &HttpUrl, input: &str) -> Result<HttpUrl, UrlError> {
    let target = join_and_parse(base, input)?;
    // same-origin = scheme + host + port all equal (field compare, not a string).
    if target.scheme() == base.scheme()
        && target.host_str() == base.host_str()
        && target.port() == base.port()
    {
        Ok(target)
    } else {
        Err(UrlError::DifferentOrigin {
            resolved: target.as_url().to_string(),
        })
    }
}

/// Redact embedded credentials (userinfo) from a URL-ish string.
///
/// For a string carrying `user:password@` (Postgres/Redis/HTTP basic-auth DSNs,
/// etc.), returns the same URL with the username/password replaced by
/// `<redacted>` so it is safe to log. The host, port, path, and query remain —
/// they are useful for diagnostics. A string with NO credentials is returned
/// verbatim (parsed then re-serialized, so the canonical form). If the input is
/// not parseable as a URL, a fixed placeholder is returned — **never** the raw
/// input (which may itself contain a credential the caller wanted to redact).
///
/// Use the [`RedactedUrl`] display wrapper when you want to avoid allocating a
/// `String` purely for logging.
///
/// # Examples
/// ```
/// # use utils::net::url_ext::redact_url_credentials;
/// assert_eq!(
///     redact_url_credentials("postgres://alice:s3cr3t@localhost:5432/app"),
///     "postgres://redacted:redacted@localhost:5432/app",
/// );
/// // No credentials → unchanged (canonical re-serialization only).
/// assert_eq!(redact_url_credentials("sqlite:///tmp/app.db?mode=rwc"), "sqlite:///tmp/app.db?mode=rwc");
/// // Unparseable → placeholder, never the raw input.
/// assert_eq!(redact_url_credentials("not a url"), "<redacted-unparseable-url>");
/// ```
#[must_use]
pub fn redact_url_credentials(input: &str) -> String {
    let Ok(mut url) = Url::parse(input) else {
        return "<redacted-unparseable-url>".to_string();
    };
    // Replace with the unreserved token `redacted` (letters only) so the URL
    // serializer does NOT percent-encode it into `%3Credacted%3E` — the output
    // stays readable for diagnostics.
    if !url.username().is_empty() {
        let _ = url.set_username("redacted");
    }
    if url.password().is_some() {
        let _ = url.set_password(Some("redacted"));
    }
    url.to_string()
}

/// A display wrapper that redacts credentials on demand — no `String` allocation.
///
/// Use with structured logging so the raw secret-bearing string is never
/// materialized into a loggable form:
///
/// ```ignore
/// info!(dsn = %utils::net::url_ext::RedactedUrl(dsn), "Opening database");
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RedactedUrl<'a>(pub &'a str);

impl fmt::Display for RedactedUrl<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&redact_url_credentials(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_url_parse_valid() {
        let u = HttpUrl::parse("https://example.com/path").unwrap();
        assert_eq!(u.scheme(), "https");
        assert_eq!(u.host_str(), "example.com");
        assert_eq!(u.port(), None);
    }

    #[test]
    fn http_url_parse_with_port() {
        let u = HttpUrl::parse("http://localhost:8080/api").unwrap();
        assert_eq!(u.host_str(), "localhost");
        assert_eq!(u.port(), Some(8080));
    }

    #[test]
    fn http_url_parse_rejects_empty() {
        assert!(matches!(HttpUrl::parse(""), Err(UrlError::Empty)));
        assert!(matches!(HttpUrl::parse("   "), Err(UrlError::Empty)));
    }

    #[test]
    fn http_url_parse_rejects_non_http_scheme() {
        assert!(matches!(
            HttpUrl::parse("ftp://files.example.com"),
            Err(UrlError::UnsupportedScheme(_))
        ));
    }

    #[test]
    fn normalized_origin_with_and_without_port() {
        let no_port = HttpUrl::parse("https://example.com/x").unwrap();
        assert_eq!(
            crate::net::origin::PublicHttpOrigin::from_url(&no_port).as_str(),
            "https://example.com"
        );
        let port = HttpUrl::parse("https://example.com:8443/x").unwrap();
        assert_eq!(
            crate::net::origin::PublicHttpOrigin::from_url(&port).as_str(),
            "https://example.com:8443"
        );
    }

    #[test]
    fn join_same_origin_relative_path() {
        let base = HttpUrl::parse("https://example.com/a/b").unwrap();
        let joined = join_same_origin(&base, "c/d").unwrap();
        assert_eq!(joined.as_url().as_str(), "https://example.com/a/c/d");
    }

    #[test]
    fn join_same_origin_absolute_path() {
        let base = HttpUrl::parse("https://example.com/a/b").unwrap();
        let joined = join_same_origin(&base, "/x/y").unwrap();
        assert_eq!(joined.as_url().as_str(), "https://example.com/x/y");
    }

    #[test]
    fn join_same_origin_rejects_scheme_relative() {
        let base = HttpUrl::parse("https://example.com/a").unwrap();
        // `//evil.com/x` would replace the host.
        assert!(matches!(
            join_same_origin(&base, "//evil.com/x"),
            Err(UrlError::DifferentOrigin { .. })
        ));
    }

    #[test]
    fn join_same_origin_rejects_absolute_url() {
        let base = HttpUrl::parse("https://example.com/a").unwrap();
        assert!(matches!(
            join_same_origin(&base, "http://evil.com/x"),
            Err(UrlError::DifferentOrigin { .. })
        ));
    }

    #[test]
    fn join_same_origin_rejects_scheme_change() {
        let base = HttpUrl::parse("https://example.com/a").unwrap();
        // `http:`-prefixed absolute reference changes scheme but keeps host.
        assert!(matches!(
            join_same_origin(&base, "http://example.com/x"),
            Err(UrlError::DifferentOrigin { .. })
        ));
    }

    // --- redact_url_credentials / RedactedUrl ---

    #[test]
    fn redact_replaces_postgres_user_password() {
        assert_eq!(
            redact_url_credentials("postgres://user:pass@localhost/db"),
            "postgres://redacted:redacted@localhost/db"
        );
    }

    #[test]
    fn redact_handles_url_encoded_password_and_keeps_query() {
        // `p%40ss` is a URL-encoded password; the host/port/path/query survive.
        let out =
            redact_url_credentials("postgresql://user:p%40ss@localhost:5432/db?sslmode=require");
        assert!(out.starts_with("postgresql://redacted:redacted@localhost:5432/db?"));
        assert!(out.contains("sslmode=require"));
        // The encoded password must NOT leak into the output.
        assert!(!out.contains("p%40ss"));
        assert!(!out.contains("pass"));
    }

    #[test]
    fn redact_leaves_sqlite_dsn_unchanged() {
        // SQLite DSN has no userinfo — host/path/query stay useful for diagnostics.
        assert_eq!(
            redact_url_credentials("sqlite:///tmp/app.db?mode=rwc"),
            "sqlite:///tmp/app.db?mode=rwc"
        );
    }

    #[test]
    fn redact_unparseable_returns_placeholder_not_raw() {
        // Never echo the raw input (it might itself be a secret-bearing string).
        assert_eq!(
            redact_url_credentials("not a url"),
            "<redacted-unparseable-url>"
        );
    }

    #[test]
    fn redact_dropping_only_password_keeps_username_redacted() {
        // user with no password: username is still redacted (it can be a secret).
        assert_eq!(
            redact_url_credentials("postgres://alice@localhost:5432/app"),
            "postgres://redacted@localhost:5432/app"
        );
    }

    #[test]
    fn redacted_url_display_matches_function() {
        let dsn = "postgres://u:p@host:5432/db";
        assert_eq!(format!("{}", RedactedUrl(dsn)), redact_url_credentials(dsn));
    }

    // -- property tests (P7): HttpUrl parse/round-trip invariants ------------

    proptest::proptest! {
        /// A well-formed http(s) URL with a host parses and preserves scheme+host.
        #[test]
        fn http_url_parse_preserves_scheme_and_host(host in "[a-z][a-z0-9-]{0,8}\\.example") {
            for scheme in ["http", "https"] {
                let input = format!("{scheme}://{host}/path?q=1");
                let parsed = HttpUrl::parse(&input).expect("valid http(s) URL parses");
                assert_eq!(parsed.scheme(), scheme);
                assert_eq!(parsed.host_str(), host);
            }
        }

        /// `PublicHttpOrigin` round-trips: parsing the origin string yields the
        /// same scheme + host + explicit port.
        #[test]
        fn normalized_origin_round_trips(
            scheme in "(http|https)",
            host in "[a-z][a-z0-9-]{0,8}\\.example",
            port in 1u16..65535
        ) {
            let input = format!("{scheme}://{host}:{port}/x");
            let url = HttpUrl::parse(&input).expect("parse");
            let origin = crate::net::origin::PublicHttpOrigin::from_url(&url).as_str();
            let expected_prefix = format!("{scheme}://{host}:{port}");
            assert!(
                origin.starts_with(&expected_prefix),
                "origin {origin} should start with {expected_prefix}"
            );
        }
    }
}
