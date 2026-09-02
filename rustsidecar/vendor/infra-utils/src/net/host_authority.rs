//! `HostAuthority` — parse an HTTP `Host`/authority header value.
//!
//! [`HostPort`](super::host_port::HostPort) requires a port; a `Host` header
//! frequently carries a bare host with no port (the default port is implied by
//! the scheme). [`HostAuthority`] accepts both shapes and exposes the host and
//! the optional port, so a host-allowlist guard can compare structurally
//! instead of lowercasing a raw string and hoping the shapes line up.

/// Errors from [`HostAuthority::parse`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HostAuthorityError {
    /// The value had no host (empty, or starts with `:`).
    #[error("missing host")]
    MissingHost,
    /// The port was not a parseable `u16`.
    #[error("invalid port: {0}")]
    InvalidPort(String),
    /// The value had more than one `:` outside a bracketed IPv6 literal.
    #[error("ambiguous authority: multiple ':' separators")]
    Ambiguous,
}

/// A parsed HTTP `Host`/authority value: a host plus an optional port.
///
/// Construct via [`HostAuthority::parse`]. The host is lowercased and stored
/// without the IPv6 brackets (so `[::1]` and `::1` compare equal). The port is
/// `Some` only when the input carried one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostAuthority {
    host: String,
    port: Option<u16>,
}

impl HostAuthority {
    /// Parse an HTTP `Host`/authority header value.
    ///
    /// Accepts `host`, `host:port`, `[ipv6]`, and `[ipv6]:port`. The host is
    /// lowercased; IPv6 brackets are stripped for storage and re-added on
    /// display. The port is optional and validated to `0..=65535`.
    ///
    /// # Errors
    ///
    /// [`HostAuthorityError`] for a missing host, an unparseable port, or an
    /// ambiguous multi-colon value outside an IPv6 literal.
    ///
    /// # Examples
    ///
    /// ```
    /// use utils::net::host_authority::HostAuthority;
    /// let a = HostAuthority::parse("Example.COM").unwrap();
    /// assert_eq!(a.host(), "example.com");
    /// assert!(a.port().is_none());
    /// let b = HostAuthority::parse("[::1]:8080").unwrap();
    /// assert_eq!(b.host(), "::1");
    /// assert_eq!(b.port(), Some(8080));
    /// ```
    pub fn parse(value: &str) -> Result<Self, HostAuthorityError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(HostAuthorityError::MissingHost);
        }
        // Bracketed IPv6: [::1] or [::1]:port
        if let Some(rest) = trimmed.strip_prefix('[') {
            let Some((host, tail)) = rest.split_once(']') else {
                return Err(HostAuthorityError::MissingHost);
            };
            if host.is_empty() {
                return Err(HostAuthorityError::MissingHost);
            }
            let port = if tail.is_empty() {
                None
            } else if let Some(port_str) = tail.strip_prefix(':') {
                if port_str.contains(':') {
                    return Err(HostAuthorityError::Ambiguous);
                }
                Some(parse_port(port_str)?)
            } else {
                return Err(HostAuthorityError::Ambiguous);
            };
            return Ok(Self {
                host: host.to_ascii_lowercase(),
                port,
            });
        }
        // Plain host[:port]. A bare IPv6 literal without brackets has multiple
        // ':' and is rejected as Ambiguous — the bracketed form is required.
        let mut parts = trimmed.splitn(2, ':');
        let host = parts.next().unwrap_or("");
        if host.is_empty() {
            return Err(HostAuthorityError::MissingHost);
        }
        let port_str = parts.next();
        if let Some(p) = port_str {
            if p.contains(':') {
                return Err(HostAuthorityError::Ambiguous);
            }
            let port = parse_port(p)?;
            return Ok(Self {
                host: host.to_ascii_lowercase(),
                port: Some(port),
            });
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port: None,
        })
    }

    /// Build from an already-validated host + optional port. Lowercases the host.
    #[must_use]
    pub fn new(host: impl Into<String>, port: Option<u16>) -> Self {
        Self {
            host: host.into().to_ascii_lowercase(),
            port,
        }
    }

    /// The host, lowercased and without IPv6 brackets.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, if the input carried one.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    /// Render back to a canonical `host[:port]` form (IPv6 re-bracketed).
    #[must_use]
    pub fn to_authority_string(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match self.port {
            Some(p) => format!("{host}:{p}"),
            None => host,
        }
    }

    /// Structural case-insensitive equality with a raw `host[:port]` input.
    ///
    /// Parses `other` and compares host + port; `Err` means `other` is
    /// malformed and is therefore not equal.
    pub fn eq_raw(&self, other: &str) -> bool {
        match Self::parse(other) {
            Ok(parsed) => self == &parsed,
            Err(_) => false,
        }
    }
}

impl std::fmt::Display for HostAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_authority_string())
    }
}

fn parse_port(s: &str) -> Result<u16, HostAuthorityError> {
    s.parse::<u16>()
        .map_err(|_| HostAuthorityError::InvalidPort(s.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_host() {
        let a = HostAuthority::parse("example.com").unwrap();
        assert_eq!(a.host(), "example.com");
        assert!(a.port().is_none());
    }

    #[test]
    fn parses_host_port() {
        let a = HostAuthority::parse("example.com:8443").unwrap();
        assert_eq!(a.host(), "example.com");
        assert_eq!(a.port(), Some(8443));
    }

    #[test]
    fn lowercases_host() {
        let a = HostAuthority::parse("EXAMPLE.COM").unwrap();
        assert_eq!(a.host(), "example.com");
    }

    #[test]
    fn parses_bracketed_ipv6_bare() {
        let a = HostAuthority::parse("[::1]").unwrap();
        assert_eq!(a.host(), "::1");
        assert!(a.port().is_none());
        assert_eq!(a.to_authority_string(), "[::1]");
    }

    #[test]
    fn parses_bracketed_ipv6_with_port() {
        let a = HostAuthority::parse("[::1]:8080").unwrap();
        assert_eq!(a.host(), "::1");
        assert_eq!(a.port(), Some(8080));
        assert_eq!(a.to_authority_string(), "[::1]:8080");
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(
            HostAuthority::parse("").unwrap_err(),
            HostAuthorityError::MissingHost
        );
        assert_eq!(
            HostAuthority::parse("   ").unwrap_err(),
            HostAuthorityError::MissingHost
        );
    }

    #[test]
    fn rejects_leading_colon() {
        assert_eq!(
            HostAuthority::parse(":80").unwrap_err(),
            HostAuthorityError::MissingHost
        );
    }

    #[test]
    fn rejects_bad_port() {
        assert!(matches!(
            HostAuthority::parse("example.com:99999").unwrap_err(),
            HostAuthorityError::InvalidPort(_)
        ));
    }

    #[test]
    fn rejects_ambiguous_multi_colon() {
        assert_eq!(
            HostAuthority::parse("a:b:80").unwrap_err(),
            HostAuthorityError::Ambiguous
        );
    }

    #[test]
    fn eq_raw_is_case_insensitive_and_shape_aware() {
        let a = HostAuthority::parse("example.com:8443").unwrap();
        assert!(a.eq_raw("EXAMPLE.COM:8443"));
        assert!(a.eq_raw("example.com:8443"));
        assert!(!a.eq_raw("example.com")); // port differs
        assert!(!a.eq_raw("evil.com"));
        assert!(!a.eq_raw("example.com:notaport")); // malformed
    }

    #[test]
    fn display_round_trips_through_authority_string() {
        let cases = [
            ("example.com", "example.com"),
            ("example.com:80", "example.com:80"),
            ("[::1]", "[::1]"),
            ("[::1]:443", "[::1]:443"),
        ];
        for (input, expected) in cases {
            let a = HostAuthority::parse(input).unwrap();
            assert_eq!(a.to_authority_string(), expected, "input: {input}");
            assert_eq!(a.to_string(), expected, "input: {input}");
        }
    }
}
