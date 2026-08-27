//! `HostPort` — a validated host + port authority value type.
//!
//! An HTTP `Host`/authority is `host[:port]`; a bare `String` lets a typo'd or
//! hostile value (`evil.com:0`, `:9999`, `evil.com other`) slip through.
//! [`HostPort`] parses to a non-empty host + a port in the valid range
//! (`0..=65535`), exposing both and rendering back to `host:port`. Pure (no
//! DNS): it validates syntax only.

/// Errors from [`HostPort::parse`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HostPortError {
    /// The value had no host (empty, or starts with `:`).
    #[error("missing host")]
    MissingHost,
    /// The port was absent (a `host:port` authority requires the port).
    #[error("missing port")]
    MissingPort,
    /// The port was not a parseable `u16`.
    #[error("invalid port: {0}")]
    InvalidPort(String),
    /// The value had more than one `:` (ambiguous IPv6-without-brackets, or
    /// garbage like `a:b:80`).
    #[error("ambiguous authority: multiple ':' separators")]
    Ambiguous,
}

/// A validated `host:port` authority.
///
/// Construct via [`HostPort::parse`]; the host is non-empty and the port is
/// `0..=65535`. Pure syntactic validation — no DNS resolution or IP
/// classification (that's the caller's job, often via [`crate::net::ssrf`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostPort {
    host: String,
    port: u16,
}

impl HostPort {
    /// Parse `host:port` into a validated [`HostPort`].
    ///
    /// `host` must be non-empty; `port` must be present and a valid `u16`.
    /// An IPv6 literal must be bracketed (`[::1]:8080`).
    ///
    /// # Errors
    ///
    /// [`HostPortError`] for a missing host/port, an unparseable port, or an
    /// ambiguous multi-colon value.
    ///
    /// # Examples
    ///
    /// ```
    /// use utils::net::host_port::HostPort;
    /// let hp = HostPort::parse("example.com:8443").unwrap();
    /// assert_eq!(hp.host(), "example.com");
    /// assert_eq!(hp.port(), 8443);
    /// assert_eq!(hp.to_string(), "example.com:8443");
    /// ```
    pub fn parse(value: &str) -> Result<Self, HostPortError> {
        // Bracketed IPv6: [::1]:8080
        if let Some(rest) = value.strip_prefix('[') {
            let Some((host, tail)) = rest.split_once(']') else {
                return Err(HostPortError::MissingHost);
            };
            let Some(port_str) = tail.strip_prefix(':') else {
                return Err(HostPortError::MissingPort);
            };
            if host.is_empty() {
                return Err(HostPortError::MissingHost);
            }
            let port = parse_port(port_str)?;
            return Ok(Self {
                host: format!("[{host}]"),
                port,
            });
        }
        // Plain host:port — exactly one ':'.
        let mut parts = value.splitn(2, ':');
        let host = parts.next().unwrap_or("");
        if host.is_empty() {
            return Err(HostPortError::MissingHost);
        }
        let Some(port_str) = parts.next() else {
            return Err(HostPortError::MissingPort);
        };
        if port_str.contains(':') {
            return Err(HostPortError::Ambiguous);
        }
        let port = parse_port(port_str)?;
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    /// Build from an already-validated host + port.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// The host (as it appeared, including `[...]` for an IPv6 literal).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port (`0..=65535`).
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// Parse a port string into `u16`.
fn parse_port(s: &str) -> Result<u16, HostPortError> {
    s.parse::<u16>()
        .map_err(|_| HostPortError::InvalidPort(s.to_owned()))
}

impl std::fmt::Display for HostPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_port() {
        let hp = HostPort::parse("example.com:8443").unwrap();
        assert_eq!(hp.host(), "example.com");
        assert_eq!(hp.port(), 8443);
        assert_eq!(hp.to_string(), "example.com:8443");
    }

    #[test]
    fn parses_bracketed_ipv6() {
        let hp = HostPort::parse("[::1]:8080").unwrap();
        assert_eq!(hp.host(), "[::1]");
        assert_eq!(hp.port(), 8080);
    }

    #[test]
    fn rejects_missing_host() {
        assert_eq!(
            HostPort::parse(":80").unwrap_err(),
            HostPortError::MissingHost
        );
        assert_eq!(HostPort::parse("").unwrap_err(), HostPortError::MissingHost);
    }

    #[test]
    fn rejects_missing_port() {
        assert_eq!(
            HostPort::parse("example.com").unwrap_err(),
            HostPortError::MissingPort
        );
    }

    #[test]
    fn rejects_bad_port() {
        let err = HostPort::parse("example.com:99999").unwrap_err();
        assert!(matches!(err, HostPortError::InvalidPort(_)));
    }

    #[test]
    fn rejects_ambiguous_multi_colon() {
        assert_eq!(
            HostPort::parse("a:b:80").unwrap_err(),
            HostPortError::Ambiguous
        );
    }
}
