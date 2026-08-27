//! `TraceId` — the W3C 32-hex-char trace identifier newtype.
//!
//! A trace id identifies a distributed trace across services (W3C Trace
//! Context level 1). It is exactly 32 lowercase hex chars (16 bytes), non-zero,
//! distinct from a UUID-v7 [`crate::id::RequestId`] and from a span id. This
//! newtype makes an unvalidated `String`/`&str` trace id into a checked value
//! you can pass through spans without re-validating at every hop.

/// A W3C trace id: 32 lowercase hex chars, non-zero.
///
/// Construct via [`TraceId::parse`]; round-trip via [`TraceId::as_str`].
/// Composes with [`crate::net::trace::TraceContext`] (which carries the
/// trace id + span id + flags).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TraceId(String);

/// Errors from [`TraceId::parse`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TraceIdError {
    /// The value is not exactly 32 hex chars.
    #[error("trace id must be 32 hex chars")]
    BadLength,
    /// The value contains a non-hex char.
    #[error("trace id must be hex")]
    BadHex,
    /// The value is all zeros (invalid per W3C).
    #[error("trace id must be non-zero")]
    AllZero,
}

impl TraceId {
    /// Parse a W3C trace id: exactly 32 lowercase/uppercase hex chars,
    /// non-zero.
    ///
    /// # Errors
    ///
    /// [`TraceIdError`] on a length, charset, or all-zero violation.
    ///
    /// # Examples
    ///
    /// ```
    /// use utils::id::trace_id::TraceId;
    /// let id = TraceId::parse("0af7651916cd43dd8448eb211c80319c").unwrap();
    /// assert_eq!(id.as_str(), "0af7651916cd43dd8448eb211c80319c");
    /// ```
    pub fn parse(value: &str) -> Result<Self, TraceIdError> {
        if value.len() != 32 {
            return Err(TraceIdError::BadLength);
        }
        if !value.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(TraceIdError::BadHex);
        }
        if !value.chars().any(|c| c != '0') {
            return Err(TraceIdError::AllZero);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// The trace id as a 32-lowercase-hex string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TraceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "0af7651916cd43dd8448eb211c80319c";

    #[test]
    fn parses_valid_trace_id() {
        let id = TraceId::parse(VALID).unwrap();
        assert_eq!(id.as_str(), VALID);
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(
            TraceId::parse("deadbeef").unwrap_err(),
            TraceIdError::BadLength
        );
    }

    #[test]
    fn rejects_non_hex() {
        let bad = "zzf7651916cd43dd8448eb211c80319c";
        assert_eq!(TraceId::parse(bad).unwrap_err(), TraceIdError::BadHex);
    }

    #[test]
    fn rejects_all_zero() {
        let bad = "00000000000000000000000000000000";
        assert_eq!(TraceId::parse(bad).unwrap_err(), TraceIdError::AllZero);
    }

    #[test]
    fn normalizes_uppercase_to_lowercase() {
        let id = TraceId::parse("0AF7651916CD43DD8448EB211C80319C").unwrap();
        assert_eq!(id.as_str(), VALID);
    }
}
