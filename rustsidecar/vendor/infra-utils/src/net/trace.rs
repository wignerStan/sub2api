//! W3C `traceparent` parse/validate — RFC-style distributed-trace context.
//!
//! [`TraceContext`] parses a W3C Trace Context `traceparent` header value
//! (`version-trace-id-span-id-flags`) without each app hand-rolling it. Pure
//! string/hex parsing — no `http` crate, no axum — so it stays usable in both
//! inbound (api-serve header extractors) and outbound (egress-client propagating a
//! trace into a fetch) contexts.
//!
//! Format (W3C Trace Context level 1):
//! ```text
//! traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
//!              ^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^^ ^^
//!              version (2 hex)   trace-id (32 hex)  span-id (16 hex)  flags (2 hex)
//! ```
//! `trace-id` all-zero and `span-id` all-zero are invalid per the spec.

/// A parsed W3C `traceparent` value.
///
/// Lowercase hex strings, validated to spec lengths + non-zero IDs. `Clone` so
/// a handler can fork child spans; the fields are pure data, no lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    /// The trace-id (32 lowercase hex chars / 16 bytes). Non-zero.
    trace_id: String,
    /// The span/parent-id (16 lowercase hex chars / 8 bytes). Non-zero.
    span_id: String,
    /// The trace-flags byte as a `u8` (bit 0 = sampled).
    flags: u8,
}

/// Errors from [`TraceContext::parse`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TraceContextError {
    /// The value did not have exactly four `-`-separated fields.
    #[error("traceparent must be version-traceid-spanid-flags (4 dash fields)")]
    BadFormat,
    /// The version field is not exactly 2 hex chars.
    #[error("version must be 2 hex chars")]
    BadVersion,
    /// The trace-id is not 32 hex chars or is all-zero.
    #[error("trace-id must be 32 non-zero hex chars")]
    BadTraceId,
    /// The span-id is not 16 hex chars or is all-zero.
    #[error("span-id must be 16 non-zero hex chars")]
    BadSpanId,
    /// The flags field is not 2 hex chars.
    #[error("flags must be 2 hex chars")]
    BadFlags,
    /// The version is `255` (0xff), reserved as invalid by the spec.
    #[error("version 255 is reserved")]
    ReservedVersion,
}

impl TraceContext {
    /// Parse a `traceparent` header value.
    ///
    /// # Errors
    ///
    /// [`TraceContextError`] for any deviation from the W3C format (field
    /// count, hex length, all-zero IDs, reserved version 255).
    ///
    /// # Examples
    ///
    /// ```
    /// use utils::net::trace::TraceContext;
    /// let ctx = TraceContext::parse("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01").unwrap();
    /// assert_eq!(ctx.trace_id(), "0af7651916cd43dd8448eb211c80319c");
    /// assert_eq!(ctx.span_id(), "b7ad6b7169203331");
    /// assert!(ctx.sampled());
    /// ```
    pub fn parse(value: &str) -> Result<Self, TraceContextError> {
        let mut parts = value.split('-');
        let version = parts.next().ok_or(TraceContextError::BadFormat)?;
        let trace_id = parts.next().ok_or(TraceContextError::BadFormat)?;
        let span_id = parts.next().ok_or(TraceContextError::BadFormat)?;
        let flags = parts.next().ok_or(TraceContextError::BadFormat)?;
        if parts.next().is_some() {
            return Err(TraceContextError::BadFormat);
        }

        if version.len() != 2 || !version.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(TraceContextError::BadVersion);
        }
        if version.eq_ignore_ascii_case("ff") {
            return Err(TraceContextError::ReservedVersion);
        }
        if !is_nonzero_hex(trace_id, 32) {
            return Err(TraceContextError::BadTraceId);
        }
        if !is_nonzero_hex(span_id, 16) {
            return Err(TraceContextError::BadSpanId);
        }
        if flags.len() != 2 || !flags.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(TraceContextError::BadFlags);
        }
        let flags_val = u8::from_str_radix(flags, 16).map_err(|_| TraceContextError::BadFlags)?;
        Ok(Self {
            trace_id: trace_id.to_ascii_lowercase(),
            span_id: span_id.to_ascii_lowercase(),
            flags: flags_val,
        })
    }

    /// The trace-id (32 lowercase hex chars).
    #[must_use]
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// The span/parent-id (16 lowercase hex chars).
    #[must_use]
    pub fn span_id(&self) -> &str {
        &self.span_id
    }

    /// Whether the sampled flag (bit 0) is set.
    #[must_use]
    pub const fn sampled(&self) -> bool {
        self.flags & 0x01 == 0x01
    }

    /// Render the value back to its canonical `traceparent` string.
    #[must_use]
    pub fn to_header(&self) -> String {
        format!("00-{}-{}-{:02x}", self.trace_id, self.span_id, self.flags)
    }
}

/// `s` must be exactly `len` lowercase/uppercase hex chars and not all-zero.
fn is_nonzero_hex(s: &str, len: usize) -> bool {
    if s.len() != len || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    s.chars().any(|c| c != '0')
}

#[cfg(test)]
mod tests {
    //! W3C conformance proof for `traceparent` parsing: the canonical example,
    //! the sampled flag, and every spec rejection (bad field count, bad hex
    //! length, all-zero IDs, reserved version).

    use super::*;

    const VALID: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

    #[test]
    fn parses_canonical_example() {
        let ctx = TraceContext::parse(VALID).unwrap();
        assert_eq!(ctx.trace_id(), "0af7651916cd43dd8448eb211c80319c");
        assert_eq!(ctx.span_id(), "b7ad6b7169203331");
        assert!(ctx.sampled());
    }

    #[test]
    fn not_sampled_when_flags_zero() {
        let ctx =
            TraceContext::parse("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00").unwrap();
        assert!(!ctx.sampled());
    }

    #[test]
    fn round_trips_to_header() {
        let ctx = TraceContext::parse(VALID).unwrap();
        assert_eq!(ctx.to_header(), VALID);
    }

    #[test]
    fn rejects_wrong_field_count() {
        assert!(matches!(
            TraceContext::parse("00-trace-span"),
            Err(TraceContextError::BadFormat)
        ));
        assert!(matches!(
            TraceContext::parse("00-trace-span-01-extra"),
            Err(TraceContextError::BadFormat)
        ));
    }

    #[test]
    fn rejects_all_zero_trace_id() {
        let bad = "00-00000000000000000000000000000000-b7ad6b7169203331-01";
        assert!(matches!(
            TraceContext::parse(bad),
            Err(TraceContextError::BadTraceId)
        ));
    }

    #[test]
    fn rejects_all_zero_span_id() {
        let bad = "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01";
        assert!(matches!(
            TraceContext::parse(bad),
            Err(TraceContextError::BadSpanId)
        ));
    }

    #[test]
    fn rejects_bad_trace_id_length() {
        let bad = "00-deadbeef-b7ad6b7169203331-01";
        assert!(matches!(
            TraceContext::parse(bad),
            Err(TraceContextError::BadTraceId)
        ));
    }

    #[test]
    fn rejects_reserved_version_ff() {
        let bad = "ff-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        assert!(matches!(
            TraceContext::parse(bad),
            Err(TraceContextError::ReservedVersion)
        ));
    }

    #[test]
    fn rejects_non_hex_flags() {
        let bad = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-zz";
        assert!(matches!(
            TraceContext::parse(bad),
            Err(TraceContextError::BadFlags)
        ));
    }

    #[test]
    fn uppercase_hex_normalized_to_lowercase() {
        let ctx =
            TraceContext::parse("00-0AF7651916CD43DD8448EB211C80319C-B7AD6B7169203331-01").unwrap();
        assert_eq!(ctx.trace_id(), "0af7651916cd43dd8448eb211c80319c");
    }
}
