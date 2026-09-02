//! Header-value validation: reject response-splitting / log-injection bytes.
//!
//! A header value is an arbitrary `String` until validated; a CR/LF in it
//! enables HTTP response splitting, and a control byte poisons logs. This
//! module's [`is_clean_header_value`] is the pure check that the inbound
//! facility (and any outbound-injecting code) runs before placing caller text
//! into a header. Pure (no `http` types) so both `utils` callers and
//! `egress-client` / `api-serve` reach it without a `http` dep on `utils`.

/// Whether `value` is safe to place in an HTTP header field value.
///
/// Rejects control bytes (`0x00`–`0x1F`, `0x7F`) and the response-splitting
/// separators CR (`0x0D`) / LF (`0x0A`), which are a subset of the control
/// range anyway. Visible ASCII (SP through `~`) passes. This is stricter than
/// RFC 7230 (which allows obs-text `0x80`–`0xFF`); the strict form is the
/// safe default for caller-supplied text — a known-good constant value may
/// use `HeaderValue::from_static` directly without this check.
#[must_use]
pub fn is_clean_header_value(value: &str) -> bool {
    value.bytes().all(|b| (b' '..=b'~').contains(&b))
}

/// Reject `value` if it is not a clean header value, returning the offending
/// byte's position for diagnostics.
///
/// # Errors
///
/// `Err(position)` of the first control/splitting byte.
pub fn validate_header_value(value: &str) -> Result<(), usize> {
    for (i, b) in value.bytes().enumerate() {
        if !(b' '..=b'~').contains(&b) {
            return Err(i);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_visible_ascii() {
        assert!(is_clean_header_value("bearer abc-123"));
        assert!(is_clean_header_value("application/json; charset=utf-8"));
    }

    #[test]
    fn rejects_response_splitting_crlf() {
        assert!(!is_clean_header_value("ok\r\nX-Injected: yes"));
        assert!(!is_clean_header_value("line1\nline2"));
        assert!(!is_clean_header_value("bad\rcrlf"));
    }

    #[test]
    fn rejects_control_bytes() {
        assert!(!is_clean_header_value("a\x00b"));
        assert!(!is_clean_header_value("a\x7fb")); // DEL
        assert!(!is_clean_header_value("a\x01b"));
    }

    #[test]
    fn rejects_non_ascii() {
        assert!(!is_clean_header_value("café"));
        assert!(!is_clean_header_value("a\u{80}b")); // obs-text rejected (strict)
    }

    #[test]
    fn validate_reports_first_offending_position() {
        assert_eq!(validate_header_value("ok\r\n").unwrap_err(), 2);
        assert!(validate_header_value("clean").is_ok());
    }
}
