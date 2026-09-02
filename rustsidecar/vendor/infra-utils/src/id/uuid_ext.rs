//! Generic UUID helpers for nil rejection and deterministic normalization.
//!
//! The helpers encode generation and nil-rejection policy without routing the
//! `uuid` namespace. Callers that need other UUID operations depend on `uuid`
//! directly.
//!
//! Domain-specific ID newtypes (`UserId`, `OrgId`, …) belong in the consuming
//! crate, not this axisless leaf.

use thiserror::Error;

use uuid::Uuid;

/// Errors from UUID parsing/validation.
#[derive(Debug, Error)]
pub enum IdError {
    /// The string is not a valid UUID.
    #[error("invalid uuid: {0}")]
    Parse(#[from] uuid::Error),
    /// The UUID is the all-zero nil UUID (often a bad sentinel).
    #[error("uuid is nil (all zeros)")]
    Nil,
}

/// Deterministic content-addressed UUID (v5) over the given bytes.
///
/// Same logical inputs always produce the same UUID - useful for stable IDs
/// derived from a value (dedupe keys, content fingerprint). Uses the standard
/// URL namespace constant as the seed so IDs generated here won't collide
/// with v5 IDs other tools mint under a different namespace.
#[must_use]
pub fn namespaced_v5_string(value: &[u8]) -> String {
    Uuid::new_v5(&Uuid::NAMESPACE_URL, value).to_string()
}

/// Parse a UUID string, rejecting the nil (all-zero) UUID.
///
/// The nil UUID frequently sneaks in as a sentinel; rejecting it at the boundary
/// prevents it flowing through as a real record ID.
///
/// # Errors
///
/// Returns [`IdError::Parse`] for malformed input, [`IdError::Nil`] for the
/// nil UUID.
pub fn parse_non_nil_uuid(s: &str) -> Result<Uuid, IdError> {
    let id = Uuid::parse_str(s)?;
    if id.is_nil() {
        return Err(IdError::Nil);
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_non_nil_uuid_valid() {
        let s = "00112233-4455-6677-8899-aabbccddeeff";
        let id = parse_non_nil_uuid(s).expect("valid non-nil uuid should parse");
        assert_eq!(id.to_string(), s);
    }

    #[test]
    fn parse_non_nil_uuid_rejects_nil() {
        let err = parse_non_nil_uuid("00000000-0000-0000-0000-000000000000")
            .expect_err("nil uuid should be rejected");
        assert!(matches!(err, IdError::Nil), "got: {err}");
    }

    #[test]
    fn parse_non_nil_uuid_rejects_garbage() {
        let err = parse_non_nil_uuid("not-a-uuid").expect_err("garbage should be rejected");
        assert!(matches!(err, IdError::Parse(_)), "got: {err}");
    }
}
