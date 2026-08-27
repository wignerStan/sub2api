//! Pure validation and normalization functions.
//!
//! Note: hash computation lives in [`crate::crypto::hash`] — including
//! `sha256`/`md5` returning a [`Checksum`]. Do not re-add `sha256_bytes`/
//! `md5_bytes` here: it shadowed `crypto::hash::sha256_bytes` (which returns
//! `[u8; 32]`) under an identical name, producing two different return types
//! for the same call path.

/// Collapse consecutive whitespace to single spaces and trim.
#[must_use]
pub fn normalize_whitespace(s: &str) -> String {
    let mut result = String::new();
    let mut first = true;
    for word in s.split_whitespace() {
        if !first {
            result.push(' ');
        }
        result.push_str(word);
        first = false;
    }
    result
}

/// Validate that a string is a non-empty ASCII alphanumeric key of the given length.
///
/// # Errors
///
/// Returns `ValueError::InvalidKey` if the string has the wrong length
/// or contains non-ASCII-alphanumeric characters.
pub fn validate_ascii_key(
    s: &str,
    expected_len: usize,
) -> Result<(), crate::value_error::ValueError> {
    if s.len() != expected_len || !s.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(crate::value_error::ValueError::InvalidKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_whitespace_collapse() {
        assert_eq!(normalize_whitespace("  hello   world  "), "hello world");
    }

    #[test]
    fn normalize_whitespace_single() {
        assert_eq!(normalize_whitespace("hello"), "hello");
    }

    #[test]
    fn normalize_whitespace_empty() {
        assert_eq!(normalize_whitespace("   "), "");
    }

    #[test]
    fn validate_ascii_key_valid() {
        validate_ascii_key("ABCD1234", 8).expect("valid 8-char alphanumeric key should pass");
    }

    #[test]
    fn validate_ascii_key_wrong_length() {
        let err = validate_ascii_key("ABCD123", 8).unwrap_err();
        assert!(err.to_string().contains("invalid ascii key"), "got: {err}");
        let err = validate_ascii_key("ABCD12345", 8).unwrap_err();
        assert!(err.to_string().contains("invalid ascii key"), "got: {err}");
    }

    #[test]
    fn validate_ascii_key_non_ascii() {
        let err = validate_ascii_key("ABCD12é4", 8).unwrap_err();
        assert!(err.to_string().contains("invalid ascii key"), "got: {err}");
    }
}
