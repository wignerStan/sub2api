//! HMAC-SHA256 for message authentication. SHA-256 alone is a hash (integrity,
//! no key); HMAC binds a key so only holders of it can produce a valid tag —
//! the right tool for authenticating messages, webhooks, request signing.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Error from HMAC computation or verification.
#[derive(Debug, Error)]
pub enum MacError {
    /// The key length is invalid for the HMAC variant (should not happen for
    /// HMAC-SHA256, which accepts any key length, but kept for forward-compat).
    #[error("invalid key length")]
    InvalidKey,
    /// The provided tag did not verify against the message under the key.
    #[error("hmac verification failed")]
    VerifyFailed,
}

/// Compute an HMAC-SHA256 tag over `message` with `key`.
///
/// # Errors
///
/// [`MacError::InvalidKey`] only if the underlying HMAC rejects the key
/// (does not occur for HMAC-SHA256 in practice).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<[u8; 32], MacError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| MacError::InvalidKey)?;
    mac.update(message);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Verify an HMAC-SHA256 `expected` tag in CONSTANT TIME.
///
/// Computes the tag and uses `verify_slice` (constant-time comparison) — never
/// a manual `==`, which leaks timing information about how many bytes matched.
/// Returns `Ok(())` on match, [`MacError::VerifyFailed`] otherwise.
///
/// # Errors
///
/// [`MacError::VerifyFailed`] if the tag does not match; [`MacError::InvalidKey`]
/// only on an impossible key-length rejection.
pub fn hmac_sha256_verify(key: &[u8], message: &[u8], expected: &[u8]) -> Result<(), MacError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| MacError::InvalidKey)?;
    mac.update(message);
    mac.verify_slice(expected)
        .map_err(|_| MacError::VerifyFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_roundtrips_and_verifies() {
        let key = b"secret-key";
        let msg = b"message";
        let tag = hmac_sha256(key, msg).unwrap();
        // Correct key verifies.
        assert!(hmac_sha256_verify(key, msg, &tag).is_ok());
        // Wrong key fails.
        assert!(hmac_sha256_verify(b"wrong", msg, &tag).is_err());
        // Tampered message fails.
        assert!(hmac_sha256_verify(key, b"tampered", &tag).is_err());
        // Tampered tag fails.
        let mut bad_tag = tag;
        bad_tag[0] ^= 0xff;
        assert!(hmac_sha256_verify(key, msg, &bad_tag).is_err());
    }

    #[test]
    fn hmac_deterministic() {
        let tag1 = hmac_sha256(b"k", b"m").unwrap();
        let tag2 = hmac_sha256(b"k", b"m").unwrap();
        assert_eq!(tag1, tag2);
        // Different message → different tag.
        assert_ne!(tag1, hmac_sha256(b"k", b"m2").unwrap());
    }
}
