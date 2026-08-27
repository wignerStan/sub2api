//! Generic hashing helpers.
//!
//! Zero domain vocabulary — knows hashing, nothing else.

use crate::crypto::checksum::Checksum;

/// Compute SHA-256 digest of `data` and return as lowercase hex string.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    use ring::digest::{Context, SHA256};
    let mut ctx = Context::new(&SHA256);
    ctx.update(data);
    let digest = ctx.finish();
    digest.as_ref().iter().fold(
        String::with_capacity(digest.as_ref().len() * 2),
        |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        },
    )
}

/// Compute SHA-256 digest of `data` and return the raw 32-byte digest.
#[must_use]
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    use ring::digest::{Context, SHA256};
    let mut ctx = Context::new(&SHA256);
    ctx.update(data);
    let digest = ctx.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// SHA-256 hash, returned as a [`Checksum`].
pub fn sha256(data: &[u8]) -> Checksum {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    Checksum::from_bytes(digest.to_vec())
}

// ---- BLAKE3 ----
//
// BLAKE3 is the default for "hash bytes fast": it is substantially faster than
// SHA-2 (parallelizable, SIMD), with one-shot, incremental, extended-output,
// keyed hashing, and key-derivation modes — all in the default `std` build.
// Use it for content-addressing, dedup keys, and checksums where speed matters
// and SHA-2 interop is not required. For standard-crypto interop (SHA-2, and
// HMAC/AEAD/ECDH/PBKDF2 in `ring`), use the SHA-2 helpers above and `ring`.

/// Default BLAKE3 output length: 32 bytes (256 bits), the native digest size.
pub const BLAKE3_OUT_LEN: usize = 32;

/// BLAKE3 context-key length (for [`blake3_derive_key`] / KDF mode): 32 bytes.
pub const BLAKE3_KEY_LEN: usize = 32;

/// Compute a one-shot BLAKE3 hash and return it as a lowercase hex string.
#[must_use]
pub fn blake3_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// Compute a one-shot BLAKE3 hash and return the raw 32-byte digest.
#[must_use]
pub fn blake3_bytes(data: &[u8]) -> [u8; BLAKE3_OUT_LEN] {
    blake3::hash(data).into()
}

/// Compute a one-shot BLAKE3 hash, returned as a [`Checksum`].
pub fn blake3(data: &[u8]) -> Checksum {
    Checksum::from_bytes(blake3::hash(data).as_bytes().to_vec())
}

/// Compute a BLAKE3 hash with extended (XOF) output of arbitrary length.
///
/// BLAKE3's native digest is 32 bytes; this extends it to `len` bytes using
/// the standard extended-output mode (suitable for stream ciphers, longer
/// fingerprints, or any length).
#[must_use]
pub fn blake3_extended(data: &[u8], len: usize) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    let mut out = vec![0u8; len];
    hasher.finalize_xof().fill(&mut out);
    out
}

/// Compute a keyed BLAKE3 hash (MAC mode) and return it as a hex string.
///
/// `key` must be exactly [`BLAKE3_KEY_LEN`] (32) bytes.
///
/// # Panics
///
/// Panics if `key.len() != BLAKE3_KEY_LEN`.
#[must_use]
pub fn blake3_keyed_hex(data: &[u8], key: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new_keyed(&key_array(key));
    hasher.update(data);
    hasher.finalize().to_hex().to_string()
}

/// Derive a sub-key from `data` using BLAKE3's key-derivation mode.
///
/// Uses the `derive_key(context)` mode: `context` is a domain-separation
/// string compiled to a fixed key at build time. Returns `len` bytes.
///
/// # Panics
///
/// Panics if `context` is empty (BLAKE3 requires a non-empty context string).
#[must_use]
pub fn blake3_derive_key(context: &str, data: &[u8], len: usize) -> Vec<u8> {
    assert!(
        !context.is_empty(),
        "BLAKE3 derive_key context must be non-empty"
    );
    let mut out = vec![0u8; len];
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(data);
    hasher.finalize_xof().fill(&mut out);
    out
}

/// Build an incremental BLAKE3 hasher incrementally via a callback, then
/// return the 32-byte digest as a [`Checksum`]. Use for streaming/large inputs
/// that should not be held in memory all at once.
pub fn blake3_incremental(data: impl IntoIterator<Item = impl AsRef<[u8]>>) -> Checksum {
    let mut hasher = blake3::Hasher::new();
    for chunk in data {
        hasher.update(chunk.as_ref());
    }
    Checksum::from_bytes(hasher.finalize().as_bytes().to_vec())
}

// ---- BLAKE3 helpers ----

// `key_array` is only called with keys already validated to be exactly
// BLAKE3_KEY_LEN bytes; the expect is a checked invariant, not a fallible op.
#[allow(clippy::expect_used)]
fn key_array(key: &[u8]) -> [u8; BLAKE3_KEY_LEN] {
    let arr: [u8; BLAKE3_KEY_LEN] = key
        .try_into()
        .expect("BLAKE3 key must be exactly BLAKE3_KEY_LEN (32) bytes");
    arr
}

/// MD5 hash, returned as a [`Checksum`].
pub fn md5(data: &[u8]) -> Checksum {
    use md5::{Digest, Md5};
    let digest = Md5::digest(data);
    Checksum::from_bytes(digest.to_vec())
}

/// SHA-1 hex string (uses ring's legacy SHA-1; sha2 has no SHA-1).
pub fn sha1_hex(data: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data);
    hex_encode(digest.as_ref())
}

/// MD5 hex string.
pub fn md5_hex(data: &[u8]) -> String {
    hex_encode(md5(data).as_bytes())
}

/// Hex-encode a byte slice.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_known_input() {
        let hex = sha256_hex(b"hello");
        assert_eq!(
            hex,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn sha256_bytes_length() {
        let bytes = sha256_bytes(b"test");
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn sha256_hex_empty() {
        let hex = sha256_hex(b"");
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn md5_hex_known_input() {
        let hex = md5_hex(b"hello");
        assert_eq!(hex, "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn sha256_checksum_roundtrip() {
        let cs = sha256(b"hello");
        assert_eq!(cs.to_hex(), sha256_hex(b"hello"));
        assert_eq!(cs.as_bytes().len(), 32);
    }

    #[test]
    fn md5_checksum_known_input() {
        let cs = md5(b"hello");
        assert_eq!(cs.to_hex(), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn sha1_hex_known_input() {
        let hex = sha1_hex(b"hello");
        assert_eq!(hex, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
    }

    #[test]
    fn hex_encode_lowercases() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0xab]), "00ffab");
    }

    // ---- BLAKE3 ----

    #[test]
    fn blake3_hex_known_vectors() {
        // Reference vectors from the blake3 crate (cross-checked locally).
        assert_eq!(
            blake3_hex(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            blake3_hex(b"abc"),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    #[test]
    fn blake3_bytes_is_32() {
        assert_eq!(blake3_bytes(b"hello").len(), BLAKE3_OUT_LEN);
    }

    #[test]
    fn blake3_bytes_matches_hex() {
        assert_eq!(hex_encode(&blake3_bytes(b"abc")), blake3_hex(b"abc"));
    }

    #[test]
    fn blake3_checksum_matches_one_shot() {
        let cs = blake3(b"hello");
        assert_eq!(cs.to_hex(), blake3_hex(b"hello"));
        assert_eq!(cs.as_bytes().len(), 32);
    }

    #[test]
    fn blake3_extended_extends_digest() {
        // XOF output begins with the 32-byte digest, then continues.
        let digest = blake3_hex(b"");
        let ext = blake3_extended(b"", 64);
        // First 32 bytes (64 hex chars) equal the native digest.
        assert_eq!(hex_encode(&ext[..32]), digest);
        assert_eq!(ext.len(), 64);
    }

    #[test]
    fn blake3_extended_zero_len() {
        assert!(blake3_extended(b"abc", 0).is_empty());
    }

    #[test]
    fn blake3_keyed_known_vector() {
        let key_seq: [u8; BLAKE3_KEY_LEN] = (0u8..BLAKE3_KEY_LEN as u8)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        assert_eq!(
            blake3_keyed_hex(b"abc", &key_seq),
            "6da54495d8152f2bcba87bd7282df70901cdb66b4448ed5f4c7bd2852b8b5532"
        );
    }

    #[test]
    #[should_panic(expected = "BLAKE3 key must be exactly")]
    fn blake3_keyed_rejects_wrong_key_length() {
        let _ = blake3_keyed_hex(b"abc", &[0u8; 16]);
    }

    #[test]
    fn blake3_derive_key_is_deterministic() {
        let a = blake3_derive_key("app.key.v1", b"material", 16);
        let b = blake3_derive_key("app.key.v1", b"material", 16);
        assert_eq!(a, b);
        // Different context or material yields different keys.
        assert_ne!(a, blake3_derive_key("app.key.v2", b"material", 16));
        assert_ne!(a, blake3_derive_key("app.key.v1", b"different", 16));
    }

    #[test]
    #[should_panic(expected = "context must be non-empty")]
    fn blake3_derive_key_rejects_empty_context() {
        let _ = blake3_derive_key("", b"x", 16);
    }

    #[test]
    fn blake3_incremental_matches_one_shot() {
        // Streaming chunks must equal a single one-shot hash of the concatenation.
        let chunks: Vec<&[u8]> = vec![b"foo", b"bar", b"baz"];
        let cs = blake3_incremental(chunks);
        assert_eq!(cs.to_hex(), blake3_hex(b"foobarbaz"));
    }
}
