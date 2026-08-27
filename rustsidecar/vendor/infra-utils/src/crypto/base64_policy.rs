//! Base64 encode/decode with a fixed house policy (URL-safe, no padding) plus
//! bounded decode. Base64 has alphabet/padding variants that are easy to mix
//! up; this module picks ONE format and caps decoded size so a hostile input
//! cannot exhaust memory. Standard-alphabet decode is provided for interop.

use base64::Engine;
use base64::engine::general_purpose;
use thiserror::Error;

/// Errors from base64 (de)coding.
#[derive(Debug, Error)]
pub enum Base64Error {
    /// The input is not valid base64 under the chosen engine.
    #[error("invalid base64: {0}")]
    Invalid(#[from] base64::DecodeError),
    /// The decoded output would exceed the configured max length.
    #[error("decoded length {decoded} exceeds max {max}")]
    TooLarge {
        /// The decoded length.
        decoded: usize,
        /// The configured cap.
        max: usize,
    },
}

/// Decode URL-safe no-padding base64, refusing outputs longer than
/// `max_decoded_len`. Each base64 char is ~6 bits, so the input length bounds
/// the output; the cap is checked before allocation.
///
/// # Errors
///
/// [`Base64Error::Invalid`] for malformed input; [`Base64Error::TooLarge`] if
/// the decoded output would exceed the cap.
pub fn decode_urlsafe_no_pad_bounded(
    s: &str,
    max_decoded_len: usize,
) -> Result<Vec<u8>, Base64Error> {
    let estimated = estimate_decoded_len(s.len());
    if estimated > max_decoded_len {
        return Err(Base64Error::TooLarge {
            decoded: estimated,
            max: max_decoded_len,
        });
    }
    let out = general_purpose::URL_SAFE_NO_PAD.decode(s)?;
    if out.len() > max_decoded_len {
        return Err(Base64Error::TooLarge {
            decoded: out.len(),
            max: max_decoded_len,
        });
    }
    Ok(out)
}

/// Decode STANDARD-alphabet base64 (A–Z a–z 0–9 + /), rejecting padding
/// mismatches and oversized outputs. Use for interop with systems that emit
/// standard base64; callers use the URL_SAFE_NO_PAD engine directly for encoding.
///
/// # Errors
///
/// [`Base64Error::Invalid`] for malformed input; [`Base64Error::TooLarge`] if
/// oversized.
pub fn decode_standard_strict(s: &str, max_decoded_len: usize) -> Result<Vec<u8>, Base64Error> {
    let estimated = estimate_decoded_len(s.len());
    if estimated > max_decoded_len {
        return Err(Base64Error::TooLarge {
            decoded: estimated,
            max: max_decoded_len,
        });
    }
    let out = general_purpose::STANDARD.decode(s)?;
    if out.len() > max_decoded_len {
        return Err(Base64Error::TooLarge {
            decoded: out.len(),
            max: max_decoded_len,
        });
    }
    Ok(out)
}

/// Standard-alphabet base64 encode (RFC 4648 §4, with padding).
///
/// Use for content that interoperates with standard base64 decoders
/// (e.g. JSON payloads embedded in transit, checkpoint snapshots). For new
/// internal formats prefer URL-safe no-padding via the house policy.
#[must_use]
pub fn encode_standard(bytes: &[u8]) -> String {
    general_purpose::STANDARD.encode(bytes)
}

/// Upper bound on decoded length from an input of `input_len` base64 chars
/// (ignores padding for safety).
fn estimate_decoded_len(input_len: usize) -> usize {
    input_len.saturating_mul(3) / 4
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn encode(bytes: &[u8]) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    #[test]
    fn urlsafe_no_pad_roundtrip() {
        let bytes = b"hello world";
        let enc = encode(bytes);
        assert!(!enc.contains('='));
        assert_eq!(decode_urlsafe_no_pad_bounded(&enc, 100).unwrap(), bytes);
    }

    #[test]
    fn decode_rejects_oversized() {
        let enc = encode(&[0u8; 100]);
        let err = decode_urlsafe_no_pad_bounded(&enc, 10).unwrap_err();
        assert!(matches!(err, Base64Error::TooLarge { .. }), "got: {err}");
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode_urlsafe_no_pad_bounded("!!!not base64!!!", 100).is_err());
    }

    #[test]
    fn standard_strict_roundtrip() {
        // STANDARD engine output.
        let enc = general_purpose::STANDARD.encode(b"data");
        assert_eq!(decode_standard_strict(&enc, 100).unwrap(), b"data");
    }
}
