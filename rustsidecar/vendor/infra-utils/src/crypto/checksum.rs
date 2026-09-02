//! Checksum — hash digest bytes.

/// A checksum or hash digest.
///
/// Stores raw bytes. No hashing capability — that belongs in infra.
/// Foundation owns the type; infra computes it.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Checksum(Vec<u8>);

impl Checksum {
    /// Create a checksum from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Create a checksum from a hex string.
    ///
    /// # Errors
    ///
    /// Returns `ValueError::InvalidHex` if the string contains
    /// non-hex characters or has odd length.
    pub fn from_hex(hex: &str) -> Result<Self, crate::value_error::ValueError> {
        if !hex.len().is_multiple_of(2) {
            return Err(crate::value_error::ValueError::InvalidHex);
        }
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for i in (0..hex.len()).step_by(2) {
            let byte = u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| crate::value_error::ValueError::InvalidHex)?;
            bytes.push(byte);
        }
        Ok(Self(bytes))
    }

    /// Returns the checksum bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the checksum as a lowercase hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(self.0.len() * 2);
        for b in &self.0 {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_hex_roundtrip() {
        let cs = Checksum::from_hex("deadbeef").expect("valid hex should parse");
        assert_eq!(cs.to_hex(), "deadbeef");
        assert_eq!(cs.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn from_bytes() {
        let cs = Checksum::from_bytes(vec![0x00, 0xff]);
        assert_eq!(cs.as_bytes(), &[0x00, 0xff]);
    }

    #[test]
    fn from_hex_odd_length_fails() {
        let err = Checksum::from_hex("abc").expect_err("odd-length hex should fail");
        assert!(err.to_string().contains("invalid hex"), "got: {err}");
    }

    #[test]
    fn from_hex_invalid_chars_fails() {
        let err = Checksum::from_hex("zz").expect_err("invalid hex chars should fail");
        assert!(err.to_string().contains("invalid hex"), "got: {err}");
    }

    mod edge {
        use super::*;

        #[test]
        fn empty_checksum() {
            let cs = Checksum::from_bytes(vec![]);
            assert_eq!(cs.to_hex(), "");
        }

        #[test]
        fn uppercase_hex_accepted() {
            let cs = Checksum::from_hex("DEADBEEF").expect("uppercase hex should parse");
            assert_eq!(cs.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        }
    }
}
