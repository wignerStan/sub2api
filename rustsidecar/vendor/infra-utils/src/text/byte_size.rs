//! Byte size — unsigned byte count.

/// A size in bytes.
///
/// Plain `u64` newtype. Prevents mixing byte counts with other numeric values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct ByteSize(u64);

impl ByteSize {
    /// Create from bytes.
    #[must_use]
    pub const fn from_bytes(bytes: u64) -> Self {
        Self(bytes)
    }

    /// Create from kilobytes (1024 bytes).
    #[must_use]
    pub const fn from_kib(kib: u64) -> Self {
        Self(kib * 1024)
    }

    /// Create from megabytes (1024*1024 bytes).
    #[must_use]
    pub const fn from_mib(mib: u64) -> Self {
        Self(mib * 1024 * 1024)
    }

    /// Returns the size in bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> u64 {
        self.0
    }

    /// Returns the size in kilobytes (truncated).
    #[must_use]
    pub const fn as_kib(&self) -> u64 {
        self.0 / 1024
    }

    /// Returns the size in megabytes (truncated).
    #[must_use]
    pub const fn as_mib(&self) -> u64 {
        self.0 / (1024 * 1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes() {
        let size = ByteSize::from_bytes(2048);
        assert_eq!(size.as_bytes(), 2048);
        assert_eq!(size.as_kib(), 2);
    }

    #[test]
    fn from_kib() {
        let size = ByteSize::from_kib(4);
        assert_eq!(size.as_bytes(), 4096);
    }

    #[test]
    fn from_mib() {
        let size = ByteSize::from_mib(1);
        assert_eq!(size.as_bytes(), 1_048_576);
    }

    #[test]
    fn ordering() {
        assert!(ByteSize::from_bytes(100) < ByteSize::from_bytes(200));
    }

    mod edge {
        use super::*;

        #[test]
        fn zero() {
            let size = ByteSize::from_bytes(0);
            assert_eq!(size.as_kib(), 0);
            assert_eq!(size.as_mib(), 0);
        }

        #[test]
        fn truncation_on_conversion() {
            let size = ByteSize::from_bytes(1500);
            assert_eq!(size.as_kib(), 1);
        }
    }
}
