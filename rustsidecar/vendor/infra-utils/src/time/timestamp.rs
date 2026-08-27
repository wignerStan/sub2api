//! Unix timestamp (seconds since epoch).

/// Unix timestamp — seconds since 1970-01-01 00:00:00 UTC.
///
/// A plain `i64` newtype. Negative values represent times before the epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Create a timestamp from seconds since Unix epoch.
    #[must_use]
    pub const fn from_secs(secs: i64) -> Self {
        Self(secs)
    }

    /// Create a timestamp from milliseconds since Unix epoch.
    #[must_use]
    pub const fn from_millis(millis: i64) -> Self {
        Self(millis / 1000)
    }

    /// Returns the timestamp as seconds since Unix epoch.
    #[must_use]
    pub const fn as_secs(&self) -> i64 {
        self.0
    }

    /// Returns the timestamp as milliseconds since Unix epoch.
    #[must_use]
    pub const fn as_millis(&self) -> i64 {
        self.0 * 1000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_secs_roundtrip() {
        let ts = Timestamp::from_secs(1_700_000_000);
        assert_eq!(ts.as_secs(), 1_700_000_000);
    }

    #[test]
    fn from_millis_truncates() {
        let ts = Timestamp::from_millis(1_700_000_123);
        assert_eq!(ts.as_secs(), 1_700_000);
    }

    #[test]
    fn negative_timestamp() {
        let ts = Timestamp::from_secs(-1000);
        assert_eq!(ts.as_secs(), -1000);
    }

    #[test]
    fn ordering_works() {
        let a = Timestamp::from_secs(100);
        let b = Timestamp::from_secs(200);
        assert!(a < b);
    }
}
