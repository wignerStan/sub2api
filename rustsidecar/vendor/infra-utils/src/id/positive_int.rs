//! Positive integer — strictly greater than zero.

/// A positive integer (strictly > 0).
///
/// Construction rejects zero and negative values. Once constructed, the type
/// guarantees the value is positive.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct PositiveInt(u64);

impl PositiveInt {
    /// Create a positive integer, rejecting zero.
    ///
    /// # Errors
    ///
    /// Returns `ValueError::NotPositive` if value is 0.
    pub const fn new(value: u64) -> Result<Self, crate::value_error::ValueError> {
        if value == 0 {
            return Err(crate::value_error::ValueError::NotPositive);
        }
        Ok(Self(value))
    }

    /// Create from a non-zero u64 without validation.
    #[must_use]
    pub const fn from_non_zero(value: std::num::NonZeroU64) -> Self {
        Self(value.get())
    }

    /// Returns the value as u64.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.0
    }

    /// Convert to `NonZeroU64`.
    ///
    /// # Panics
    ///
    /// Never panics — the value is guaranteed positive by construction.
    #[must_use]
    #[allow(clippy::expect_used)]
    pub const fn as_non_zero(&self) -> std::num::NonZeroU64 {
        std::num::NonZeroU64::new(self.0).expect("PositiveInt is guaranteed > 0")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_positive() {
        assert_eq!(
            PositiveInt::new(1).expect("1 should be positive").value(),
            1
        );
        assert_eq!(
            PositiveInt::new(100)
                .expect("100 should be positive")
                .value(),
            100
        );
    }

    #[test]
    fn zero_fails() {
        let err = PositiveInt::new(0).unwrap_err();
        assert!(err.to_string().contains("positive"), "{err}");
    }

    #[test]
    fn ordering() {
        assert!(
            PositiveInt::new(1).expect("1 should be positive")
                < PositiveInt::new(2).expect("2 should be positive")
        );
    }

    mod edge {
        use super::*;

        #[test]
        fn max_value() {
            assert_eq!(
                PositiveInt::new(u64::MAX)
                    .expect("u64::MAX should be positive")
                    .value(),
                u64::MAX
            );
        }

        #[test]
        fn from_non_zero() {
            let nz = std::num::NonZeroU64::new(42).expect("42 should be non-zero");
            let pi = PositiveInt::from_non_zero(nz);
            assert_eq!(pi.value(), 42);
        }
    }
}
