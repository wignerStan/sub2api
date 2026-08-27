//! Percent — validated 0-100 value.

/// A percentage value in the range [0, 100].
///
/// Construction validates the range. Once constructed, the type guarantees
/// the value is a valid percentage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct Percent(u8);

impl Percent {
    /// Create a percentage, validating the 0-100 range.
    ///
    /// # Errors
    ///
    /// Returns `ValueError::OutOfRange` if value > 100.
    pub const fn new(value: u8) -> Result<Self, crate::value_error::ValueError> {
        if value > 100 {
            return Err(crate::value_error::ValueError::OutOfRange);
        }
        Ok(Self(value))
    }

    /// Create a percentage of 0%.
    #[must_use]
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Create a percentage of 100%.
    #[must_use]
    pub const fn full() -> Self {
        Self(100)
    }

    /// Returns the raw percentage value.
    #[must_use]
    pub const fn value(&self) -> u8 {
        self.0
    }

    /// Returns the percentage as a fraction in [0.0, 1.0].
    #[must_use]
    pub fn as_fraction(&self) -> f64 {
        f64::from(self.0) / 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_percentages() {
        assert_eq!(Percent::new(0).expect("0% should be valid").value(), 0);
        assert_eq!(Percent::new(50).expect("50% should be valid").value(), 50);
        assert_eq!(
            Percent::new(100).expect("100% should be valid").value(),
            100
        );
    }

    #[test]
    fn over_100_fails() {
        let err = Percent::new(101).expect_err("101% should be rejected");
        assert!(err.to_string().contains("out of valid range"), "got: {err}");
    }

    #[test]
    fn max_u8_fails() {
        let err = Percent::new(255).expect_err("255% should be rejected");
        assert!(err.to_string().contains("out of valid range"), "got: {err}");
    }

    #[test]
    fn as_fraction() {
        assert!(
            (Percent::new(50).expect("50% should be valid").as_fraction() - 0.5).abs()
                < f64::EPSILON
        );
    }

    mod edge {
        use super::*;

        #[test]
        fn zero_and_full() {
            assert_eq!(Percent::zero().value(), 0);
            assert_eq!(Percent::full().value(), 100);
        }
    }
}
