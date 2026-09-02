//! UTC date-time (year, month, day, hour, minute, second).

/// A UTC date-time broken into calendar fields.
///
/// No timezone, no offset, no chrono dependency. Pure validated fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct UtcDateTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

impl UtcDateTime {
    /// Create a UTC date-time, validating field ranges.
    ///
    /// # Errors
    ///
    /// Returns `ValueError::InvalidDateTime` if any field is out of range.
    pub fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self, crate::value_error::ValueError> {
        if !(1..=12).contains(&month) {
            return Err(crate::value_error::ValueError::InvalidDateTime);
        }
        if day == 0 || day > 31 {
            return Err(crate::value_error::ValueError::InvalidDateTime);
        }
        if hour > 23 || minute > 59 || second > 60 {
            return Err(crate::value_error::ValueError::InvalidDateTime);
        }
        Ok(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        })
    }

    /// Create a date-only UTC value (time fields zeroed).
    ///
    /// # Errors
    ///
    /// Returns `ValueError::InvalidDateTime` if month or day is out of range.
    pub fn date(year: u16, month: u8, day: u8) -> Result<Self, crate::value_error::ValueError> {
        Self::new(year, month, day, 0, 0, 0)
    }

    /// Returns the year component.
    #[must_use]
    pub const fn year(&self) -> u16 {
        self.year
    }

    /// Returns the month component (1-12).
    #[must_use]
    pub const fn month(&self) -> u8 {
        self.month
    }

    /// Returns the day component (1-31).
    #[must_use]
    pub const fn day(&self) -> u8 {
        self.day
    }

    /// Returns the hour component (0-23).
    #[must_use]
    pub const fn hour(&self) -> u8 {
        self.hour
    }

    /// Returns the minute component (0-59).
    #[must_use]
    pub const fn minute(&self) -> u8 {
        self.minute
    }

    /// Returns the second component (0-60, allowing for leap seconds).
    #[must_use]
    pub const fn second(&self) -> u8 {
        self.second
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_datetime() {
        let dt =
            UtcDateTime::new(2024, 6, 15, 10, 30, 45).expect("valid datetime should construct");
        assert_eq!(dt.year(), 2024);
        assert_eq!(dt.month(), 6);
        assert_eq!(dt.day(), 15);
        assert_eq!(dt.hour(), 10);
    }

    #[test]
    fn date_only() {
        let dt = UtcDateTime::date(2024, 1, 1).expect("valid date should construct");
        assert_eq!(dt.hour(), 0);
    }

    #[test]
    fn invalid_month_zero() {
        let err = UtcDateTime::new(2024, 0, 1, 0, 0, 0).expect_err("month 0 should be rejected");
        assert!(err.to_string().contains("invalid date-time"), "got: {err}");
    }

    #[test]
    fn invalid_month_thirteen() {
        let err = UtcDateTime::new(2024, 13, 1, 0, 0, 0).expect_err("month 13 should be rejected");
        assert!(err.to_string().contains("invalid date-time"), "got: {err}");
    }

    #[test]
    fn invalid_day_zero() {
        let err = UtcDateTime::new(2024, 1, 0, 0, 0, 0).expect_err("day 0 should be rejected");
        assert!(err.to_string().contains("invalid date-time"), "got: {err}");
    }

    #[test]
    fn invalid_hour() {
        let err = UtcDateTime::new(2024, 1, 1, 24, 0, 0).expect_err("hour 24 should be rejected");
        assert!(err.to_string().contains("invalid date-time"), "got: {err}");
    }

    mod edge {
        use super::*;

        #[test]
        fn boundary_values() {
            let dt = UtcDateTime::new(2024, 12, 31, 23, 59, 59)
                .expect("boundary datetime should be valid");
            assert_eq!(dt.year(), 2024);
            assert_eq!(dt.month(), 12);
            assert_eq!(dt.day(), 31);
            assert_eq!(dt.hour(), 23);
            assert_eq!(dt.minute(), 59);
            assert_eq!(dt.second(), 59);
        }

        #[test]
        fn leap_second() {
            let dt =
                UtcDateTime::new(2024, 6, 30, 23, 59, 60).expect("leap second 60 should be valid");
            assert_eq!(dt.second(), 60);
        }

        #[test]
        fn day_31_valid_for_some_months() {
            let dt = UtcDateTime::new(2024, 1, 31, 0, 0, 0).expect("January 31 should be valid");
            assert_eq!(dt.day(), 31);
        }
    }
}
