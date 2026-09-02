//! DST-safe local-to-UTC conversion and strict RFC3339 parsing.
//!
//! Wraps only chrono operations with real footguns (DST ambiguity, panicking
//! arithmetic, offset-less parsing). For pure value
//! manipulation (format, compare, convert) reach `chrono` directly.
//!
//! - All times are UTC internally (`DateTime<Utc>`). Local time is a boundary
//!   concern; convert it with [`local_to_utc_strict_in`] so DST gaps/ambiguity
//!   surface as [`TimeError`] instead of a silent pick.

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use thiserror::Error;

/// Failure from local→UTC conversion: the local time is a DST gap or fold.
#[derive(Debug, Error)]
pub enum TimeError {
    /// The local time is ambiguous (DST fall-back — two valid UTC instants).
    #[error("local time is ambiguous (DST fall-back): {local}")]
    Ambiguous {
        /// The local (naive) datetime that mapped to two instants.
        local: NaiveDateTime,
    },
    /// The local time does not exist (DST spring-forward gap).
    #[error("local time does not exist (DST spring-forward): {local}")]
    Nonexistent {
        /// The local (naive) datetime that fell in the gap.
        local: NaiveDateTime,
    },
}

/// Parse an RFC3339 string, REQUIRING an offset, returning UTC.
///
/// Unlike a naive `parse_from_str`, RFC3339 mandates an offset, so this rejects
/// offset-less strings at the parse boundary rather than silently applying a
/// default zone.
///
/// # Errors
///
/// Returns `chrono::ParseError` if the string is not valid RFC3339 (including
/// missing offset).
pub fn parse_rfc3339_utc(s: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_rfc3339(s).map(std::convert::Into::into)
}

/// Convert a wall-clock local time to UTC under a given time zone, surfacing DST
/// ambiguity/nonexistence as [`TimeError`].
///
/// Generic over [`chrono::TimeZone`] so DST can be tested deterministically
/// against a known zone (e.g. a `FixedOffset`) without depending on the
/// machine's `Local` setting. Never blindly picks one of two instants.
///
/// # Errors
///
/// [`TimeError::Ambiguous`] on a DST fall-back, [`TimeError::Nonexistent`] on a
/// spring-forward gap.
pub fn local_to_utc_strict_in<Tz: TimeZone>(
    tz: &Tz,
    local: NaiveDateTime,
) -> Result<DateTime<Utc>, TimeError> {
    match tz.from_local_datetime(&local) {
        chrono::MappedLocalTime::Single(dt) => Ok(dt.with_timezone(&Utc)),
        chrono::MappedLocalTime::Ambiguous(_, _) => Err(TimeError::Ambiguous { local }),
        chrono::MappedLocalTime::None => Err(TimeError::Nonexistent { local }),
    }
}

/// Convert a wall-clock local time to a timezone-aware datetime in `tz`,
/// surfacing DST ambiguity/nonexistence as [`TimeError`].
///
/// Like [`local_to_utc_strict_in`] but returns `DateTime<Tz>` (not converted to
/// UTC) — use when the caller needs the local-zone representation preserved.
///
/// # Errors
///
/// [`TimeError::Ambiguous`] on a DST fall-back, [`TimeError::Nonexistent`] on a
/// spring-forward gap.
pub fn local_datetime_strict<Tz: chrono::TimeZone>(
    tz: &Tz,
    local: NaiveDateTime,
) -> Result<chrono::DateTime<Tz>, TimeError> {
    match tz.from_local_datetime(&local) {
        chrono::MappedLocalTime::Single(dt) => Ok(dt),
        chrono::MappedLocalTime::Ambiguous(_, _) => Err(TimeError::Ambiguous { local }),
        chrono::MappedLocalTime::None => Err(TimeError::Nonexistent { local }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::FixedOffset;

    #[test]
    fn parse_rfc3339_utc_valid_z() {
        let dt = parse_rfc3339_utc("2024-01-15T10:30:00Z").unwrap();
        assert_eq!(dt, Utc.timestamp_opt(1_705_314_600, 0).single().unwrap());
    }

    #[test]
    fn parse_rfc3339_utc_normalizes_offset() {
        // +02:00 offset → normalized to UTC (08:30Z).
        let dt = parse_rfc3339_utc("2024-01-15T10:30:00+02:00").unwrap();
        assert_eq!(dt, parse_rfc3339_utc("2024-01-15T08:30:00Z").unwrap());
    }

    #[test]
    fn parse_rfc3339_utc_rejects_missing_offset() {
        // No offset/Z → RFC3339 requires one → Err.
        assert!(parse_rfc3339_utc("2024-01-15T10:30:00").is_err());
    }

    #[test]
    fn parse_rfc3339_utc_rejects_garbage() {
        assert!(parse_rfc3339_utc("not-a-time").is_err());
    }

    #[test]
    fn local_to_utc_strict_in_fixed_offset() {
        // A fixed +02:00 zone has no DST, so every local time is Single.
        let tz = FixedOffset::east_opt(2 * 3600).unwrap();
        let local =
            NaiveDateTime::parse_from_str("2024-01-15 10:30:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let utc = local_to_utc_strict_in(&tz, local).unwrap();
        assert_eq!(utc, parse_rfc3339_utc("2024-01-15T08:30:00Z").unwrap());
    }

    #[test]
    fn local_to_utc_strict_in_surfaces_mapped_variants() {
        // Directly exercise the Ambiguous/Nonexistent branches via minimal fake
        // TimeZones that we control, so the MappedLocalTime→TimeError mapping is
        // tested deterministically (independent of the machine's Local zone).
        use chrono::MappedLocalTime;

        /// A zone whose local→datetime conversion always yields `Ambiguous`.
        #[derive(Clone, Copy)]
        struct AmbigTz;
        impl TimeZone for AmbigTz {
            type Offset = FixedOffset;
            fn from_offset(_: &Self::Offset) -> Self {
                Self
            }
            fn offset_from_local_date(
                &self,
                _: &chrono::NaiveDate,
            ) -> MappedLocalTime<Self::Offset> {
                unreachable!()
            }
            fn offset_from_local_datetime(
                &self,
                _: &NaiveDateTime,
            ) -> MappedLocalTime<Self::Offset> {
                MappedLocalTime::Ambiguous(
                    FixedOffset::east_opt(0).unwrap(),
                    FixedOffset::east_opt(3600).unwrap(),
                )
            }
            fn offset_from_utc_date(&self, _: &chrono::NaiveDate) -> Self::Offset {
                FixedOffset::east_opt(0).unwrap()
            }
            fn offset_from_utc_datetime(&self, _: &NaiveDateTime) -> Self::Offset {
                FixedOffset::east_opt(0).unwrap()
            }
        }

        /// A zone whose local→datetime conversion always yields `None` (gap).
        #[derive(Clone, Copy)]
        struct NoneTz;
        impl TimeZone for NoneTz {
            type Offset = FixedOffset;
            fn from_offset(_: &Self::Offset) -> Self {
                Self
            }
            fn offset_from_local_date(
                &self,
                _: &chrono::NaiveDate,
            ) -> MappedLocalTime<Self::Offset> {
                unreachable!()
            }
            fn offset_from_local_datetime(
                &self,
                _: &NaiveDateTime,
            ) -> MappedLocalTime<Self::Offset> {
                MappedLocalTime::None
            }
            fn offset_from_utc_date(&self, _: &chrono::NaiveDate) -> Self::Offset {
                FixedOffset::east_opt(0).unwrap()
            }
            fn offset_from_utc_datetime(&self, _: &NaiveDateTime) -> Self::Offset {
                FixedOffset::east_opt(0).unwrap()
            }
        }

        let local =
            NaiveDateTime::parse_from_str("2024-01-15 10:30:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let ambig = local_to_utc_strict_in(&AmbigTz, local).unwrap_err();
        assert!(matches!(ambig, TimeError::Ambiguous { .. }), "got: {ambig}");
        let none = local_to_utc_strict_in(&NoneTz, local).unwrap_err();
        assert!(matches!(none, TimeError::Nonexistent { .. }), "got: {none}");
    }

    #[test]
    fn local_datetime_strict_preserves_zone() {
        // Fixed +02:00: no DST, so every local time is Single.
        let tz = chrono::FixedOffset::east_opt(2 * 3600).unwrap();
        let local =
            NaiveDateTime::parse_from_str("2024-01-15 10:30:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let dt = local_datetime_strict(&tz, local).unwrap();
        // Result is in the +02:00 zone, not converted to UTC.
        assert_eq!(dt.to_rfc3339(), "2024-01-15T10:30:00+02:00");
    }
}
