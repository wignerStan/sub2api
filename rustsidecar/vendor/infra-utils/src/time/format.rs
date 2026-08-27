//! Generic time formatting helpers.
//!
//! Zero domain vocabulary — takes/returns primitives only.

use std::time::Duration;

use chrono::{NaiveDateTime, TimeZone, Utc};

/// Format a Unix epoch (seconds) as an RFC3339 string.
///
/// Returns `None` if the timestamp is outside chrono's representable range.
#[must_use]
pub fn epoch_to_rfc3339(secs: i64) -> Option<String> {
    Utc.timestamp_opt(secs, 0)
        .single()
        .map(|dt| dt.to_rfc3339())
}

/// Format a Unix epoch millisecond timestamp as an RFC3339 string.
///
/// Correct for negative timestamps (times before the epoch): uses Euclidean
/// (floor) division so the sub-second remainder is always a non-negative
/// offset added to `secs`, matching `chrono`'s own millisecond interpretation.
///
/// Returns `None` if the timestamp is outside chrono's representable range.
#[must_use]
pub fn epoch_millis_to_rfc3339(millis: i64) -> Option<String> {
    let secs = millis.div_euclid(1000);
    let nanos = millis.rem_euclid(1000) as u32 * 1_000_000;
    Utc.timestamp_opt(secs, nanos)
        .single()
        .map(|dt| dt.to_rfc3339())
}

/// Parse a `"YYYY-MM-DD HH:MM:SS"` datetime string to Unix epoch seconds.
#[must_use]
pub fn parse_naive_datetime(s: &str) -> Option<i64> {
    let naive = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").ok()?;
    Some(Utc.from_utc_datetime(&naive).timestamp())
}

/// Format a [`Duration`] into a compact human-readable string.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn format_duration(duration: Duration) -> String {
    let millis = i64::try_from(duration.as_millis()).unwrap_or(i64::MAX);
    if millis < 1000 {
        format!("{millis}ms")
    } else if millis < 60_000 {
        format!("{:.2}s", millis as f64 / 1000.0)
    } else {
        let minutes = millis / 60_000;
        let seconds = (millis % 60_000) / 1000;
        format!("{minutes}m {seconds:02}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_to_rfc3339_known() {
        let rfc = epoch_to_rfc3339(1_700_000_000).expect("in-range timestamp");
        assert!(rfc.starts_with("2023"));
        assert!(rfc.contains('T'));
    }

    #[test]
    fn epoch_to_rfc3339_zero() {
        let rfc = epoch_to_rfc3339(0).expect("epoch zero");
        assert!(rfc.starts_with("1970"));
    }

    #[test]
    fn epoch_to_rfc3339_out_of_range() {
        assert_eq!(epoch_to_rfc3339(i64::MAX), None);
    }

    #[test]
    fn epoch_millis_to_rfc3339_positive_subsecond() {
        let rfc = epoch_millis_to_rfc3339(1_700_000_000_500).expect("in-range");
        assert!(rfc.contains(".500"));
        assert!(rfc.starts_with("2023"));
    }

    #[test]
    fn epoch_millis_to_rfc3339_negative_matches_chrono() {
        for millis in [-1, -500, -999, -1000, -1500, -2000, -1_700_000_000_500] {
            let ours = epoch_millis_to_rfc3339(millis);
            let truth = Utc
                .timestamp_millis_opt(millis)
                .single()
                .map(|dt| dt.to_rfc3339());
            assert_eq!(ours, truth, "millis = {millis}");
        }
    }

    #[test]
    fn parse_naive_datetime_valid() {
        let secs = parse_naive_datetime("2024-01-15 10:30:00").expect("should parse");
        assert!(secs > 0);
    }

    #[test]
    fn format_duration_subsecond() {
        assert_eq!(format_duration(Duration::from_millis(250)), "250ms");
        assert_eq!(format_duration(Duration::from_millis(0)), "0ms");
    }

    #[test]
    fn format_duration_seconds() {
        assert_eq!(format_duration(Duration::from_millis(1_500)), "1.50s");
    }

    #[test]
    fn format_duration_minutes() {
        assert_eq!(format_duration(Duration::from_millis(75_000)), "1m 15s");
        assert_eq!(format_duration(Duration::from_millis(60_000)), "1m 00s");
    }
}
