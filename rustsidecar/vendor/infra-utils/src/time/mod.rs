//! Passive time values, formatting, timestamps, and strict timezone conversion.
//!
//! Retry/backoff and runtime scheduling are operational policies and do not
//! belong in this leaf. Reach `chrono` types directly from an owning crate.

pub mod clock;
pub mod format;
pub mod timestamp;
pub mod utc_datetime;
