//! Passive validation errors shared by small utility value types.

/// Validation errors from small, axisless utility value types.
#[derive(Debug, thiserror::Error)]
pub enum ValueError {
    /// Input was empty or whitespace-only.
    #[error("input is empty or whitespace")]
    EmptyInput,
    /// A numeric value was outside the valid range.
    #[error("value is out of valid range")]
    OutOfRange,
    /// A value was zero when positive was required.
    #[error("value must be positive (non-zero)")]
    NotPositive,
    /// Invalid hex string for checksum.
    #[error("invalid hex string")]
    InvalidHex,
    /// Invalid date-time fields.
    #[error("invalid date-time")]
    InvalidDateTime,
    /// Invalid path segment (separators, dots, null bytes).
    #[error("invalid path segment")]
    InvalidPathSegment,
    /// Invalid ASCII key (wrong length or non-alphanumeric characters).
    #[error("invalid ascii key")]
    InvalidKey,
}
