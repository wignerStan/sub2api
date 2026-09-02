//! Bounded, pure-memory YAML conversion for meaning and use-flow owners.
//!
//! This module deliberately exposes no filesystem, reader/writer, environment,
//! or foreign parser types. Operational config/source owners bind
//! `serde_yaml_ng` directly; semantic callers enable the optional `yaml`
//! feature and use this owned, byte-budgeted conversion contract.

use serde::{Serialize, de::DeserializeOwned};
use std::io::{self, Write};

/// Default maximum YAML input or rendered output size: one MiB.
pub const DEFAULT_MAX_YAML_BYTES: usize = 1024 * 1024;

/// Failure from bounded in-memory YAML conversion.
#[derive(Debug, thiserror::Error)]
pub enum YamlError {
    /// Input or output exceeded the caller’s byte budget.
    #[error("yaml {direction} is {actual} bytes; limit is {limit} bytes")]
    TooLarge {
        /// Whether the bounded value was input or output.
        direction: &'static str,
        /// Observed byte length.
        actual: usize,
        /// Configured byte limit.
        limit: usize,
    },
    /// YAML parsing failed; the foreign error type does not leak through the API.
    #[error("yaml parse failed: {message}")]
    Parse {
        /// Redacted parser diagnostic.
        message: String,
    },
    /// YAML serialization failed; the foreign error type does not leak through the API.
    #[error("yaml serialization failed: {message}")]
    Serialize {
        /// Redacted serializer diagnostic.
        message: String,
    },
}

/// Parse bounded YAML text into a caller-owned type using the default budget.
///
/// # Errors
///
/// Returns [`YamlError::TooLarge`] before parsing oversized input, or
/// [`YamlError::Parse`] for invalid YAML/data.
pub fn from_str<T>(text: &str) -> Result<T, YamlError>
where
    T: DeserializeOwned,
{
    from_str_bounded(text, DEFAULT_MAX_YAML_BYTES)
}

/// Parse YAML text after enforcing a caller-supplied byte budget.
///
/// # Errors
///
/// Returns [`YamlError::TooLarge`] before parsing oversized input, or
/// [`YamlError::Parse`] for invalid YAML/data.
pub fn from_str_bounded<T>(text: &str, max_bytes: usize) -> Result<T, YamlError>
where
    T: DeserializeOwned,
{
    ensure_bound("input", text.len(), max_bytes)?;
    serde_yaml_ng::from_str(text).map_err(|error| YamlError::Parse {
        message: error.to_string(),
    })
}

/// Render a value as YAML using the default output budget.
///
/// # Errors
///
/// Returns [`YamlError::Serialize`] on serialization failure or
/// [`YamlError::TooLarge`] when the rendered output exceeds the budget.
pub fn to_string<T>(value: &T) -> Result<String, YamlError>
where
    T: Serialize + ?Sized,
{
    to_string_bounded(value, DEFAULT_MAX_YAML_BYTES)
}

/// Render a value as YAML and reject output larger than `max_bytes`.
///
/// # Errors
///
/// Returns [`YamlError::Serialize`] on serialization failure or
/// [`YamlError::TooLarge`] when the rendered output exceeds the budget.
pub fn to_string_bounded<T>(value: &T, max_bytes: usize) -> Result<String, YamlError>
where
    T: Serialize + ?Sized,
{
    let mut output = BoundedOutput::new(max_bytes);
    if let Err(error) = serde_yaml_ng::to_writer(&mut output, value) {
        if let Some(actual) = output.rejected_size {
            return Err(YamlError::TooLarge {
                direction: "output",
                actual,
                limit: max_bytes,
            });
        }
        return Err(YamlError::Serialize {
            message: error.to_string(),
        });
    }
    String::from_utf8(output.bytes).map_err(|error| YamlError::Serialize {
        message: error.to_string(),
    })
}

/// Internal sink that refuses the write which would cross the output budget.
///
/// Keeping this writer private is intentional: callers get owned YAML
/// conversion, not a generic I/O or foreign serializer surface.
struct BoundedOutput {
    bytes: Vec<u8>,
    limit: usize,
    rejected_size: Option<usize>,
}

impl BoundedOutput {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(128)),
            limit,
            rejected_size: None,
        }
    }
}

impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let attempted = self.bytes.len().saturating_add(bytes.len());
        if attempted > self.limit {
            self.rejected_size = Some(attempted);
            return Err(io::Error::other("yaml output byte budget exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn ensure_bound(direction: &'static str, actual: usize, limit: usize) -> Result<(), YamlError> {
    if actual <= limit {
        return Ok(());
    }
    Err(YamlError::TooLarge {
        direction,
        actual,
        limit,
    })
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, Deserialize, PartialEq, Serialize)]
    struct Config {
        enabled: bool,
    }

    #[test]
    fn bounded_round_trip_uses_owned_contract() {
        let parsed: Config = from_str("enabled: true\n").expect("parse");
        assert_eq!(parsed, Config { enabled: true });
        let rendered = to_string(&parsed).expect("render");
        assert!(rendered.contains("enabled: true"));
    }

    #[test]
    fn oversized_input_is_rejected_before_parsing() {
        let error = from_str_bounded::<Config>("enabled: true\n", 4).expect_err("bounded");
        assert!(matches!(
            error,
            YamlError::TooLarge {
                direction: "input",
                ..
            }
        ));
    }

    #[test]
    fn oversized_output_is_rejected() {
        let error = to_string_bounded(&Config { enabled: true }, 4).expect_err("bounded");
        assert!(matches!(
            error,
            YamlError::TooLarge {
                direction: "output",
                ..
            }
        ));
    }

    #[test]
    fn output_sink_refuses_the_crossing_write() {
        let mut output = BoundedOutput::new(4);
        output.write_all(b"1234").expect("within budget");
        assert!(output.write_all(b"5").is_err());
        assert_eq!(output.bytes, b"1234");
        assert_eq!(output.rejected_size, Some(5));
    }
}
