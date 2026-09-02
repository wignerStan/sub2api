//! Validated non-empty string.

/// A string guaranteed to be non-empty and non-whitespace.
///
/// Constructed via [`NonEmptyString::parse`]. Once constructed, the type
/// system guarantees the content is non-trivial.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct NonEmptyString(String);

impl NonEmptyString {
    /// Parse a raw string, rejecting empty or whitespace-only input.
    ///
    /// # Errors
    ///
    /// Returns `ValueError::EmptyInput` if the input is empty or
    /// contains only whitespace.
    pub fn parse(s: &str) -> Result<Self, crate::value_error::ValueError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(crate::value_error::ValueError::EmptyInput);
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Returns the validated content as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the inner String, consuming self.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid() {
        let s = NonEmptyString::parse("hello").expect("non-empty string should parse");
        assert_eq!(s.as_str(), "hello");
    }

    #[test]
    fn parse_trims_whitespace() {
        let s = NonEmptyString::parse("  hello  ").expect("whitespace-padded string should parse");
        assert_eq!(s.as_str(), "hello");
    }

    #[test]
    fn parse_empty_fails() {
        let err = NonEmptyString::parse("").expect_err("empty string should be rejected");
        assert!(
            err.to_string().contains("empty or whitespace"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_whitespace_only_fails() {
        let err =
            NonEmptyString::parse("   ").expect_err("whitespace-only string should be rejected");
        assert!(
            err.to_string().contains("empty or whitespace"),
            "got: {err}"
        );
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn parse_roundtrip(s in "[^\t\n\r ].{0,100}") {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    prop_assert!(NonEmptyString::parse(&s).is_err());
                } else {
                    let nes = NonEmptyString::parse(&s).expect("non-empty proptest string should parse");
                    prop_assert_eq!(nes.as_str(), trimmed);
                }
            }
        }
    }
}
