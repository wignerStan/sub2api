//! Validated path segment — safe for filesystem use.

/// A validated path segment (single component, no separators).
///
/// Rejects empty strings, path separators (`/`, `\`), parent refs (`..`),
/// and null bytes. Safe for use as a single filesystem path component.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ValidatedPathSegment(String);

impl ValidatedPathSegment {
    /// Parse and validate a path segment.
    ///
    /// # Errors
    ///
    /// Returns `ValueError::InvalidPathSegment` if the input is empty,
    /// contains `/`, `\`, `..`, or null bytes.
    pub fn parse(s: &str) -> Result<Self, crate::value_error::ValueError> {
        if s.is_empty() {
            return Err(crate::value_error::ValueError::InvalidPathSegment);
        }
        if s.contains('/') || s.contains('\\') {
            return Err(crate::value_error::ValueError::InvalidPathSegment);
        }
        if s == ".." || s == "." {
            return Err(crate::value_error::ValueError::InvalidPathSegment);
        }
        if s.contains('\0') {
            return Err(crate::value_error::ValueError::InvalidPathSegment);
        }
        Ok(Self(s.to_string()))
    }

    /// Returns the validated segment as a string slice.
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
    fn valid_segment() {
        let seg = ValidatedPathSegment::parse("hello").unwrap();
        assert_eq!(seg.as_str(), "hello");
    }

    #[test]
    fn empty_fails() {
        let err = ValidatedPathSegment::parse("").unwrap_err();
        assert!(
            err.to_string().contains("invalid path segment"),
            "got: {err}"
        );
    }

    #[test]
    fn slash_fails() {
        let err = ValidatedPathSegment::parse("a/b").unwrap_err();
        assert!(
            err.to_string().contains("invalid path segment"),
            "got: {err}"
        );
    }

    #[test]
    fn backslash_fails() {
        let err = ValidatedPathSegment::parse("a\\b").unwrap_err();
        assert!(
            err.to_string().contains("invalid path segment"),
            "got: {err}"
        );
    }

    #[test]
    fn dotdot_fails() {
        let err = ValidatedPathSegment::parse("..").unwrap_err();
        assert!(
            err.to_string().contains("invalid path segment"),
            "got: {err}"
        );
    }

    #[test]
    fn dot_fails() {
        let err = ValidatedPathSegment::parse(".").unwrap_err();
        assert!(
            err.to_string().contains("invalid path segment"),
            "got: {err}"
        );
    }

    #[test]
    fn null_byte_fails() {
        let err = ValidatedPathSegment::parse("a\0b").unwrap_err();
        assert!(
            err.to_string().contains("invalid path segment"),
            "got: {err}"
        );
    }

    mod edge {
        use super::*;

        #[test]
        fn dot_in_middle_is_ok() {
            let seg = ValidatedPathSegment::parse("file.txt")
                .expect("'file.txt' should be a valid path segment");
            assert_eq!(seg.as_str(), "file.txt");
        }

        #[test]
        fn leading_dot_is_ok() {
            let seg = ValidatedPathSegment::parse(".hidden")
                .expect("'.hidden' should be a valid path segment");
            assert_eq!(seg.as_str(), ".hidden");
        }

        #[test]
        fn unicode_is_ok() {
            let seg = ValidatedPathSegment::parse("日本語")
                .expect("'日本語' should be a valid path segment");
            assert_eq!(seg.as_str(), "日本語");
        }
    }
}
