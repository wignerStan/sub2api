//! Small `safeParse`-style validation helpers.
//!
//! Pure, dependency-free value validators that collect human-readable error
//! messages. Useful as a thin, generic validation API for inputs and config,
//! or for contexts that have no schema/validation framework available.
//!
//! Zero domain vocabulary — pure predicate/value helpers, like the rest of
//! `utils`.

/// A collected list of validation errors (`safeParse` style): empty means
/// valid; each entry is a human-readable message naming the field and the
/// failure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationErrors {
    pub errors: Vec<String>,
}

impl ValidationErrors {
    /// An empty (valid) error collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a validation error message (e.g. produced by one of the helpers).
    pub fn push(&mut self, message: String) {
        self.errors.push(message);
    }

    /// Record an error only if `err` is `Some`.
    pub fn push_opt(&mut self, err: Option<String>) {
        if let Some(message) = err {
            self.errors.push(message);
        }
    }

    /// No errors recorded => valid.
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

impl std::ops::Deref for ValidationErrors {
    type Target = [String];
    fn deref(&self) -> &[String] {
        &self.errors
    }
}

impl IntoIterator for ValidationErrors {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;
    fn into_iter(self) -> Self::IntoIter {
        self.errors.into_iter()
    }
}

// --- Field validators: each returns `Some(message)` on failure, `None` on pass.
// A caller collects these into a `ValidationErrors`. ---

/// `Some` if the value is `None`/empty (required-field check).
pub fn required<T: AsRef<str>>(value: Option<T>, field: &str) -> Option<String> {
    match &value {
        Some(v) if !v.as_ref().is_empty() => None,
        _ => Some(format!("{field}: required value is missing or empty")),
    }
}

/// `Some` if `value` is not one of the allowed `choices`.
pub fn one_of(value: &str, choices: &[&str], field: &str) -> Option<String> {
    if choices.contains(&value) {
        None
    } else {
        Some(format!(
            "{field}: {value:?} is not one of the allowed values {}",
            choices
                .iter()
                .map(|c| format!("{c:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

/// `Some` if `value` is outside `[min, max]` (inclusive bounds).
pub fn in_range(value: i64, min: i64, max: i64, field: &str) -> Option<String> {
    if (min..=max).contains(&value) {
        None
    } else {
        Some(format!("{field}: {value} is out of range [{min}, {max}]"))
    }
}

/// `Some` if the string's char length is outside `[min, max]` (inclusive).
pub fn len_bounds(value: &str, min: usize, max: usize, field: &str) -> Option<String> {
    let len = value.chars().count();
    if (min..=max).contains(&len) {
        None
    } else {
        Some(format!(
            "{field}: length {len} is out of bounds [{min}, {max}]"
        ))
    }
}

/// `Some` if the string does not fully match the regex.
///
/// Compiled per call (no caching): use only for occasional checks, not hot
/// paths. Depend on the `regex` crate directly from the owner that needs it.
pub fn matches_regex(value: &str, re: &regex::Regex, field: &str) -> Option<String> {
    if re.is_match(value) {
        None
    } else {
        Some(format!(
            "{field}: {value:?} does not match required pattern"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_valid() {
        assert!(ValidationErrors::new().is_valid());
        assert!(ValidationErrors::default().is_valid());
    }

    #[test]
    fn push_and_push_opt_collect() {
        let mut errs = ValidationErrors::new();
        errs.push("a: bad".to_string());
        errs.push_opt(None);
        errs.push_opt(Some("b: worse".to_string()));
        assert!(!errs.is_valid());
        assert_eq!(
            errs.errors,
            vec!["a: bad".to_string(), "b: worse".to_string()]
        );
    }

    #[test]
    fn required_passes_and_fails() {
        assert!(required(Some("x"), "f").is_none());
        assert!(required(Some(""), "f").is_some());
        assert!(required::<&str>(None, "f").is_some());
    }

    #[test]
    fn one_of_passes_and_fails() {
        assert!(one_of("a", &["a", "b"], "f").is_none());
        let err = one_of("c", &["a", "b"], "f").unwrap();
        assert!(err.contains("not one of") && err.contains("\"a\"") && err.contains("\"b\""));
    }

    #[test]
    fn in_range_passes_and_fails() {
        assert!(in_range(5, 1, 10, "f").is_none());
        let err = in_range(0, 1, 10, "f").unwrap();
        assert!(err.contains("out of range [1, 10]"));
    }

    #[test]
    fn len_bounds_passes_and_fails() {
        assert!(len_bounds("abc", 1, 5, "f").is_none());
        let err = len_bounds("toolong", 1, 3, "f").unwrap();
        assert!(err.contains("out of bounds [1, 3]"));
    }

    #[test]
    fn matches_regex_passes_and_fails() {
        let re = regex::Regex::new(r"^[a-z]+$").unwrap();
        assert!(matches_regex("abc", &re, "f").is_none());
        assert!(matches_regex("a1", &re, "f").is_some());
    }
}
