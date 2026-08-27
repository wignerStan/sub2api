//! Minimal strict mustache-style templating for prompt and text assets.
//!
//! Supported syntax:
//! - `{{ name }}` placeholder interpolation (whitespace around the name is
//!   trimmed, so `{{name}}` and `{{ name }}` are equivalent).
//! - `{{{{` for a literal `{{`.
//! - `}}}}` for a literal `}}`.
//!
//! Rendering is strict: every placeholder must be supplied exactly once, and
//! every supplied value must be used. Missing, extra, or duplicate values are
//! reported as errors. Zero external dependencies.
//!
//! Adapted from `codex-rs/utils/template/src/lib.rs`. Zero domain vocabulary.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

/// A parse-time failure while constructing a [`Template`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateParseError {
    /// A placeholder with no name, e.g. `{{ }}`.
    EmptyPlaceholder {
        /// Byte offset where the offending placeholder began.
        start: usize,
    },
    /// A placeholder that contains a nested `{{`, e.g. `{{ outer {{ inner }} }}`.
    NestedPlaceholder {
        /// Byte offset where the offending placeholder began.
        start: usize,
    },
    /// A `}}` with no matching opening `{{`.
    UnmatchedClosingDelimiter {
        /// Byte offset of the stray `}}`.
        start: usize,
    },
    /// A placeholder that is never closed with `}}`.
    UnterminatedPlaceholder {
        /// Byte offset where the unterminated placeholder began.
        start: usize,
    },
}

impl fmt::Display for TemplateParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPlaceholder { start } => {
                write!(f, "template placeholder at byte {start} is empty")
            },
            Self::NestedPlaceholder { start } => {
                write!(
                    f,
                    "template placeholder starting at byte {start} contains a nested `{{`"
                )
            },
            Self::UnmatchedClosingDelimiter { start } => {
                write!(f, "template contains an unmatched `}}` at byte {start}")
            },
            Self::UnterminatedPlaceholder { start } => {
                write!(
                    f,
                    "template placeholder starting at byte {start} is missing `}}`"
                )
            },
        }
    }
}

impl Error for TemplateParseError {}

/// A render-time failure while applying values to a [`Template`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateRenderError {
    /// A placeholder name was supplied more than once.
    DuplicateValue {
        /// The duplicated placeholder name.
        name: String,
    },
    /// A supplied value is not referenced by any placeholder.
    ExtraValue {
        /// The unused value name.
        name: String,
    },
    /// A placeholder was not given a value.
    MissingValue {
        /// The placeholder name that lacked a value.
        name: String,
    },
}

impl fmt::Display for TemplateRenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateValue { name } => {
                write!(f, "template value `{name}` was provided more than once")
            },
            Self::ExtraValue { name } => {
                write!(f, "template value `{name}` is not used by this template")
            },
            Self::MissingValue { name } => {
                write!(f, "template placeholder `{name}` is missing a value")
            },
        }
    }
}

impl Error for TemplateRenderError {}

/// Either a parse or render failure for a [`Template`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateError {
    /// The template source could not be parsed.
    Parse(TemplateParseError),
    /// The template could not be rendered with the supplied values.
    Render(TemplateRenderError),
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(err) => err.fmt(f),
            Self::Render(err) => err.fmt(f),
        }
    }
}

impl Error for TemplateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Parse(err) => Some(err),
            Self::Render(err) => Some(err),
        }
    }
}

impl From<TemplateParseError> for TemplateError {
    fn from(value: TemplateParseError) -> Self {
        Self::Parse(value)
    }
}

impl From<TemplateRenderError> for TemplateError {
    fn from(value: TemplateRenderError) -> Self {
        Self::Render(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    Placeholder(String),
}

/// A parsed strict mustache template, ready to render against a value map.
///
/// Construct with [`Template::parse`]; render with [`Template::render`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    placeholders: BTreeSet<String>,
    segments: Vec<Segment>,
}

impl Template {
    /// Parse `source` into a reusable [`Template`].
    ///
    /// # Errors
    ///
    /// Returns a [`TemplateParseError`] (wrapped in [`TemplateError::Parse`])
    /// for empty/nested/unterminated placeholders or unmatched `}}`.
    pub fn parse(source: &str) -> Result<Self, TemplateError> {
        let mut placeholders = BTreeSet::new();
        let mut segments = Vec::new();
        let mut literal_start = 0usize;
        let mut cursor = 0usize;

        while cursor < source.len() {
            let rest = &source[cursor..];
            if rest.starts_with("{{{{") {
                push_literal(&mut segments, &source[literal_start..cursor]);
                push_literal(&mut segments, "{{");
                cursor += "{{{{".len();
                literal_start = cursor;
                continue;
            }
            if rest.starts_with("}}}}") {
                push_literal(&mut segments, &source[literal_start..cursor]);
                push_literal(&mut segments, "}}");
                cursor += "}}}}".len();
                literal_start = cursor;
                continue;
            }
            if rest.starts_with("{{") {
                push_literal(&mut segments, &source[literal_start..cursor]);
                let (placeholder, next_cursor) = parse_placeholder(source, cursor)?;
                placeholders.insert(placeholder.clone());
                segments.push(Segment::Placeholder(placeholder));
                cursor = next_cursor;
                literal_start = cursor;
                continue;
            }
            if rest.starts_with("}}") {
                return Err(TemplateParseError::UnmatchedClosingDelimiter { start: cursor }.into());
            }

            let Some(ch) = rest.chars().next() else {
                break;
            };
            cursor += ch.len_utf8();
        }

        push_literal(&mut segments, &source[literal_start..]);
        Ok(Self {
            placeholders,
            segments,
        })
    }

    /// The sorted, de-duplicated placeholder names this template references.
    #[must_use]
    pub fn placeholders(&self) -> impl ExactSizeIterator<Item = &str> {
        self.placeholders.iter().map(String::as_str)
    }

    /// Render the template against `values`.
    ///
    /// Every placeholder must have a value and every value must be used; any
    /// mismatch is a render error. Placeholder names are matched after
    /// trimming surrounding whitespace, so `{{ name }}` and `{{name}}` both
    /// look up `values["name"]`.
    ///
    /// # Errors
    ///
    /// Returns a [`TemplateRenderError`] (wrapped in [`TemplateError::Render`])
    /// for missing placeholders, extra values, or duplicate value names.
    pub fn render(&self, values: &BTreeMap<String, String>) -> Result<String, TemplateError> {
        for placeholder in &self.placeholders {
            if !values.contains_key(placeholder.as_str()) {
                return Err(TemplateRenderError::MissingValue {
                    name: placeholder.clone(),
                }
                .into());
            }
        }

        for name in values.keys() {
            if !self.placeholders.contains(name.as_str()) {
                return Err(TemplateRenderError::ExtraValue { name: name.clone() }.into());
            }
        }

        let mut rendered = String::new();
        for segment in &self.segments {
            match segment {
                Segment::Literal(literal) => rendered.push_str(literal),
                Segment::Placeholder(name) => {
                    let Some(value) = values.get(name.as_str()) else {
                        return Err(TemplateRenderError::MissingValue { name: name.clone() }.into());
                    };
                    rendered.push_str(value);
                },
            }
        }
        Ok(rendered)
    }
}

fn push_literal(segments: &mut Vec<Segment>, literal: &str) {
    if literal.is_empty() {
        return;
    }

    if let Some(Segment::Literal(existing)) = segments.last_mut() {
        existing.push_str(literal);
    } else {
        segments.push(Segment::Literal(literal.to_string()));
    }
}

fn parse_placeholder(source: &str, start: usize) -> Result<(String, usize), TemplateParseError> {
    let placeholder_start = start + "{{".len();
    let mut cursor = placeholder_start;

    while cursor < source.len() {
        let rest = &source[cursor..];
        if rest.starts_with("{{") {
            return Err(TemplateParseError::NestedPlaceholder { start });
        }
        if rest.starts_with("}}") {
            let placeholder = source[placeholder_start..cursor].trim();
            if placeholder.is_empty() {
                return Err(TemplateParseError::EmptyPlaceholder { start });
            }
            return Ok((placeholder.to_string(), cursor + "}}".len()));
        }

        let Some(ch) = rest.chars().next() else {
            break;
        };
        cursor += ch.len_utf8();
    }

    Err(TemplateParseError::UnterminatedPlaceholder { start })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn render_replaces_placeholders_with_and_without_whitespace() {
        let template =
            Template::parse("Hello, {{ name }}. You are in {{place}}. {{ name }} is repeated.")
                .unwrap();
        let rendered = template
            .render(&map(&[("name", "Codex"), ("place", "codex-rs")]))
            .unwrap();
        assert_eq!(
            rendered,
            "Hello, Codex. You are in codex-rs. Codex is repeated."
        );
    }

    #[test]
    fn parsed_templates_can_be_reused() {
        let template = Template::parse("{{greeting}}, {{ name }}!").unwrap();
        assert_eq!(
            template.render(&map(&[("greeting", "Hello"), ("name", "Codex")])),
            Ok("Hello, Codex!".to_string())
        );
        assert_eq!(
            template.render(&map(&[("greeting", "Hi"), ("name", "builder")])),
            Ok("Hi, builder!".to_string())
        );
    }

    #[test]
    fn render_supports_literal_delimiter_escapes() {
        let template =
            Template::parse("literal open: {{{{, literal close: }}}}, value: {{ name }}").unwrap();
        let rendered = template.render(&map(&[("name", "Codex")])).unwrap();
        assert_eq!(
            rendered,
            "literal open: {{, literal close: }}, value: Codex"
        );
    }

    #[test]
    fn render_supports_multiline_templates_and_adjacent_placeholders() {
        let template = Template::parse("Line 1: {{first}}{{second}}\nLine 2: {{ third }}").unwrap();
        let rendered = template
            .render(&map(&[("first", "A"), ("second", "B"), ("third", "C")]))
            .unwrap();
        assert_eq!(rendered, "Line 1: AB\nLine 2: C");
    }

    #[test]
    fn placeholders_are_sorted_and_unique() {
        let template = Template::parse("{{ b }} {{ a }} {{ b }}").unwrap();
        assert_eq!(template.placeholders().collect::<Vec<_>>(), vec!["a", "b"]);
    }

    #[test]
    fn parse_errors_when_placeholder_is_empty() {
        let err = Template::parse("Hello, {{   }}.").unwrap_err();
        assert_eq!(
            err,
            TemplateError::Parse(TemplateParseError::EmptyPlaceholder { start: 7 })
        );
    }

    #[test]
    fn parse_errors_when_placeholder_is_unterminated() {
        let err = Template::parse("Hello, {{ name.").unwrap_err();
        assert_eq!(
            err,
            TemplateError::Parse(TemplateParseError::UnterminatedPlaceholder { start: 7 })
        );
    }

    #[test]
    fn parse_errors_when_placeholder_is_nested() {
        let err = Template::parse("Hello, {{ outer {{ inner }} }}.").unwrap_err();
        assert_eq!(
            err,
            TemplateError::Parse(TemplateParseError::NestedPlaceholder { start: 7 })
        );
    }

    #[test]
    fn parse_errors_when_closing_delimiter_is_unmatched() {
        let err = Template::parse("Hello, }} world.").unwrap_err();
        assert_eq!(
            err,
            TemplateError::Parse(TemplateParseError::UnmatchedClosingDelimiter { start: 7 })
        );
    }

    #[test]
    fn render_errors_when_placeholder_is_missing() {
        let template = Template::parse("Hello, {{ name }}.").unwrap();
        let empty: BTreeMap<String, String> = BTreeMap::new();
        assert_eq!(
            template.render(&empty),
            Err(TemplateError::Render(TemplateRenderError::MissingValue {
                name: "name".to_string()
            }))
        );
    }

    #[test]
    fn render_errors_when_extra_value_is_provided() {
        let template = Template::parse("Hello, {{ name }}.").unwrap();
        assert_eq!(
            template.render(&map(&[("name", "Codex"), ("unused", "extra")])),
            Err(TemplateError::Render(TemplateRenderError::ExtraValue {
                name: "unused".to_string()
            }))
        );
    }

    #[test]
    fn render_empty_template_with_empty_values_succeeds() {
        let template = Template::parse("no placeholders here").unwrap();
        let empty: BTreeMap<String, String> = BTreeMap::new();
        assert_eq!(
            template.render(&empty),
            Ok("no placeholders here".to_string())
        );
    }
}
