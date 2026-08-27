//! Fixed-delimiter pair scanning — the generic form of "find `{{ ... }}`
//! regions". A hand-rolled, non-greedy scan with no dependencies: equivalent to
//! the regex `{open}.*?{close}` with surrounding whitespace trimmed from the
//! capture.
//!
//! It closes each pair at the first `close` following its `open`, so
//! overlapping or nested delimiters are not treated as one pair. Pure;
//! allocates only the returned vec.

/// A scanned delimiter pair: the whole-match byte range and the captured inner
/// body with surrounding ASCII whitespace trimmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelimitedSpan {
    /// Start byte offset of `open` (inclusive).
    pub start: usize,
    /// End byte offset, just past `close` (exclusive).
    pub end: usize,
    /// Start byte offset of the trimmed inner body (inclusive).
    pub inner_start: usize,
    /// End byte offset of the trimmed inner body (exclusive).
    pub inner_end: usize,
}

impl DelimitedSpan {
    /// The matched inner body (already whitespace-trimmed), borrowed from the
    /// source.
    pub fn inner<'a>(&self, content: &'a str) -> &'a str {
        &content[self.inner_start..self.inner_end]
    }

    /// The whole matched region (`open` + body + `close`), borrowed from the
    /// source.
    pub fn whole<'a>(&self, content: &'a str) -> &'a str {
        &content[self.start..self.end]
    }
}

/// Scan `content` left-to-right for non-overlapping `open`…`close` pairs,
/// trimming ASCII whitespace around each captured body. Mirrors a non-greedy
/// regex `{open}.*?{close}`: each pair closes at the first `close` at/after the
/// trimmed body start. An unterminated `open` (no following `close`) stops the
/// scan and leaves the remainder verbatim (it is not a pair).
///
/// `open` and `close` are fixed substrings, not patterns.
#[must_use]
pub fn scan_delimited_pairs(content: &str, open: &str, close: &str) -> Vec<DelimitedSpan> {
    let bytes = content.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0;
    while let Some(open_rel) = content[i..].find(open) {
        let start = i + open_rel;
        let inner_lo = start + open.len();
        // Trim leading whitespace after `open`.
        let body_lo = inner_lo
            + bytes[inner_lo..]
                .iter()
                .take_while(|c| c.is_ascii_whitespace())
                .count();
        // Non-greedy: close at the first `close` at/after the body start.
        match content[body_lo..].find(close) {
            Some(close_rel) => {
                let close_start = body_lo + close_rel;
                let inner_end = close_start;
                let body_hi = inner_end
                    - bytes[body_lo..inner_end]
                        .iter()
                        .rev()
                        .take_while(|c| c.is_ascii_whitespace())
                        .count();
                spans.push(DelimitedSpan {
                    start,
                    end: close_start + close.len(),
                    inner_start: body_lo,
                    inner_end: body_hi,
                });
                i = close_start + close.len();
            },
            None => break,
        }
    }
    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_inner_trimmed() {
        let spans = scan_delimited_pairs("a{{  hello  }}b", "{{", "}}");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].inner("a{{  hello  }}b"), "hello");
        assert_eq!(spans[0].whole("a{{  hello  }}b"), "{{  hello  }}");
    }

    #[test]
    fn non_greedy_closes_at_first_close() {
        // The scan closes at the FIRST `}}` (non-greedy). `{{.Field}} suffix }}`
        // yields one pair whose body is `.Field`; the stray `}}` is left alone.
        let spans = scan_delimited_pairs("{{.Field}} suffix }} tail", "{{", "}}");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].inner("{{.Field}} suffix }} tail"), ".Field");
    }

    #[test]
    fn multiple_pairs_each_close_their_own() {
        let spans = scan_delimited_pairs("{{a}}-{{b}}", "{{", "}}");
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].inner("{{a}}-{{b}}"), "a");
        assert_eq!(spans[1].inner("{{a}}-{{b}}"), "b");
    }

    #[test]
    fn empty_body_pair() {
        let spans = scan_delimited_pairs("x{{}}y", "{{", "}}");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].inner("x{{}}y"), "");
    }

    #[test]
    fn unterminated_open_stops_scan() {
        // An `{{` with no following `}}` is not a pair; the scan stops.
        let spans = scan_delimited_pairs("a{{ unfinished", "{{", "}}");
        assert!(spans.is_empty());
    }

    #[test]
    fn generic_delimiters() {
        // Not just braces — works for any fixed open/close.
        let spans = scan_delimited_pairs("[ a ] [ b ]", "[", "]");
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].inner("[ a ] [ b ]"), "a");
        assert_eq!(spans[1].inner("[ a ] [ b ]"), "b");
    }
}
