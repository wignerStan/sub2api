//! Token-aware text truncation for LLM tool output management.
//!
//! Truncates the middle of a UTF-8 string to fit an approximate token budget,
//! preserving the beginning and the end on char boundaries and inserting a
//! `…N tokens truncated…` marker. The ~4 bytes/token approximation matches the
//! upstream codex-rs algorithm so truncation budgets line up across the stack.
//!
//! Adapted from `codex-rs/utils/string/src/truncate.rs`. Zero domain vocabulary.

/// Approximate bytes per token for rough estimates (~4, matching common LLM
/// tokenizers on English/ASCII text).
const APPROX_BYTES_PER_TOKEN: usize = 4;

/// Rough token count estimate for `text` (~4 bytes/token, ceiling division).
///
/// Empty input yields `0`.
#[must_use]
pub fn approx_token_count(text: &str) -> usize {
    let len = text.len();
    len.saturating_add(APPROX_BYTES_PER_TOKEN.saturating_sub(1)) / APPROX_BYTES_PER_TOKEN
}

/// Approximate byte budget for a given token count (~4 bytes/token).
#[must_use]
pub fn approx_bytes_for_tokens(tokens: usize) -> usize {
    tokens.saturating_mul(APPROX_BYTES_PER_TOKEN)
}

/// Convert a byte count to an approximate token count (`u64`, ceiling division).
#[must_use]
pub fn approx_tokens_from_byte_count(bytes: usize) -> u64 {
    let bytes_u64 = u64::try_from(bytes).unwrap_or(u64::MAX);
    let bpt = u64::try_from(APPROX_BYTES_PER_TOKEN).unwrap_or(u64::MAX);
    bytes_u64.saturating_add(bpt.saturating_sub(1)) / bpt
}

/// Truncate the middle of a UTF-8 string to at most `max_tokens` approximate
/// tokens, preserving the beginning and the end.
///
/// Returns the possibly truncated string and `Some(original_token_count)` when
/// truncation actually occurred; otherwise returns the original string and
/// `None`. The marker is reported in token units (`…N tokens truncated…`).
///
/// When `max_tokens` is `0`, the entire string is replaced by the marker. Empty
/// input always yields `("", None)`.
#[must_use]
pub fn truncate_middle_with_token_budget(s: &str, max_tokens: usize) -> (String, Option<u64>) {
    if s.is_empty() {
        return (String::new(), None);
    }

    if max_tokens > 0 && s.len() <= approx_bytes_for_tokens(max_tokens) {
        return (s.to_string(), None);
    }

    let truncated = truncate_with_byte_estimate(s, approx_bytes_for_tokens(max_tokens));
    let total_tokens = approx_tokens_from_byte_count(s.len());

    if truncated == s {
        (truncated, None)
    } else {
        (truncated, Some(total_tokens))
    }
}

/// Truncate the middle of a UTF-8 string to at most `max_bytes` bytes, landing
/// on char boundaries, with a token-unit marker.
fn truncate_with_byte_estimate(s: &str, max_bytes: usize) -> String {
    if s.is_empty() {
        return String::new();
    }

    if max_bytes == 0 {
        return format_truncation_marker(approx_tokens_from_byte_count(s.len()));
    }

    if s.len() <= max_bytes {
        return s.to_string();
    }

    let total_bytes = s.len();
    let (left_budget, right_budget) = split_budget(max_bytes);
    let (left, right) = split_string(s, left_budget, right_budget);
    // Report the byte-budget shortfall in approximate tokens. The
    // char-boundary split may keep a few extra bytes on either side, but the
    // marker intentionally reflects the requested budget difference.
    let removed_tokens = approx_tokens_from_byte_count(total_bytes.saturating_sub(max_bytes));
    let marker = format_truncation_marker(removed_tokens);

    assemble_truncated_output(left, right, &marker)
}

/// Split `s` into a kept prefix and kept suffix on char boundaries, leaving the
/// middle (between the budgets) to be replaced by the truncation marker.
fn split_string(s: &str, beginning_bytes: usize, end_bytes: usize) -> (&str, &str) {
    if s.is_empty() {
        return ("", "");
    }

    let len = s.len();
    let tail_start_target = len.saturating_sub(end_bytes);
    let mut prefix_end = 0usize;
    let mut suffix_start = len;
    let mut suffix_started = false;

    for (idx, ch) in s.char_indices() {
        let char_end = idx + ch.len_utf8();
        if char_end <= beginning_bytes {
            prefix_end = char_end;
            continue;
        }

        if idx >= tail_start_target {
            if !suffix_started {
                suffix_start = idx;
                suffix_started = true;
            }
            continue;
        }
    }

    if suffix_start < prefix_end {
        suffix_start = prefix_end;
    }

    let before = &s[..prefix_end];
    let after = &s[suffix_start..];

    (before, after)
}

fn split_budget(budget: usize) -> (usize, usize) {
    let left = budget / 2;
    (left, budget - left)
}

fn format_truncation_marker(removed_tokens: u64) -> String {
    format!("…{removed_tokens} tokens truncated…")
}

fn assemble_truncated_output(prefix: &str, suffix: &str, marker: &str) -> String {
    let mut out = String::with_capacity(prefix.len() + marker.len() + suffix.len() + 1);
    out.push_str(prefix);
    out.push_str(marker);
    out.push_str(suffix);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approx_token_count_ceiling_division() {
        assert_eq!(approx_token_count(""), 0);
        assert_eq!(approx_token_count("abcd"), 1); // exactly 4 bytes → 1 token
        assert_eq!(approx_token_count("abc"), 1); // 3 bytes → ceil(3/4) = 1
        assert_eq!(approx_token_count("abcdefgh"), 2); // 8 bytes → 2 tokens
    }

    #[test]
    fn approx_bytes_for_tokens_scales_linearly() {
        assert_eq!(approx_bytes_for_tokens(0), 0);
        assert_eq!(approx_bytes_for_tokens(1), 4);
        assert_eq!(approx_bytes_for_tokens(10), 40);
    }

    #[test]
    fn truncate_no_change_when_within_budget() {
        let (out, tokens) = truncate_middle_with_token_budget("hello world", 100);
        assert_eq!(out, "hello world");
        assert_eq!(tokens, None);
    }

    #[test]
    fn truncate_empty_returns_empty_with_none() {
        let (out, tokens) = truncate_middle_with_token_budget("", 10);
        assert_eq!(out, "");
        assert_eq!(tokens, None);
    }

    #[test]
    fn truncate_inserts_token_marker_and_reports_count() {
        let long = "a".repeat(1000);
        let (out, tokens) = truncate_middle_with_token_budget(&long, 10);
        assert_ne!(out, long, "output must differ from input");
        assert!(
            out.contains("tokens truncated…"),
            "output must carry the token marker: {out}"
        );
        // Budget of 10 tokens ≈ 40 bytes kept; the rest is truncated.
        let reported = tokens.expect("truncation must report a token count");
        assert_eq!(reported, approx_tokens_from_byte_count(1000));
        assert!(reported > 0);
    }

    #[test]
    fn truncate_preserves_prefix_and_suffix() {
        let s = "HEADxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxTAIL";
        let (out, _) = truncate_middle_with_token_budget(s, 6); // 6 tokens ≈ 24 bytes kept
        assert!(
            out.starts_with("HEAD"),
            "prefix must be preserved, got: {out}"
        );
        assert!(
            out.ends_with("TAIL"),
            "suffix must be preserved, got: {out}"
        );
    }

    #[test]
    fn truncate_zero_budget_replaces_entirely_with_marker() {
        let (out, tokens) = truncate_middle_with_token_budget("hello world", 0);
        assert!(
            out.contains("tokens truncated…") && !out.contains("hello"),
            "zero budget must drop all content, got: {out}"
        );
        assert!(tokens.is_some(), "zero-budget truncation reports a count");
    }

    #[test]
    fn truncate_respects_multibyte_char_boundaries() {
        // Each 'é' is 2 bytes; ensure we never split a codepoint.
        let s = "café".repeat(50); // 500 bytes
        let (out, _) = truncate_middle_with_token_budget(&s, 10);
        // The output must be valid UTF-8 (String guarantees this); just ensure
        // it contains the marker and is shorter than the input.
        assert!(out.contains("tokens truncated…"));
        assert!(out.len() < s.len());
    }
}
