//! Generic text/string helpers.
//!
//! Zero domain vocabulary — knows strings and bytes, nothing else.

/// Return a trimmed non-empty slice, or `None` if blank.
#[must_use]
pub fn non_empty_trimmed(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty() { None } else { Some(value) }
}

/// Truncate a string to `max_bytes` using a character-count marker in the
/// middle. Preserves the beginning and end.
///
/// Returns the input unchanged if it fits. Returns an empty string for empty
/// input regardless of `max_bytes`.
#[must_use]
pub fn truncate_middle_chars(s: &str, max_bytes: usize) -> String {
    if s.is_empty() {
        return String::new();
    }
    if max_bytes == 0 {
        let removed_chars = s.chars().count();
        return format!("…{removed_chars} chars truncated…");
    }
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let left_budget = max_bytes / 2;
    let right_budget = max_bytes - left_budget;

    let (left_end, right_start) = split_at_budgets(s, left_budget, right_budget);
    let removed_chars = s[left_end..right_start].chars().count();
    let left = &s[..left_end];
    let right = &s[right_start..];
    format!("{left}…{removed_chars} chars truncated…{right}")
}

/// Slice a `&str` to at most `maxb` bytes, landing on a char boundary.
///
/// Returns the original slice if it already fits.
#[must_use]
pub fn take_bytes_at_char_boundary(s: &str, maxb: usize) -> &str {
    if s.len() <= maxb {
        return s;
    }
    let mut last_ok = 0;
    for (i, ch) in s.char_indices() {
        let end = i + ch.len_utf8();
        if end > maxb {
            break;
        }
        last_ok = end;
    }
    &s[..last_ok]
}

/// Find all UUIDs in a string.
///
/// Detects the standard `8-4-4-4-12` hex format. No regex dependency —
/// scans byte-by-byte since UUID characters are pure ASCII.
#[must_use]
pub fn find_uuids(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut results = Vec::new();
    if len < 36 {
        return results;
    }
    let mut i = 0;
    while i + 36 <= len {
        if is_uuid_at(bytes, i)
            && (i == 0 || !bytes[i - 1].is_ascii_hexdigit())
            && (i + 36 == len || !bytes[i + 36].is_ascii_hexdigit())
        {
            results.push(s[i..i + 36].to_string());
            i += 37;
        } else {
            i += 1;
        }
    }
    results
}

/// Sanitize a tag value to comply with metric tag validation rules:
/// only ASCII alphanumeric, `.`, `_`, `-`, and `/` are allowed.
///
/// Trims leading/trailing underscores, caps at 256 chars, and falls back to
/// `"unspecified"` if the result is empty or has no alphanumeric chars.
#[must_use]
pub fn sanitize_metric_tag_value(value: &str) -> String {
    const MAX_LEN: usize = 256;
    let sanitized: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '/') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = sanitized.trim_matches('_');
    if trimmed.is_empty() || !trimmed.chars().any(|ch| ch.is_ascii_alphanumeric()) {
        return "unspecified".to_string();
    }
    if trimmed.len() <= MAX_LEN {
        trimmed.to_string()
    } else {
        trimmed[..MAX_LEN].to_string()
    }
}

/// Convert a markdown-style `#L..` location suffix into a terminal-friendly
/// `:line[:column][-line[:column]]` suffix.
#[must_use]
pub fn normalize_markdown_hash_location_suffix(suffix: &str) -> Option<String> {
    let fragment = suffix.strip_prefix('#')?;
    let (start, end) = match fragment.split_once('-') {
        Some((s, e)) => (s, Some(e)),
        None => (fragment, None),
    };
    let (start_line, start_column) = parse_location_point(start)?;
    let mut normalized = String::from(":");
    normalized.push_str(start_line);
    if let Some(column) = start_column {
        normalized.push(':');
        normalized.push_str(column);
    }
    if let Some(end) = end {
        let (end_line, end_column) = parse_location_point(end)?;
        normalized.push('-');
        normalized.push_str(end_line);
        if let Some(column) = end_column {
            normalized.push(':');
            normalized.push_str(column);
        }
    }
    Some(normalized)
}

fn parse_location_point(point: &str) -> Option<(&str, Option<&str>)> {
    let point = point.strip_prefix('L')?;
    match point.split_once('C') {
        Some((line, column)) => Some((line, Some(column))),
        None => Some((point, None)),
    }
}

fn split_at_budgets(s: &str, beginning_bytes: usize, end_bytes: usize) -> (usize, usize) {
    let len = s.len();
    let tail_start_target = len.saturating_sub(end_bytes);
    let mut prefix_end = 0usize;
    let mut suffix_start = len;

    for (idx, ch) in s.char_indices() {
        let char_end = idx + ch.len_utf8();
        if char_end <= beginning_bytes {
            prefix_end = char_end;
        } else if idx >= tail_start_target && suffix_start == len {
            suffix_start = idx;
        }
    }

    if suffix_start < prefix_end {
        suffix_start = prefix_end;
    }
    (prefix_end, suffix_start)
}

fn is_uuid_at(b: &[u8], offset: usize) -> bool {
    let chunk = &b[offset..offset + 36];
    chunk[0..8].iter().all(u8::is_ascii_hexdigit)
        && chunk[8] == b'-'
        && chunk[9..13].iter().all(u8::is_ascii_hexdigit)
        && chunk[13] == b'-'
        && chunk[14..18].iter().all(u8::is_ascii_hexdigit)
        && chunk[18] == b'-'
        && chunk[19..23].iter().all(u8::is_ascii_hexdigit)
        && chunk[23] == b'-'
        && chunk[24..36].iter().all(u8::is_ascii_hexdigit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_empty_trimmed_filters_blanks() {
        assert_eq!(non_empty_trimmed("  value  "), Some("value"));
        assert_eq!(non_empty_trimmed("  "), None);
    }

    #[test]
    fn truncate_middle_chars_fits() {
        assert_eq!(truncate_middle_chars("short", 100), "short");
    }

    #[test]
    fn truncate_middle_chars_truncates() {
        let result = truncate_middle_chars("hello world this is long", 10);
        assert!(result.contains("…"));
        assert!(result.contains("chars truncated…"));
    }

    #[test]
    fn truncate_middle_chars_empty() {
        assert_eq!(truncate_middle_chars("", 10), "");
    }

    #[test]
    fn truncate_middle_chars_zero_budget() {
        let result = truncate_middle_chars("hello", 0);
        assert!(result.contains("5 chars truncated"));
    }

    #[test]
    fn take_bytes_at_char_boundary_fits() {
        assert_eq!(take_bytes_at_char_boundary("hello", 10), "hello");
    }

    #[test]
    fn take_bytes_at_char_boundary_truncates() {
        assert_eq!(take_bytes_at_char_boundary("hello", 3), "hel");
    }

    #[test]
    fn take_bytes_at_char_boundary_respects_multibyte() {
        let s = "café";
        assert_eq!(take_bytes_at_char_boundary(s, 4), "caf");
    }

    #[test]
    fn find_uuids_finds_multiple() {
        let input = "x 00112233-4455-6677-8899-aabbccddeeff y 12345678-90ab-cdef-0123-456789abcdef";
        assert_eq!(
            find_uuids(input),
            vec![
                "00112233-4455-6677-8899-aabbccddeeff".to_string(),
                "12345678-90ab-cdef-0123-456789abcdef".to_string(),
            ]
        );
    }

    #[test]
    fn find_uuids_ignores_invalid_and_empty_input() {
        // Wrong segment lengths are not UUIDs.
        assert_eq!(
            find_uuids("not-a-uuid-1234-5678-9abc-def0-123456789abc"),
            Vec::<String>::new()
        );
        // Too short to contain even one 36-char UUID.
        assert!(find_uuids("short").is_empty());
        // Non-ASCII neighbors do not block a clean UUID that follows them.
        assert_eq!(
            find_uuids("🙂 55e5d6f7-8a7f-4d2a-8d88-123456789012 end"),
            vec!["55e5d6f7-8a7f-4d2a-8d88-123456789012".to_string()]
        );
        // A hex run continues past the 36-char window, so it is not a UUID.
        assert_eq!(
            find_uuids("55e5d6f7-8a7f-4d2a-8d88-123456789012abc"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn sanitize_metric_tag_value_replaces_invalid() {
        assert_eq!(sanitize_metric_tag_value("bad value!"), "bad_value");
    }

    #[test]
    fn sanitize_metric_tag_value_falls_back_when_empty_of_alnum() {
        // Only separators → no alphanumeric content → "unspecified".
        assert_eq!(sanitize_metric_tag_value("///"), "unspecified");
        assert_eq!(sanitize_metric_tag_value("____"), "unspecified");
        assert_eq!(sanitize_metric_tag_value(""), "unspecified");
    }

    #[test]
    fn normalize_location_single_point() {
        assert_eq!(
            normalize_markdown_hash_location_suffix("#L74C3"),
            Some(":74:3".to_string())
        );
    }

    #[test]
    fn normalize_location_range_and_line_only() {
        // Full range: #L74C3-L76C9 → :74:3-76:9.
        assert_eq!(
            normalize_markdown_hash_location_suffix("#L74C3-L76C9"),
            Some(":74:3-76:9".to_string())
        );
        // Line only, no column.
        assert_eq!(
            normalize_markdown_hash_location_suffix("#L74"),
            Some(":74".to_string())
        );
        // Missing leading '#' → None.
        assert_eq!(normalize_markdown_hash_location_suffix("L74C3"), None);
    }
}
