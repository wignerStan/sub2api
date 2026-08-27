//! `RequestTarget` — pure analysis of an HTTP request-target path.
//!
//! A request-target path is client-controlled. Without structural analysis a
//! guard that scans for a few literal substrings (`%2F`, `%5C`) misses
//! double-encoded forms, encoded dot segments, decoded control chars, and
//! non-canonical percent-encoding. [`analyze_request_path`] walks the path once
//! and returns a structured [`PathAnalysis`] so a guard can reject on a real
//! policy instead of a substring heuristic.

/// The result of analyzing a request-target path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathAnalysis {
    /// The path contained a percent-encoded path separator (`%2F`/`%5C`,
    /// any case). A handler that decodes and re-splits on `/` would see an
    /// extra segment an attacker smuggled past the router.
    pub encoded_separator: bool,
    /// The path contained a percent-encoded dot segment (`%2E`, any case),
    /// which decodes to `.` and can shift the resolved path if a downstream
    /// component normalizes after decoding.
    pub encoded_dot_segment: bool,
    /// The path contained the Unicode replacement char (`\u{FFFD}`), which
    /// `http` inserts when the raw bytes are not valid UTF-8.
    pub non_utf8: bool,
    /// The path contained a decoded control char (C0 range + DEL) after
    /// percent-decoding. Such chars have no business in a request-target.
    pub decoded_control_char: bool,
    /// The path contained a non-canonical percent-encoding: a `%` followed by
    /// fewer than two hex digits, or `%` not followed by hex at all. Such
    /// sequences are malformed and rejected by strict decoders.
    pub malformed_percent: bool,
}

impl PathAnalysis {
    /// Whether the analysis found any violation under the strict policy
    /// (encoded separator, encoded dot segment, non-UTF-8, decoded control
    /// char, malformed percent-encoding).
    #[must_use]
    pub const fn any_violation(&self) -> bool {
        self.encoded_separator
            || self.encoded_dot_segment
            || self.non_utf8
            || self.decoded_control_char
            || self.malformed_percent
    }
}

/// Analyze a request-target path for normalization violations.
///
/// Pure: no allocation beyond the returned struct, no I/O. Walks the path bytes
/// once. The input is the raw path as `http::Uri::path()` returns it (already
/// percent-decoded for non-UTF-8 → replacement char, but encoded separators
/// survive because `path()` returns the encoded form).
///
/// Detects:
///
/// - Encoded separators: `%2F`/`%5C` (any case).
/// - Encoded dot segments: `%2E` (any case).
/// - Non-UTF-8: the Unicode replacement char `\u{FFFD}`.
/// - Decoded control chars: `%XX` decoding to a byte in `0x00..=0x1F` or `0x7F`.
/// - Malformed percent-encoding: `%` not followed by two hex digits.
#[must_use]
pub fn analyze_request_path(path: &str) -> PathAnalysis {
    let bytes = path.as_bytes();
    let mut out = PathAnalysis::default();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            // Need two hex digits after '%'.
            let h1 = bytes.get(i + 1).copied();
            let h2 = bytes.get(i + 2).copied();
            match (h1, h2) {
                (Some(d1), Some(d2)) if is_hex(d1) && is_hex(d2) => {
                    let decoded = (hex_val(d1) << 4) | hex_val(d2);
                    match decoded {
                        b'/' | b'\\' => out.encoded_separator = true,
                        b'.' => out.encoded_dot_segment = true,
                        c if c <= 0x1F || c == 0x7F => out.decoded_control_char = true,
                        _ => {},
                    }
                    i += 3;
                    continue;
                },
                _ => {
                    out.malformed_percent = true;
                    i += 1;
                    continue;
                },
            }
        }
        if b == 0xEF && bytes.get(i + 1) == Some(&0xBF) && bytes.get(i + 2) == Some(&0xBD) {
            out.non_utf8 = true;
            i += 3;
            continue;
        }
        // Bare (already-decoded) control char — reject too, a downstream that
        // trusts the path should never see one.
        if b <= 0x1F || b == 0x7F {
            out.decoded_control_char = true;
        }
        i += 1;
    }
    out
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'A'..=b'F' => b - b'A' + 10,
        b'a'..=b'f' => b - b'a' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_path_has_no_violations() {
        assert_eq!(analyze_request_path("/items/42"), PathAnalysis::default());
        assert!(!analyze_request_path("/items/42").any_violation());
    }

    #[test]
    fn detects_encoded_forward_slash_any_case() {
        for p in ["/x%2Fy", "/x%2fy", "/a%2Fb%2Fc"] {
            let a = analyze_request_path(p);
            assert!(a.encoded_separator, "path: {p}");
        }
    }

    #[test]
    fn detects_encoded_backslash_any_case() {
        for p in ["/x%5Cy", "/x%5cy"] {
            let a = analyze_request_path(p);
            assert!(a.encoded_separator, "path: {p}");
        }
    }

    #[test]
    fn detects_encoded_dot_segment() {
        let a = analyze_request_path("/%2E%2E/secret");
        assert!(a.encoded_dot_segment);
        // A bare `..` is not an encoded dot — only %2E counts here (the encoded
        // form is what slips past routers that decode after splitting).
        let a = analyze_request_path("/../secret");
        assert!(!a.encoded_dot_segment);
    }

    #[test]
    fn detects_non_utf8_replacement_char() {
        let path = "/x\u{FFFD}y";
        let a = analyze_request_path(path);
        assert!(a.non_utf8);
    }

    #[test]
    fn detects_decoded_control_char_via_percent() {
        for p in ["/x%00y", "/a%0Ab", "/%7F"] {
            let a = analyze_request_path(p);
            assert!(a.decoded_control_char, "path: {p}");
        }
    }

    #[test]
    fn detects_bare_control_char() {
        let a = analyze_request_path("/x\x01y");
        assert!(a.decoded_control_char);
    }

    #[test]
    fn detects_malformed_percent() {
        for p in ["/x%2", "/a%G1b", "/%"] {
            let a = analyze_request_path(p);
            assert!(a.malformed_percent, "path: {p}");
        }
    }

    #[test]
    fn any_violation_aggregates_all_flags() {
        for p in ["/x%2Fy", "/x%5Cy", "/%2E%2E", "/x\u{FFFD}", "/x%00", "/x%2"] {
            assert!(analyze_request_path(p).any_violation(), "path: {p}");
        }
    }

    #[test]
    fn empty_and_root_are_clean() {
        assert!(!analyze_request_path("").any_violation());
        assert!(!analyze_request_path("/").any_violation());
    }

    #[test]
    fn percent_encoded_safe_chars_are_not_violations() {
        // %20 (space), %41 ('A'), %7E ('~') are valid encoded chars that are
        // not separators, dots, or control chars.
        let a = analyze_request_path("/a%20b%41c%7Ed");
        assert!(!a.any_violation());
    }
}
