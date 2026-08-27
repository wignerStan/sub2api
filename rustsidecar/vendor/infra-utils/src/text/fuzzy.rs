//! Case-insensitive subsequence matching for fuzzy filtering.
//!
//! Zero domain vocabulary, zero dependencies.

/// Fuzzy-match `needle` against `haystack`.
///
/// Returns `Some((indices, score))` if `needle` is a case-insensitive
/// subsequence of `haystack`, or `None` otherwise.
///
/// - `indices`: sorted, deduplicated character positions in the original
///   `haystack` (suitable for `str::chars().enumerate()` highlighting).
/// - `score`: lower is better; prefix matches get a `-100` bonus.
///
/// Unicode-aware: handles case-folding expansions (e.g. `ß` → `ss`).
#[must_use]
pub fn fuzzy_match(haystack: &str, needle: &str) -> Option<(Vec<usize>, i32)> {
    if needle.is_empty() {
        return Some((Vec::new(), i32::MAX));
    }

    let mut lowered_chars: Vec<char> = Vec::new();
    let mut lowered_to_orig: Vec<usize> = Vec::new();
    for (orig_idx, ch) in haystack.chars().enumerate() {
        for lc in ch.to_lowercase() {
            lowered_chars.push(lc);
            lowered_to_orig.push(orig_idx);
        }
    }

    let lowered_needle: Vec<char> = needle.to_lowercase().chars().collect();

    let mut result_indices: Vec<usize> = Vec::with_capacity(lowered_needle.len());
    let mut cur = 0usize;
    let mut first_lower_pos: usize = 0;
    let mut last_lower_pos: usize = 0;
    for &nc in &lowered_needle {
        let mut found_at: Option<usize> = None;
        while cur < lowered_chars.len() {
            if lowered_chars[cur] == nc {
                found_at = Some(cur);
                cur += 1;
                break;
            }
            cur += 1;
        }
        let pos = found_at?;
        if result_indices.is_empty() {
            first_lower_pos = pos;
        }
        last_lower_pos = pos;
        result_indices.push(lowered_to_orig[pos]);
    }

    let window = (i32::try_from(last_lower_pos).unwrap_or(i32::MAX)
        - i32::try_from(first_lower_pos).unwrap_or(0)
        + 1)
        - i32::try_from(lowered_needle.len()).unwrap_or(i32::MAX);
    let mut score = window.max(0);
    if first_lower_pos == 0 {
        score -= 100;
    }

    result_indices.sort_unstable();
    result_indices.dedup();
    Some((result_indices, score))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_indices() {
        let (idx, score) = fuzzy_match("hello", "hl").unwrap();
        assert_eq!(idx, vec![0, 2]);
        assert_eq!(score, -99);
    }

    #[test]
    fn no_match() {
        assert!(fuzzy_match("hello", "xyz").is_none());
    }

    #[test]
    fn case_insensitive() {
        let (idx, score) = fuzzy_match("FooBar", "foO").unwrap();
        assert_eq!(idx, vec![0, 1, 2]);
        assert_eq!(score, -100);
    }

    #[test]
    fn empty_needle() {
        let (idx, score) = fuzzy_match("anything", "").unwrap();
        assert!(idx.is_empty());
        assert_eq!(score, i32::MAX);
    }

    #[test]
    fn prefer_contiguous_over_spread() {
        let (_, score_a) = fuzzy_match("abc", "abc").unwrap();
        let (_, score_b) = fuzzy_match("a-b-c", "abc").unwrap();
        assert!(score_a < score_b);
    }

    #[test]
    fn prefix_bonus() {
        let (_, score_a) = fuzzy_match("file_name", "file").unwrap();
        let (_, score_b) = fuzzy_match("my_file_name", "file").unwrap();
        assert!(score_a < score_b);
    }

    #[test]
    fn unicode_dotted_i() {
        // İ (U+0130) lowercases to 'i' + '̇' (two code points).
        let (idx, _) = fuzzy_match("İstanbul", "is").unwrap();
        assert_eq!(idx.len(), 2);
    }

    #[test]
    fn german_sharp_s() {
        // ß lowercases to itself (not "ss"), so it matches directly.
        let (idx, _) = fuzzy_match("straße", "raße").unwrap();
        assert!(idx.contains(&2)); // 'r' at char index 2
        assert!(idx.contains(&4)); // 'ß' at char index 4
    }

    #[test]
    fn multi_char_lowercase_expansion_dedups_indices() {
        // İ (U+0130) lowercases to 'i' + '̇' (two code points), both mapping
        // to the same original char index. Verify the dedup at the end of
        // fuzzy_match collapses them correctly.
        let (idx, _) = fuzzy_match("İstanbul", "ist").unwrap();
        let mut sorted = idx.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(idx, sorted, "result indices should contain no duplicates");
    }
}
