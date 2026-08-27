//! Pure HTTP media-type + `Accept` parsing (RFC 7231 §5.3.2, §3.1.1.1).
//!
//! The low layer for the api-serve content-negotiation / content-type guards:
//! pure `&str → typed value` parsing with no policy decisions and no
//! `api-*` dependency. Guards layer on top (typed value + policy config →
//! accept/reject), so the signatures grow by layer: this file returns typed
//! structures; a guard composes them with its acceptance policy.

/// An RFC 7231 media range from an `Accept` header: `type/subtype` plus an
/// optional q-value and parameters (`;key=value`).
///
/// `type`/`subtype` are lowercased (media types are case-insensitive). A missing
/// q-value defaults to `1.0` per the spec.
#[derive(Debug, Clone, PartialEq)]
pub struct MediaRange {
    /// Lowercased top-level type (e.g. `text`, `application`, or `*`).
    pub type_: String,
    /// Lowercased subtype (e.g. `plain`, `json`, or `*`).
    pub subtype: String,
    /// The q-value (0..=1000 in milli-q); defaults to 1000 (`q=1.0`).
    pub q: u32,
}

/// An RFC 7231 media type from a `Content-Type` header: `type/subtype+suffix`
/// plus parameters, case-normalized (§3.1.1.1: type/subtype are
/// case-insensitive).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaType {
    /// Lowercased top-level type.
    pub type_: String,
    /// Lowercased subtype (without a `+suffix`).
    pub subtype: String,
    /// Structured-syntax suffix without the `+` (e.g. `xml` for `application/rss+xml`),
    /// if present.
    pub suffix: Option<String>,
}

impl MediaRange {
    /// Whether this range matches `type/subtype` per RFC 7231 wildcard rules:
    /// `*/*` matches any; `type/*` matches any subtype of `type`; an exact
    /// `type/subtype` matches only itself. Types/subtypes are case-insensitive.
    #[must_use]
    pub fn matches(&self, type_: &str, subtype: &str) -> bool {
        let t = type_.to_ascii_lowercase();
        let s = subtype.to_ascii_lowercase();
        let type_ok = self.type_ == "*" || self.type_ == t;
        let sub_ok = self.subtype == "*" || self.subtype == s;
        type_ok && sub_ok
    }
}

impl MediaType {
    /// Whether this media type equals `type/subtype` (case-insensitive, ignoring
    /// parameters + suffix).
    #[must_use]
    pub fn is(&self, type_: &str, subtype: &str) -> bool {
        self.type_ == type_.to_ascii_lowercase() && self.subtype == subtype.to_ascii_lowercase()
    }
}

/// Parse an `Accept` header into ordered, q-weighted media ranges.
///
/// Honors q-values (highest first), `*/*` and `type/*` wildcards, and ignores
/// parameters other than `q` for ordering. An empty/whitespace header yields a
/// single `*/*;q=1.0` range (matches anything), matching the "no Accept header =
/// accept anything" convention.
#[must_use]
pub fn parse_accept(header: &str) -> Vec<MediaRange> {
    let trimmed = header.trim();
    if trimmed.is_empty() {
        return vec![MediaRange {
            type_: "*".to_string(),
            subtype: "*".to_string(),
            q: 1000,
        }];
    }
    let mut ranges: Vec<MediaRange> = trimmed.split(',').filter_map(parse_one_range).collect();
    // Stable sort by descending q so a lower-positioned higher-q range wins;
    // ties preserve header order (RFC: the most specific wins among equal q,
    // but specificity is left to the guard — here we only order by q).
    ranges.sort_by(|a, b| b.q.cmp(&a.q));
    ranges
}

/// Parse a single comma-separated `Accept` entry (`text/*;q=0.8;charset=utf-8`).
fn parse_one_range(entry: &str) -> Option<MediaRange> {
    let mut parts = entry.split(';');
    let media = parts.next()?.trim();
    let (type_, subtype) = split_media_pair(media)?;
    let mut q = 1000u32;
    for param in parts {
        let param = param.trim();
        if let Some(val) = param
            .strip_prefix("q=")
            .or_else(|| param.strip_prefix("Q="))
        {
            q = parse_q(val);
        }
    }
    Some(MediaRange {
        type_: type_.to_ascii_lowercase(),
        subtype: subtype.to_ascii_lowercase(),
        q,
    })
}

/// Parse a `type/subtype` token (no params). Returns `None` if malformed.
fn split_media_pair(media: &str) -> Option<(&str, &str)> {
    let (t, s) = media.split_once('/')?;
    let t = t.trim();
    let s = s.trim();
    if t.is_empty() || s.is_empty() {
        return None;
    }
    Some((t, s))
}

/// Parse an RFC 7231 q-value (0..=1, up to 3 decimals) into milli-q (0..=1000).
/// Out-of-range / unparseable values clamp to 0 (the spec treats an invalid q as
/// if `q=0`, i.e. not acceptable).
fn parse_q(val: &str) -> u32 {
    let v = val.trim();
    let f: f64 = v.parse().unwrap_or(0.0);
    let milli = (f.clamp(0.0, 1.0) * 1000.0).round() as u32;
    milli.min(1000)
}

/// Parse a `Content-Type` value into a typed [`MediaType`] (case-normalized
/// type/subtype, `+suffix` separated, parameters ignored). Returns `None` for a
/// malformed value.
#[must_use]
pub fn parse_media_type(content_type: &str) -> Option<MediaType> {
    // Split off parameters (`;charset=...`); the first token is the media type.
    let media = content_type.split(';').next()?.trim();
    let (type_, rhs) = split_media_pair(media)?;
    // A structured-syntax suffix (`+xml`, `+json`) splits off the subtype.
    let (subtype, suffix) = match rhs.split_once('+') {
        Some((sub, suf)) => (sub, Some(suf.to_ascii_lowercase())),
        None => (rhs, None),
    };
    Some(MediaType {
        type_: type_.to_ascii_lowercase(),
        subtype: subtype.to_ascii_lowercase(),
        suffix,
    })
}

/// Return a conventional filename extension for a media type.
///
/// This is intentionally generic and conservative: unknown or malformed media
/// types return `bin`. Domain-specific storage policy should layer on top.
#[must_use]
pub fn default_extension_for_media_type(content_type: &str) -> &'static str {
    let Some(media) = parse_media_type(content_type) else {
        return "bin";
    };
    match (
        media.type_.as_str(),
        media.subtype.as_str(),
        media.suffix.as_deref(),
    ) {
        ("application", "pdf", _) => "pdf",
        ("text", "html", _) => "html",
        ("text", "plain", _) => "txt",
        ("image", "svg", Some("xml")) => "svg",
        ("application", "xml", _) | ("text", "xml", _) | (_, _, Some("xml")) => "xml",
        ("application", "json", _) | (_, _, Some("json")) => "json",
        ("application", "epub", Some("zip")) => "epub",
        ("application", "msword", _) => "doc",
        ("application", "vnd.openxmlformats-officedocument.wordprocessingml.document", _) => "docx",
        ("application", "vnd.ms-excel", _) => "xls",
        ("application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet", _) => "xlsx",
        ("application", "vnd.ms-powerpoint", _) => "ppt",
        ("application", "vnd.openxmlformats-officedocument.presentationml.presentation", _) => {
            "pptx"
        },
        ("application", "zip", _) => "zip",
        ("application", "x-gzip", _) => "gz",
        ("application", "x-tar", _) => "tar",
        ("image", "jpeg", _) => "jpg",
        ("image", "png", _) => "png",
        ("image", "gif", _) => "gif",
        ("image", "tiff", _) => "tiff",
        ("image", "webp", _) => "webp",
        ("audio", "mpeg", _) => "mp3",
        ("audio", "ogg", _) => "ogg",
        ("video", "mp4", _) => "mp4",
        ("video", "webm", _) => "webm",
        ("application", "rtf", _) => "rtf",
        ("application", "postscript", _) => "ps",
        ("application", "x-bibtex", _) => "bib",
        ("application", "x-research-info-systems", _) => "ris",
        _ => "bin",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accept_empty_is_wildcard() {
        let r = parse_accept("");
        assert_eq!(r.len(), 1);
        assert!(r[0].matches("application", "json"));
    }

    #[test]
    fn parse_accept_orders_by_q_value() {
        // `text/plain;q=0.5, application/json;q=0.9` → json first.
        let r = parse_accept("text/plain;q=0.5, application/json;q=0.9");
        assert_eq!(r[0].subtype, "json");
        assert_eq!(r[0].q, 900);
        assert_eq!(r[1].subtype, "plain");
        assert_eq!(r[1].q, 500);
    }

    #[test]
    fn parse_accept_wildcard_matching() {
        let r = parse_accept("text/*, application/json");
        // `text/*` matches any text subtype; `application/json` is exact.
        assert!(r[0].matches("text", "plain"));
        assert!(!r[0].matches("application", "json"));
        assert!(r[1].matches("application", "json"));
    }

    #[test]
    fn parse_accept_default_q_is_one() {
        let r = parse_accept("application/json");
        assert_eq!(r[0].q, 1000);
    }

    #[test]
    fn parse_accept_ignores_non_q_params() {
        let r = parse_accept("application/json; charset=utf-8; q=0.1");
        assert_eq!(r[0].q, 100);
        assert!(r[0].matches("application", "json"));
    }

    #[test]
    fn parse_media_type_case_insensitive() {
        let mt = parse_media_type("APPLICATION/JSON").unwrap();
        assert!(mt.is("application", "json"));
        assert_eq!(mt.type_, "application");
        assert_eq!(mt.subtype, "json");
    }

    #[test]
    fn parse_media_type_strips_params_and_suffix() {
        let mt = parse_media_type("application/rss+xml; charset=utf-8").unwrap();
        assert_eq!(mt.subtype, "rss");
        assert_eq!(mt.suffix.as_deref(), Some("xml"));
    }

    #[test]
    fn parse_media_type_rejects_malformed() {
        assert!(parse_media_type("notamediatype").is_none());
        assert!(parse_media_type("/json").is_none());
        assert!(parse_media_type("text/").is_none());
    }

    #[test]
    fn default_extension_for_media_type_is_conservative() {
        assert_eq!(default_extension_for_media_type("application/pdf"), "pdf");
        assert_eq!(
            default_extension_for_media_type("application/epub+zip"),
            "epub"
        );
        assert_eq!(
            default_extension_for_media_type("image/svg+xml; charset=utf-8"),
            "svg"
        );
        assert_eq!(default_extension_for_media_type("unknown"), "bin");
    }
}
