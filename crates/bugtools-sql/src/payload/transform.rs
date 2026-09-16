//! Representation transformation pipeline (brief P0 §19).
//!
//! A logical test is rendered to SQL, wrapped in a boundary, then may pass
//! through a chain of *representation* transforms before HTTP serialization.
//! Every transformation is recorded so a result is reproducible: a reviewer
//! can replay the exact final string.

use serde::{Deserialize, Serialize};

/// A single representation transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransformKind {
    /// Percent-encode characters that are unsafe in a URL query.
    UrlEncode,
    /// Encode a space as `/**/` (a comment acting as whitespace).
    CommentSpace,
    /// Encode a space as `+` (form encoding).
    PlusSpace,
    /// Replace spaces with tab characters.
    TabSpace,
    /// Replace spaces with newline characters.
    NewlineSpace,
    /// Randomise the case of SQL keywords (`select` -> `SeLeCt`).
    KeywordCase,
    /// Encode selected characters as `%XX` (partial URL encoding).
    PartialUrlEncode,
    /// Wrap the value in HTML-entity-style escapes for JSON/HTML sinks.
    HtmlEntityEncode,
    /// Encode as JSON string content (escape quotes/backslashes).
    JsonEscape,
    /// Double the percent signs so an upstream decoder reveals `%XX`.
    DoubleUrlEncode,
    /// Encode as Unicode escape sequences (`\u00XX`).
    UnicodeEscape,
}

impl TransformKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::UrlEncode => "url_encode",
            Self::CommentSpace => "comment_space",
            Self::PlusSpace => "plus_space",
            Self::TabSpace => "tab_space",
            Self::NewlineSpace => "newline_space",
            Self::KeywordCase => "keyword_case",
            Self::PartialUrlEncode => "partial_url_encode",
            Self::HtmlEntityEncode => "html_entity_encode",
            Self::JsonEscape => "json_escape",
            Self::DoubleUrlEncode => "double_url_encode",
            Self::UnicodeEscape => "unicode_escape",
        }
    }
}

/// Where a transform is appropriate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepresentationContext {
    /// A URL query parameter value.
    QueryValue,
    /// A form-urlencoded body field.
    FormValue,
    /// A JSON body string value.
    JsonString,
    /// An HTTP header value.
    HeaderValue,
    /// A cookie value.
    CookieValue,
    /// A path segment.
    PathSegment,
}

/// A recorded transformation step, so the final string is explainable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformationTrace {
    pub original: String,
    pub steps: Vec<TransformKind>,
    pub final_representation: String,
}

impl TransformationTrace {
    pub fn new(original: impl Into<String>) -> Self {
        let original = original.into();
        Self {
            final_representation: original.clone(),
            original,
            steps: Vec::new(),
        }
    }

    /// Apply a transform, recording it.
    pub fn apply(mut self, kind: TransformKind) -> Self {
        self.final_representation = apply_transform(&self.final_representation, kind);
        self.steps.push(kind);
        self
    }

    /// Human summary like `url_encode+keyword_case`.
    pub fn summary(&self) -> String {
        if self.steps.is_empty() {
            "identity".to_string()
        } else {
            self.steps
                .iter()
                .map(|s| s.label())
                .collect::<Vec<_>>()
                .join("+")
        }
    }
}

/// SQL keywords whose case may be randomised without changing semantics.
const SQL_KEYWORDS: &[&str] = &[
    "SELECT", "UNION", "WHERE", "AND", "OR", "FROM", "NULL", "SLEEP", "PG_SLEEP",
    "WAITFOR", "DELAY", "CASE", "WHEN", "THEN", "ELSE", "END", "ORDER", "BY", "GROUP",
    "HAVING", "LIMIT", "OFFSET", "INTO", "VALUES",
];

/// Apply one transform to a string.
pub fn apply_transform(input: &str, kind: TransformKind) -> String {
    match kind {
        TransformKind::UrlEncode => percent_encode(input, false),
        TransformKind::DoubleUrlEncode => percent_encode(&percent_encode(input, true), true),
        TransformKind::PartialUrlEncode => {
            // Encode only quote/space/semicolon — the characters filters
            // most often look for, without encoding the whole payload.
            percent_encode_selected(input, " '\";=")
        }
        TransformKind::CommentSpace => input.replace(' ', "/**/"),
        TransformKind::PlusSpace => input.replace(' ', "+"),
        TransformKind::TabSpace => input.replace(' ', "\t"),
        TransformKind::NewlineSpace => input.replace(' ', "\n"),
        TransformKind::KeywordCase => {
            let mut out = input.to_string();
            for kw in SQL_KEYWORDS {
                out = replace_case_insensitive(&out, kw, &mixed_case(kw));
            }
            out
        }
        TransformKind::HtmlEntityEncode => input
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('\'', "&#39;")
            .replace('"', "&quot;"),
        TransformKind::JsonEscape => input.replace('\\', "\\\\").replace('"', "\\\""),
        TransformKind::UnicodeEscape => input
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == ' ' {
                    c.to_string()
                } else {
                    format!("\\u{:04X}", c as u32)
                }
            })
            .collect(),
    }
}

fn percent_encode(input: &str, encode_all_unsafe: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        let safe = byte.is_ascii_alphanumeric()
            || byte == b'-'
            || byte == b'_'
            || byte == b'.'
            || byte == b'~'
            || (!encode_all_unsafe && byte == b'*');
        if safe {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn percent_encode_selected(input: &str, chars: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if chars.contains(ch) {
            for byte in ch.to_string().bytes() {
                out.push_str(&format!("%{byte:02X}"));
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// `select` -> `SeLeCt` (deterministic so tests are stable).
fn mixed_case(keyword: &str) -> String {
    keyword
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

fn replace_case_insensitive(haystack: &str, needle: &str, replacement: &str) -> String {
    let mut result = String::with_capacity(haystack.len());
    let lower_hay = haystack.to_lowercase();
    let lower_needle = needle.to_lowercase();
    let mut i = 0;
    while i < haystack.len() {
        if lower_hay[i..].starts_with(&lower_needle) {
            result.push_str(replacement);
            i += needle.len();
        } else {
            // Advance one UTF-8 char boundary.
            let ch = haystack[i..].chars().next().unwrap();
            result.push(ch);
            i += ch.len_utf8();
        }
    }
    result
}

/// The representation variants appropriate for a location.
///
/// These are *representation* choices, not evasion recipes: each changes
/// only how the same logical test is serialized, so the engine can tell
/// whether a difference came from the application or from an intermediary
/// decoder.
pub fn variants_for(context: RepresentationContext) -> Vec<Vec<TransformKind>> {
    match context {
        RepresentationContext::QueryValue => vec![
            vec![],
            vec![TransformKind::UrlEncode],
            vec![TransformKind::CommentSpace],
            vec![TransformKind::PlusSpace],
            vec![TransformKind::KeywordCase],
            vec![TransformKind::PartialUrlEncode],
            vec![TransformKind::DoubleUrlEncode],
            vec![TransformKind::TabSpace],
        ],
        RepresentationContext::FormValue => vec![
            vec![],
            vec![TransformKind::PlusSpace],
            vec![TransformKind::UrlEncode],
            vec![TransformKind::CommentSpace],
        ],
        RepresentationContext::JsonString => vec![
            vec![],
            vec![TransformKind::JsonEscape],
            vec![TransformKind::UnicodeEscape],
            vec![TransformKind::CommentSpace],
        ],
        RepresentationContext::HeaderValue => vec![
            vec![],
            vec![TransformKind::TabSpace],
            vec![TransformKind::UrlEncode],
        ],
        RepresentationContext::CookieValue => vec![
            vec![],
            vec![TransformKind::UrlEncode],
            vec![TransformKind::CommentSpace],
        ],
        RepresentationContext::PathSegment => vec![
            vec![],
            vec![TransformKind::UrlEncode],
            vec![TransformKind::DoubleUrlEncode],
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encode_escapes_quotes_and_spaces() {
        let out = apply_transform("' OR 1=1--", TransformKind::UrlEncode);
        assert!(out.contains("%27"), "quote not encoded: {out}");
        assert!(out.contains("%20"), "space not encoded: {out}");
    }

    #[test]
    fn comment_space_replaces_spaces() {
        assert_eq!(apply_transform("AND 1=1", TransformKind::CommentSpace), "AND/**/1=1");
    }

    #[test]
    fn plus_space_replaces_spaces() {
        assert_eq!(apply_transform("AND 1=1", TransformKind::PlusSpace), "AND+1=1");
    }

    #[test]
    fn keyword_case_changes_sql_keywords() {
        let out = apply_transform("select 1 union select 2", TransformKind::KeywordCase);
        assert_ne!(out, "select 1 union select 2");
        assert!(out.to_lowercase().contains("select"));
    }

    #[test]
    fn double_url_encode_is_reversible_by_one_decode() {
        let once = apply_transform("'", TransformKind::UrlEncode);
        let twice = apply_transform("'", TransformKind::DoubleUrlEncode);
        assert!(twice.contains("%25"), "double encode should encode the percent: {twice}");
        assert_ne!(once, twice);
    }

    #[test]
    fn json_escape_escapes_quotes_and_backslashes() {
        let out = apply_transform("a\"b\\c", TransformKind::JsonEscape);
        assert_eq!(out, "a\\\"b\\\\c");
    }

    #[test]
    fn html_entity_encodes_angle_brackets() {
        let out = apply_transform("<script>", TransformKind::HtmlEntityEncode);
        assert!(!out.contains('<'));
        assert!(out.contains("&lt;"));
    }

    #[test]
    fn unicode_escape_encodes_specials() {
        let out = apply_transform("'", TransformKind::UnicodeEscape);
        assert_eq!(out, "\\u0027");
    }

    #[test]
    fn trace_records_every_step() {
        let trace = TransformationTrace::new("' OR 1=1")
            .apply(TransformKind::CommentSpace)
            .apply(TransformKind::UrlEncode);
        assert_eq!(trace.steps.len(), 2);
        assert_eq!(trace.summary(), "comment_space+url_encode");
        assert_ne!(trace.final_representation, trace.original);
    }

    #[test]
    fn identity_trace_summary() {
        assert_eq!(TransformationTrace::new("x").summary(), "identity");
    }

    #[test]
    fn every_context_offers_an_identity_variant() {
        for ctx in [
            RepresentationContext::QueryValue,
            RepresentationContext::FormValue,
            RepresentationContext::JsonString,
            RepresentationContext::HeaderValue,
            RepresentationContext::CookieValue,
            RepresentationContext::PathSegment,
        ] {
            let variants = variants_for(ctx);
            assert!(variants.iter().any(|v| v.is_empty()), "{ctx:?} had no identity variant");
        }
    }

    #[test]
    fn query_context_offers_multiple_variants() {
        assert!(variants_for(RepresentationContext::QueryValue).len() >= 4);
    }

    #[test]
    fn keyword_case_is_deterministic() {
        let a = apply_transform("select", TransformKind::KeywordCase);
        let b = apply_transform("select", TransformKind::KeywordCase);
        assert_eq!(a, b);
    }
}
