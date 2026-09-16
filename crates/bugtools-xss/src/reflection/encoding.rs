//! Reflection encoding: classify how a value was transformed between the
//! request and the response, as reusable, testable transforms.

use serde::{Deserialize, Serialize};

/// A named encoding transform with its decoder, so an encoded reflection can
/// be reversed and verified to round-trip to the submitted value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncodingTransform {
    HtmlEntity,
    UrlPercent,
    Backslash,
    UnicodeEscape,
}

impl EncodingTransform {
    /// The transform's label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::HtmlEntity => "html_entity",
            Self::UrlPercent => "url_percent",
            Self::Backslash => "backslash",
            Self::UnicodeEscape => "unicode_escape",
        }
    }

    /// Decode a fragment produced by this transform. Returns `None` when the
    /// fragment does not appear to be encoded by it.
    pub fn decode(&self, fragment: &str) -> Option<String> {
        match self {
            Self::HtmlEntity => decode_html_entities(fragment),
            Self::UrlPercent => decode_percent(fragment),
            Self::Backslash => decode_backslash(fragment),
            Self::UnicodeEscape => decode_unicode_escapes(fragment),
        }
    }

    /// Whether decoding actually changed the fragment.
    pub fn applies_to(&self, fragment: &str) -> bool {
        match self.decode(fragment) {
            Some(decoded) => decoded != fragment,
            None => false,
        }
    }
}

fn decode_html_entities(fragment: &str) -> Option<String> {
    if !fragment.contains('&') {
        return None;
    }
    let mut out = String::with_capacity(fragment.len());
    let mut rest = fragment;
    let mut changed = false;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos..];
        let (entity, tail) = split_entity(after)?;
        out.push_str(&entity);
        rest = tail;
        changed = true;
    }
    out.push_str(rest);
    if changed {
        Some(out)
    } else {
        None
    }
}

fn split_entity(after: &str) -> Option<(&'static str, &str)> {
    const ENTITIES: &[(&str, &str)] = &[
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&#39;", "'"),
        ("&#x27;", "'"),
        ("&#x2F;", "/"),
    ];
    for (encoded, decoded) in ENTITIES {
        if let Some(tail) = after.strip_prefix(encoded) {
            // SAFETY of transmute-free approach: decoded values are 'static strs.
            return Some((decoded, tail));
        }
    }
    // Unknown entity: pass the '&' through literally.
    Some(("&", &after[1..]))
}

fn decode_percent(fragment: &str) -> Option<String> {
    if !fragment.contains('%') {
        return None;
    }
    let bytes = fragment.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut changed = false;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() + 1 {
            if i + 2 < bytes.len() || i + 2 == bytes.len() {
                if i + 2 < bytes.len() + 1 && i + 2 <= bytes.len() - 1 {
                    let hex = &fragment[i + 1..i + 3];
                    if let Ok(byte) = u8::from_str_radix(hex, 16) {
                        out.push(byte);
                        i += 3;
                        changed = true;
                        continue;
                    }
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    if changed {
        String::from_utf8(out).ok()
    } else {
        // Nothing decoded: return the fragment unchanged so callers can
        // distinguish "not percent-encoded" from "invalid".
        Some(fragment.to_string())
    }
}

fn decode_backslash(fragment: &str) -> Option<String> {
    if !fragment.contains('\\') {
        return None;
    }
    let mut out = String::with_capacity(fragment.len());
    let mut chars = fragment.chars();
    let mut changed = false;
    while let Some(c) = chars.next() {
        if c == '\\' {
            changed = true;
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    if changed {
        Some(out)
    } else {
        None
    }
}

fn decode_unicode_escapes(fragment: &str) -> Option<String> {
    if !fragment.contains("\\u") {
        return None;
    }
    let mut out = String::with_capacity(fragment.len());
    let mut rest = fragment;
    let mut changed = false;
    while let Some(pos) = rest.find("\\u") {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 2..];
        if after.len() >= 4 {
            if let Ok(code) = u32::from_str_radix(&after[..4], 16) {
                if let Some(ch) = char::from_u32(code) {
                    out.push(ch);
                    rest = &after[4..];
                    changed = true;
                    continue;
                }
            }
        }
        // Not a valid escape: emit literally.
        out.push_str("\\u");
        rest = after;
    }
    out.push_str(rest);
    if changed {
        Some(out)
    } else {
        None
    }
}

/// Classify which transform produced an observed fragment, given the
/// submitted value. Returns the transform whose decode matches the
/// submission — evidence-based, not guessed.
pub fn classify_encoding(submitted: &str, observed: &str) -> Option<EncodingTransform> {
    for transform in [
        EncodingTransform::HtmlEntity,
        EncodingTransform::UrlPercent,
        EncodingTransform::Backslash,
        EncodingTransform::UnicodeEscape,
    ] {
        if let Some(decoded) = transform.decode(observed) {
            if decoded == submitted {
                return Some(transform);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_entity_round_trip() {
        assert_eq!(
            EncodingTransform::HtmlEntity.decode("a&lt;b&quot;c"),
            Some("a<b\"c".into())
        );
    }

    #[test]
    fn percent_round_trip() {
        assert_eq!(
            EncodingTransform::UrlPercent.decode("xyzzy%3C42%3E"),
            Some("xyzzy<42>".into())
        );
    }

    #[test]
    fn backslash_round_trip() {
        assert_eq!(
            EncodingTransform::Backslash.decode(r#"a\"b\\c"#),
            Some(r#"a"b\c"#.into())
        );
    }

    #[test]
    fn unicode_escape_round_trip() {
        assert_eq!(
            EncodingTransform::UnicodeEscape.decode("\\u003cscript\\u003e"),
            Some("<script>".into())
        );
    }

    #[test]
    fn classify_from_submitted_and_observed() {
        assert_eq!(
            classify_encoding("a<b", "a&lt;b"),
            Some(EncodingTransform::HtmlEntity)
        );
        assert_eq!(
            classify_encoding("a b", "a%20b"),
            Some(EncodingTransform::UrlPercent)
        );
    }

    #[test]
    fn classify_rejects_non_matching_decode() {
        // The decode does not equal the submission, so no transform is claimed.
        assert_eq!(classify_encoding("different", "a&lt;b"), None);
    }

    #[test]
    fn unknown_entity_passes_through() {
        // &notin; is not in our table; decoding must not corrupt the fragment.
        let decoded = EncodingTransform::HtmlEntity.decode("a&notin;b").unwrap();
        assert!(decoded.contains("notin"));
    }

    #[test]
    fn applies_to_detects_presence() {
        assert!(EncodingTransform::HtmlEntity.applies_to("&lt;"));
        assert!(!EncodingTransform::HtmlEntity.applies_to("plain"));
    }

    #[test]
    fn truncated_percent_is_passed_through() {
        // "%4" alone is not a complete escape.
        let decoded = EncodingTransform::UrlPercent.decode("50%4 off").unwrap();
        assert_eq!(decoded, "50%4 off");
    }
}
