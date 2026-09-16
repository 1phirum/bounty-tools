//! Reflection detection: find where a submitted value appears in a response.
//!
//! Detects exact, encoded, partial, and multiple reflection points, and
//! reports each with its byte offset so downstream parsing can resolve the
//! HTML/JS context precisely.

use super::normalizer::normalize_for_comparison;
use serde::{Deserialize, Serialize};

/// A single reflection point with a resolved context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflectionPoint {
    /// Response byte offset where the reflected value starts.
    pub offset: usize,
    /// How many bytes the reflected value occupies.
    pub length: usize,
    /// What form the reflection took.
    pub encoding: ReflectionForm,
    /// The exact bytes as they appear in the response.
    pub observed: String,
}

impl ReflectionPoint {
    /// End offset (exclusive).
    pub fn end(&self) -> usize {
        self.offset + self.length
    }
}

/// How the input appeared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReflectionForm {
    /// Bytes appeared unchanged.
    Exact,
    /// HTML entities were applied (e.g. `<` became `&lt;`).
    HtmlEncoded,
    /// Percent-encoding was applied.
    UrlEncoded,
    /// A backslash escape was added.
    BackslashEscaped,
    /// Only part of the input survived.
    Partial,
    /// The value was normalized (case, whitespace, unicode).
    Normalized,
    /// Nothing recognizable appeared.
    Absent,
}

impl ReflectionForm {
    /// Whether the reflection preserves the raw bytes.
    pub fn is_exact(&self) -> bool {
        matches!(self, Self::Exact)
    }

    /// Whether the reflection was transformed in any way.
    pub fn is_transformed(&self) -> bool {
        !matches!(self, Self::Exact | Self::Absent)
    }
}

/// Configuration for a detection run.
#[derive(Debug, Clone)]
pub struct DetectionConfig {
    /// The value that was submitted, exactly as sent.
    pub submitted: String,
    /// The parameter name it was sent under.
    pub parameter: String,
    /// Maximum reflection points to report before stopping.
    pub max_points: usize,
}

impl DetectionConfig {
    pub fn new(parameter: impl Into<String>, submitted: impl Into<String>) -> Self {
        Self {
            submitted: submitted.into(),
            parameter: parameter.into(),
            max_points: 10,
        }
    }

    pub fn with_max_points(mut self, max: usize) -> Self {
        self.max_points = max;
        self
    }
}

/// Detect every reflection point for a submitted value in a response body.
///
/// The engine tries, in order: the exact bytes, common encodings of the
/// value, and finally partial matches on distinctive fragments. Every hit
/// carries its offset so `parser::html::parse_at` can resolve the node.
pub fn detect_reflections(body: &str, config: &DetectionConfig) -> Vec<ReflectionPoint> {
    let mut points = Vec::new();

    // 1. Exact bytes.
    for offset in find_all(body, &config.submitted) {
        if points.len() >= config.max_points {
            break;
        }
        points.push(ReflectionPoint {
            offset,
            length: config.submitted.len(),
            encoding: ReflectionForm::Exact,
            observed: config.submitted.clone(),
        });
    }

    // 2. Encoded variants, in decreasing likelihood.
    if points.len() < config.max_points {
        let variants: &[(&str, ReflectionForm)] = &[
            (&html_encode(&config.submitted), ReflectionForm::HtmlEncoded),
            (&url_encode(&config.submitted), ReflectionForm::UrlEncoded),
        ];
        for (encoded, form) in variants {
            if encoded == &config.submitted {
                continue; // encoding was a no-op
            }
            for offset in find_all(body, encoded) {
                if points.len() >= config.max_points {
                    break;
                }
                points.push(ReflectionPoint {
                    offset,
                    length: encoded.len(),
                    encoding: *form,
                    observed: encoded.to_string(),
                });
            }
        }
    }

    // 3. Partial: use the longest distinctive fragment if the whole value
    //    never appeared. This catches truncation and filtering.
    if points.is_empty() {
        if let Some((fragment, raw_len)) = distinctive_fragment(&config.submitted) {
            for offset in find_all(body, &fragment) {
                if points.len() >= config.max_points {
                    break;
                }
                points.push(ReflectionPoint {
                    offset,
                    length: raw_len,
                    encoding: ReflectionForm::Partial,
                    observed: fragment.clone(),
                });
            }
        }
    }

    // 4. Normalized: whitespace-collapsed, case-insensitive match.
    if points.is_empty() {
        let norm = normalize_for_comparison(&config.submitted);
        if !norm.is_empty() && norm != config.submitted {
            for offset in find_normalized(body, &norm) {
                if points.len() >= config.max_points {
                    break;
                }
                let raw_len = approximate_raw_length(body, offset, &norm);
                points.push(ReflectionPoint {
                    offset,
                    length: raw_len,
                    encoding: ReflectionForm::Normalized,
                    observed: body[offset..offset + raw_len.min(body.len() - offset)].to_string(),
                });
            }
        }
    }

    points.sort_by_key(|p| p.offset);
    points
}

fn find_all(haystack: &str, needle: &str) -> Vec<usize> {
    if needle.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = haystack[from..].find(needle) {
        out.push(from + pos);
        from += pos + needle.len();
    }
    out
}

fn html_encode(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// The longest fragment unlikely to be filtered or generic (used for partial
/// matching). Returns (fragment, approximate raw length in the response).
fn distinctive_fragment(value: &str) -> Option<(String, usize)> {
    // Prefer an alphanumeric token of decent length.
    let tokens: Vec<&str> = value
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.len() >= 4)
        .collect();
    tokens
        .iter()
        .max_by_key(|t| t.len())
        .map(|t| ((*t).to_string(), t.len()))
}

fn find_normalized(body: &str, normalized_needle: &str) -> Vec<usize> {
    if normalized_needle.is_empty() {
        return Vec::new();
    }
    let body_norm = normalize_for_comparison(body);
    // Normalization may change offsets; do a simple scan on the normalized
    // body and map back approximately. For simplicity we search the raw body
    // case-insensitively when the normalized form is only case-folded.
    if body_norm.len() == body.len() {
        let lower_body = body.to_lowercase();
        let lower_needle = normalized_needle.to_lowercase();
        find_all(&lower_body, &lower_needle)
    } else {
        // Whitespace was collapsed; offsets no longer map 1:1. Skip rather
        // than report an offset that does not point at the real bytes.
        Vec::new()
    }
}

fn approximate_raw_length(body: &str, offset: usize, _normalized: &str) -> usize {
    // For a normalized (case-only) match the raw length equals the needle.
    let remaining = body.len() - offset;
    _normalized.len().min(remaining)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(body: &str, value: &str) -> Vec<ReflectionPoint> {
        detect_reflections(body, &DetectionConfig::new("q", value))
    }

    #[test]
    fn exact_reflection_found_with_offset() {
        let points = detect("<p>hello xyzzy42 bye</p>", "xyzzy42");
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].offset, body_offset("<p>hello xyzzy42 bye</p>", "xyzzy42"));
        assert_eq!(points[0].encoding, ReflectionForm::Exact);
        assert!(points[0].encoding.is_exact());
    }

    #[test]
    fn multiple_reflection_points_all_reported() {
        let body = "a xyzzy42 b xyzzy42 c xyzzy42";
        let points = detect(body, "xyzzy42");
        assert_eq!(points.len(), 3);
        // Sorted by offset.
        assert!(points[0].offset < points[1].offset);
        assert!(points[1].offset < points[2].offset);
    }

    #[test]
    fn html_encoded_reflection_detected() {
        let body = r#"<div title="xyzzy&lt;42&gt;"></div>"#;
        let points = detect(body, "xyzzy<42>");
        assert!(!points.is_empty());
        assert!(points.iter().any(|p| p.encoding == ReflectionForm::HtmlEncoded));
    }

    #[test]
    fn url_encoded_reflection_detected() {
        let body = "value=xyzzy%3C42%3E end";
        let points = detect(body, "xyzzy<42>");
        assert!(points.iter().any(|p| p.encoding == ReflectionForm::UrlEncoded));
    }

    #[test]
    fn partial_reflection_via_distinctive_fragment() {
        // The <script> part was stripped; only the token survived.
        let body = "error near xyzzytoken end";
        let points = detect(body, "xyzzytoken<script>");
        assert!(!points.is_empty());
        assert!(points.iter().any(|p| p.encoding == ReflectionForm::Partial));
    }

    #[test]
    fn no_reflection_yields_empty_not_a_guess() {
        let points = detect("<p>nothing here</p>", "xyzzy42");
        assert!(points.is_empty(), "absence must be absence, not a weak match");
    }

    #[test]
    fn max_points_caps_detection() {
        let body = "x ".repeat(50) + &"xyzzy42 ".repeat(20);
        let points = detect_reflections(
            &body,
            &DetectionConfig::new("q", "xyzzy42").with_max_points(5),
        );
        assert_eq!(points.len(), 5);
    }

    #[test]
    fn encoded_variants_skip_noop_encodings() {
        // A purely alphanumeric value encodes to itself; must not double count.
        let points = detect("abc xyzzy42", "xyzzy42");
        let exact = points.iter().filter(|p| p.encoding == ReflectionForm::Exact).count();
        assert_eq!(exact, 1, "same bytes must not be reported under two forms");
    }

    #[test]
    fn end_offset_is_exclusive() {
        let points = detect("<p>xyzzy42</p>", "xyzzy42");
        let p = &points[0];
        assert_eq!(&"<p>xyzzy42</p>"[p.offset..p.end()], "xyzzy42");
    }

    fn body_offset(body: &str, needle: &str) -> usize {
        body.find(needle).unwrap()
    }
}
