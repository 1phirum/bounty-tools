//! Path heuristic extractor: path-shaped runs of text anywhere in a document.
//!
//! The weakest, highest-recall net — it finds routes that never appear in a
//! parsed tag or a recognised call (e.g. a path assembled from a config blob).
//! Because it guesses, it is deliberately conservative: a leading slash, a
//! plausible segment structure, and a rejection list for dates/versions keep
//! prose and arithmetic out.

use crate::models::{EndpointExtractor, ExtractorKind, RawEndpoint};

/// Extracts path-like strings from arbitrary text.
pub struct PathHeuristicExtractor;

impl EndpointExtractor for PathHeuristicExtractor {
    fn name(&self) -> &'static str {
        "path-heuristic"
    }

    fn kind(&self) -> ExtractorKind {
        ExtractorKind::PathHeuristic
    }

    fn extract(&self, content: &str) -> Vec<RawEndpoint> {
        let mut seen = Vec::new();
        let bytes = content.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'/' && !preceded_by_scheme(bytes, i) && !is_tag_close(bytes, i) {
                let start = i;
                let mut j = i + 1;
                while j < bytes.len() && is_path_byte(bytes[j]) {
                    j += 1;
                }
                let candidate = &content[start..j];
                if is_plausible_path(candidate) && !seen.iter().any(|s| s == candidate) {
                    seen.push(candidate.to_string());
                }
                i = j.max(i + 1);
            } else {
                i += 1;
            }
        }
        seen.into_iter()
            .map(|p| RawEndpoint::new(p, ExtractorKind::PathHeuristic))
            .collect()
    }
}

fn is_path_byte(b: u8) -> bool {
    let c = b as char;
    c.is_ascii_alphanumeric()
        || matches!(c, '/' | '_' | '-' | '.' | '?' | '=' | '&' | '%' | '~' | '+' | ':' | '@')
}

/// Skip the `//` in `https://host` so we don't emit `//host/...` as a path;
/// the JS/HTML extractors already capture absolute URLs precisely.
fn preceded_by_scheme(bytes: &[u8], i: usize) -> bool {
    i > 0 && bytes[i - 1] == b'/' || (i + 1 < bytes.len() && bytes[i + 1] == b'/')
}

/// A `/` right after `<` opens an HTML closing tag (`</form>`, `</script>`),
/// not a path. The HTML extractor already reads the real references from tags,
/// so treating tag names as routes would be a pure false positive.
fn is_tag_close(bytes: &[u8], i: usize) -> bool {
    i > 0 && bytes[i - 1] == b'<'
}

fn is_plausible_path(candidate: &str) -> bool {
    let trimmed = candidate.trim_end_matches('/');
    if trimmed.len() < 3 {
        return false;
    }
    let path_only = trimmed.split(['?', '#']).next().unwrap_or(trimmed);
    let segments: Vec<&str> = path_only.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return false;
    }
    // A single purely-numeric segment ("/2026") is a date/number, not a route.
    if segments.len() == 1 && segments[0].chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    // A single segment that is a dotted version ("/1.2.3") is not a route.
    if segments.len() == 1
        && segments[0]
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.')
        && segments[0].contains('.')
    {
        return false;
    }
    // Require at least one segment carrying a letter, so "/12/34" is rejected
    // but "/v1/34" is kept.
    segments.iter().any(|s| s.chars().any(|c| c.is_ascii_alphabetic()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(text: &str) -> Vec<String> {
        PathHeuristicExtractor.extract(text).into_iter().map(|r| r.raw).collect()
    }

    #[test]
    fn finds_api_paths_in_free_text() {
        let p = paths(r#"the route is /api/v1/users and also /account/settings"#);
        assert!(p.contains(&"/api/v1/users".to_string()));
        assert!(p.contains(&"/account/settings".to_string()));
    }

    #[test]
    fn rejects_dates_versions_and_numeric_paths() {
        assert!(paths("year /2026 end").is_empty());
        assert!(paths("version /1.2.3 shipped").is_empty());
        assert!(paths("ratio /12/34 here").is_empty());
    }

    #[test]
    fn does_not_emit_scheme_slashes() {
        let p = paths("visit https://host.test/api/x now");
        assert!(!p.iter().any(|s| s.starts_with("//")));
        assert!(p.iter().any(|s| s == "/api/x"));
    }

    #[test]
    fn dedupes() {
        assert_eq!(paths("/api/x and /api/x").len(), 1);
    }

    #[test]
    fn ignores_html_closing_tags() {
        // </form> and </script> must not surface as /form and /script.
        let p = paths(r#"<form action="/api/login"></form><script>x</script>"#);
        assert!(!p.iter().any(|s| s == "/form" || s == "/script"));
        assert!(p.iter().any(|s| s == "/api/login"));
    }
}
