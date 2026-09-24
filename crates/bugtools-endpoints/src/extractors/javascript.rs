//! JavaScript extractor: request calls and URL-shaped string literals.
//!
//! Regex-based, no execution. It recognises the shapes that name a real
//! request — `fetch(...)`, `axios.get(...)`, `XMLHttpRequest.open(...)` — and
//! also sweeps for bare URL/path string literals as a lower-confidence net.
//! Runs over any text, so it sees both inline `<script>` blocks and bundled
//! `.js` files.

use regex::Regex;

use crate::models::{EndpointExtractor, ExtractorKind, MethodHint, RawEndpoint};

/// Extracts endpoints from JavaScript source (inline or standalone).
pub struct JavaScriptExtractor;

impl EndpointExtractor for JavaScriptExtractor {
    fn name(&self) -> &'static str {
        "javascript"
    }

    fn kind(&self) -> ExtractorKind {
        ExtractorKind::JsFetch
    }

    fn extract(&self, content: &str) -> Vec<RawEndpoint> {
        let mut out = Vec::new();

        // fetch("/x") / fetch(`/x`) — HTTP default method is GET.
        if let Ok(re) = Regex::new(r#"fetch\s*\(\s*['"`]([^'"`]+)['"`]"#) {
            for c in re.captures_iter(content) {
                out.push(
                    RawEndpoint::new(c[1].to_string(), ExtractorKind::JsFetch)
                        .with_method(MethodHint::Get),
                );
            }
        }

        // axios.get("/x"), axios.post("/x"), … — method is explicit.
        if let Ok(re) =
            Regex::new(r#"axios\.(get|post|put|patch|delete|head|options)\s*\(\s*['"`]([^'"`]+)['"`]"#)
        {
            for c in re.captures_iter(content) {
                out.push(
                    RawEndpoint::new(c[2].to_string(), ExtractorKind::JsAxios)
                        .with_method(MethodHint::parse(&c[1])),
                );
            }
        }

        // axios({ url: "/x", method: "post" }) — url required, method optional.
        if let Ok(re) = Regex::new(r#"url\s*:\s*['"`]([^'"`]+)['"`]"#) {
            for c in re.captures_iter(content) {
                // Look for a nearby `method:` in the same object literal.
                let start = c.get(0).map(|m| m.start()).unwrap_or(0);
                let window = &content[start.saturating_sub(80)..(start + 80).min(content.len())];
                let method = Regex::new(r#"method\s*:\s*['"`](\w+)['"`]"#)
                    .ok()
                    .and_then(|mre| mre.captures(window).map(|m| MethodHint::parse(&m[1])))
                    .unwrap_or(MethodHint::Unknown);
                out.push(
                    RawEndpoint::new(c[1].to_string(), ExtractorKind::JsAxios).with_method(method),
                );
            }
        }

        // xhr.open("POST", "/x") — first arg is the method, second the URL.
        if let Ok(re) = Regex::new(
            r#"\.open\s*\(\s*['"](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"]\s*,\s*['"`]([^'"`]+)['"`]"#,
        ) {
            for c in re.captures_iter(content) {
                out.push(
                    RawEndpoint::new(c[2].to_string(), ExtractorKind::JsXhr)
                        .with_method(MethodHint::parse(&c[1])),
                );
            }
        }

        // Bare URL/path string literals: `"/api/x"`, `'https://h/x'`, `` `/y` ``.
        // Lowest-confidence net; the engine dedupes it against the calls above.
        if let Ok(re) =
            Regex::new(r#"['"`]((?:https?|wss?)://[^'"`\s]+|/[A-Za-z0-9_\-./]{2,}(?:\?[^'"`\s]*)?)['"`]"#)
        {
            for c in re.captures_iter(content) {
                out.push(RawEndpoint::new(c[1].to_string(), ExtractorKind::JsStringLiteral));
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find<'a>(v: &'a [RawEndpoint], raw: &str, src: ExtractorKind) -> Option<&'a RawEndpoint> {
        v.iter().find(|r| r.raw == raw && r.source == src)
    }

    #[test]
    fn fetch_defaults_to_get() {
        let out = JavaScriptExtractor.extract(r#"fetch('/api/v1/users')"#);
        let r = find(&out, "/api/v1/users", ExtractorKind::JsFetch).unwrap();
        assert_eq!(r.method, MethodHint::Get);
    }

    #[test]
    fn axios_method_is_captured() {
        let out = JavaScriptExtractor.extract(r#"axios.post("/login", body)"#);
        let r = find(&out, "/login", ExtractorKind::JsAxios).unwrap();
        assert_eq!(r.method, MethodHint::Post);
    }

    #[test]
    fn axios_config_object_reads_method() {
        let out = JavaScriptExtractor.extract(r#"axios({ url: "/orders", method: "put" })"#);
        let r = find(&out, "/orders", ExtractorKind::JsAxios).unwrap();
        assert_eq!(r.method, MethodHint::Put);
    }

    #[test]
    fn xhr_open_captures_method_and_url() {
        let out = JavaScriptExtractor.extract(r#"xhr.open('DELETE', '/api/item/9')"#);
        let r = find(&out, "/api/item/9", ExtractorKind::JsXhr).unwrap();
        assert_eq!(r.method, MethodHint::Delete);
    }

    #[test]
    fn string_literals_catch_bare_paths_and_urls() {
        let out = JavaScriptExtractor.extract(r#"const a = "/api/config"; const b = "https://h.test/v2";"#);
        assert!(find(&out, "/api/config", ExtractorKind::JsStringLiteral).is_some());
        assert!(find(&out, "https://h.test/v2", ExtractorKind::JsStringLiteral).is_some());
    }

    #[test]
    fn does_not_capture_prose_strings() {
        let out = JavaScriptExtractor.extract(r#"const msg = "hello world";"#);
        assert!(out.is_empty());
    }
}
