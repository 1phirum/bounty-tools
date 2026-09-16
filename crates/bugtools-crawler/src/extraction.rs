//! HTML extraction: links, forms, and endpoint-like paths.
//!
//! Static parsing only — no JavaScript is executed.

use serde::{Deserialize, Serialize};

/// A link discovered in an HTML document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtractedLink {
    /// A navigable link (anchor, area).
    Anchor(String),
    /// A script source.
    Script(String),
    /// An image source.
    Image(String),
    /// A stylesheet.
    Stylesheet(String),
    /// A form action with its method.
    Form { action: String, method: String },
    /// A raw path-like string found in inline content (e.g. inside <script>).
    PathLike(String),
}

/// Extract links, scripts, images, stylesheets, and form actions from HTML.
///
/// Resolution against a base URL is the caller's job; anything returned here
/// is exactly what appeared in the document, which keeps this function pure
/// and unit-testable.
pub fn extract_endpoints(html: &str) -> Vec<ExtractedLink> {
    use scraper::{Html, Selector};

    let document = Html::parse_document(html);
    let mut out = Vec::new();

    let push_all = |sel: &Selector, doc: &Html, attr: &str, make: fn(String) -> ExtractedLink, out: &mut Vec<ExtractedLink>| {
        for el in doc.select(sel) {
            if let Some(v) = el.value().attr(attr) {
                let v = v.trim();
                if !v.is_empty() {
                    out.push(make(v.to_string()));
                }
            }
        }
    };

    let a_sel = Selector::parse("a[href]").unwrap();
    push_all(&a_sel, &document, "href", ExtractedLink::Anchor, &mut out);

    let script_sel = Selector::parse("script[src]").unwrap();
    push_all(&script_sel, &document, "src", ExtractedLink::Script, &mut out);

    let img_sel = Selector::parse("img[src]").unwrap();
    push_all(&img_sel, &document, "src", ExtractedLink::Image, &mut out);

    let link_sel = Selector::parse("link[href]").unwrap();
    push_all(&link_sel, &document, "href", ExtractedLink::Stylesheet, &mut out);

    let form_sel = Selector::parse("form").unwrap();
    for form in document.select(&form_sel) {
        let action = form.value().attr("action").unwrap_or("").trim().to_string();
        let method = form
            .value()
            .attr("method")
            .unwrap_or("GET")
            .trim()
            .to_uppercase();
        if !action.is_empty() {
            out.push(ExtractedLink::Form { action, method });
        }
    }

    // Static path extraction from inline script/JSON-ish content.
    for path in extract_path_like(html) {
        out.push(ExtractedLink::PathLike(path));
    }

    out
}

/// Extract path-like strings such as `/api/v1/users` from arbitrary text.
/// Deliberately conservative: requires a leading slash and a plausible
/// segment structure so prose or maths is not mistaken for a path.
pub fn extract_path_like(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' {
            let start = i;
            let mut j = i + 1;
            while j < bytes.len() {
                let c = bytes[j] as char;
                if c.is_ascii_alphanumeric()
                    || c == '/'
                    || c == '_'
                    || c == '-'
                    || c == '.'
                    || c == '?'
                    || c == '='
                    || c == '&'
                    || c == '%'
                {
                    j += 1;
                } else {
                    break;
                }
            }
            let candidate = &text[start..j];
            if is_plausible_path(candidate) && !found.contains(&candidate.to_string()) {
                found.push(candidate.to_string());
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    found
}

fn is_plausible_path(candidate: &str) -> bool {
    // Must be long enough, contain at least one alphanumeric segment, and not
    // be a bare "/" or look like a date/fraction.
    if candidate.len() < 4 {
        return false;
    }
    let trimmed = candidate.trim_end_matches('/');
    if trimmed.len() < 3 {
        return false;
    }
    let segments: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return false;
    }
    // A single purely-numeric segment like "/2026" is probably a date.
    if segments.len() == 1 && segments[0].chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_anchors_and_scripts() {
        let html = r#"
            <html><body>
              <a href="/products?id=1">Product</a>
              <a href="https://other.test/x">External</a>
              <script src="/static/app.js"></script>
              <img src="/img/logo.png">
            </body></html>
        "#;
        let links = extract_endpoints(html);
        assert!(links.contains(&ExtractedLink::Anchor("/products?id=1".into())));
        assert!(links.contains(&ExtractedLink::Script("/static/app.js".into())));
        assert!(links.contains(&ExtractedLink::Image("/img/logo.png".into())));
    }

    #[test]
    fn extracts_forms() {
        let html = r#"<form action="/search" method="post"><input name="q"></form>"#;
        let links = extract_endpoints(html);
        assert!(links.contains(&ExtractedLink::Form {
            action: "/search".into(),
            method: "POST".into()
        }));
    }

    #[test]
    fn form_defaults_to_get() {
        let html = r#"<form action="/submit"></form>"#;
        let links = extract_endpoints(html);
        assert!(links.contains(&ExtractedLink::Form {
            action: "/submit".into(),
            method: "GET".into()
        }));
    }

    #[test]
    fn extracts_api_paths_from_inline_js() {
        let html = r#"<script>fetch('/api/v1/users'); var x = "/graphql";</script>"#;
        let paths = extract_path_like(html);
        assert!(paths.contains(&"/api/v1/users".to_string()));
        assert!(paths.contains(&"/graphql".to_string()));
    }

    #[test]
    fn rejects_bare_slash_and_dates() {
        assert!(extract_path_like("a / b").is_empty());
        assert!(extract_path_like("year /2026 end").is_empty());
    }

    #[test]
    fn no_duplicate_paths() {
        let paths = extract_path_like("/api/x /api/x");
        assert_eq!(paths.iter().filter(|p| *p == "/api/x").count(), 1);
    }

    #[test]
    fn handles_empty_and_malformed_html() {
        assert!(extract_endpoints("").is_empty());
        let links = extract_endpoints("<a href=>bad</a>");
        assert!(!links.iter().any(|l| matches!(l, ExtractedLink::Anchor(s) if s.is_empty())));
    }
}
