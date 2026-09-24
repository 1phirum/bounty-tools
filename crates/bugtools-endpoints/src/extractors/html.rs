//! HTML extractor: anchors, forms, scripts, and linked resources.
//!
//! Parses the DOM with `scraper` (no JavaScript is executed) and reports each
//! reference exactly as it appeared. Forms are the richest signal: they carry
//! a method and their input names become form parameters.

use scraper::{Html, Selector};

use crate::models::{
    EndpointExtractor, EndpointKind, EndpointParam, ExtractorKind, MethodHint, ParamLocation,
    RawEndpoint,
};

/// Extracts endpoints from the HTML DOM.
pub struct HtmlExtractor;

impl EndpointExtractor for HtmlExtractor {
    fn name(&self) -> &'static str {
        "html"
    }

    fn kind(&self) -> ExtractorKind {
        // Findings carry their own precise source tag; this is only the
        // extractor's headline kind for stats.
        ExtractorKind::HtmlAnchor
    }

    fn extract(&self, content: &str) -> Vec<RawEndpoint> {
        let doc = Html::parse_document(content);
        let mut out = Vec::new();

        // Anchors — navigable references. Query names become query params.
        if let Ok(sel) = Selector::parse("a[href], area[href]") {
            for el in doc.select(&sel) {
                if let Some(href) = attr(el, "href") {
                    out.push(
                        RawEndpoint::new(href, ExtractorKind::HtmlAnchor)
                            .with_method(MethodHint::Get),
                    );
                }
            }
        }

        // Forms — method + input/select/textarea names as form parameters.
        if let Ok(sel) = Selector::parse("form") {
            for form in doc.select(&sel) {
                let action = form.value().attr("action").unwrap_or("").trim();
                if action.is_empty() {
                    continue;
                }
                let method = MethodHint::parse(form.value().attr("method").unwrap_or("GET"));
                let params = form_params(&form);
                out.push(
                    RawEndpoint::new(action, ExtractorKind::HtmlForm)
                        .with_method(method)
                        .with_kind(EndpointKind::FormAction)
                        .with_params(params),
                );
            }
        }

        // Scripts — code the app loads; nearly always assets but occasionally
        // dynamic (`/config.js?token=…`), so classification is left to the engine.
        if let Ok(sel) = Selector::parse("script[src]") {
            for el in doc.select(&sel) {
                if let Some(src) = attr(el, "src") {
                    out.push(
                        RawEndpoint::new(src, ExtractorKind::HtmlScript)
                            .with_method(MethodHint::Get),
                    );
                }
            }
        }

        // Other linked resources: stylesheets, images, iframes, media.
        for (selector, attr_name) in [
            ("link[href]", "href"),
            ("img[src]", "src"),
            ("iframe[src]", "src"),
            ("source[src]", "src"),
            ("video[src]", "src"),
            ("audio[src]", "src"),
        ] {
            if let Ok(sel) = Selector::parse(selector) {
                for el in doc.select(&sel) {
                    if let Some(v) = attr(el, attr_name) {
                        out.push(
                            RawEndpoint::new(v, ExtractorKind::HtmlResource)
                                .with_method(MethodHint::Get),
                        );
                    }
                }
            }
        }

        out
    }
}

fn attr<'a>(el: scraper::ElementRef<'a>, name: &str) -> Option<String> {
    el.value().attr(name).map(str::trim).filter(|v| !v.is_empty()).map(str::to_string)
}

fn form_params(form: &scraper::ElementRef) -> Vec<EndpointParam> {
    let mut params = Vec::new();
    if let Ok(sel) = Selector::parse("input[name], select[name], textarea[name], button[name]") {
        for field in form.select(&sel) {
            if let Some(name) = field.value().attr("name") {
                let name = name.trim();
                if !name.is_empty() && !params.iter().any(|p: &EndpointParam| p.name == name) {
                    params.push(EndpointParam {
                        name: name.to_string(),
                        location: ParamLocation::Form,
                    });
                }
            }
        }
    }
    params
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_anchor_with_get() {
        let out = HtmlExtractor.extract(r#"<a href="/products?id=1">p</a>"#);
        let a = out.iter().find(|r| r.source == ExtractorKind::HtmlAnchor).unwrap();
        assert_eq!(a.raw, "/products?id=1");
        assert_eq!(a.method, MethodHint::Get);
    }

    #[test]
    fn form_captures_method_and_input_names() {
        let html = r#"<form action="/search" method="post">
            <input name="q"><select name="cat"></select><input name="q"></form>"#;
        let out = HtmlExtractor.extract(html);
        let f = out.iter().find(|r| r.source == ExtractorKind::HtmlForm).unwrap();
        assert_eq!(f.method, MethodHint::Post);
        assert_eq!(f.kind, EndpointKind::FormAction);
        let names: Vec<&str> = f.params.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["q", "cat"], "deduped, form-ordered");
    }

    #[test]
    fn actionless_form_is_skipped() {
        let out = HtmlExtractor.extract(r#"<form method="post"><input name="q"></form>"#);
        assert!(out.iter().all(|r| r.source != ExtractorKind::HtmlForm));
    }

    #[test]
    fn scripts_and_resources() {
        let html = r#"<script src="/a.js"></script><link href="/s.css"><img src="/i.png">"#;
        let out = HtmlExtractor.extract(html);
        assert!(out.iter().any(|r| r.raw == "/a.js" && r.source == ExtractorKind::HtmlScript));
        assert!(out.iter().any(|r| r.raw == "/s.css" && r.source == ExtractorKind::HtmlResource));
        assert!(out.iter().any(|r| r.raw == "/i.png" && r.source == ExtractorKind::HtmlResource));
    }
}
