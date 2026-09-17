//! Reflection correlation: connect a submitted parameter to every point it
//! appeared at, with resolved contexts, forming the evidence trail.

use super::detector::{detect_reflections, DetectionConfig, ReflectionPoint};
use crate::parser::html::parse_at;
use crate::parser::javascript::lex_at;
use serde::{Deserialize, Serialize};

/// A reflection point with its resolved HTML and (when relevant) JS context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedReflection {
    pub parameter: String,
    pub offset: usize,
    pub length: usize,
    pub encoding: String,
    /// The parsed HTML node the reflection sits in.
    pub html_context: Option<crate::parser::html::HtmlParseContext>,
    /// The parsed JS node, when the reflection is inside a script block.
    pub js_context: Option<crate::parser::javascript::JavaScriptParseContext>,
}

/// Correlate a submitted value against a response: find every reflection,
/// and resolve each into its document position.
pub fn correlate(
    body: &str,
    parameter: &str,
    submitted: &str,
) -> Vec<CorrelatedReflection> {
    let config = DetectionConfig::new(parameter, submitted);
    let points: Vec<ReflectionPoint> = detect_reflections(body, &config);

    points
        .into_iter()
        .map(|p| CorrelatedReflection {
            parameter: parameter.to_string(),
            offset: p.offset,
            length: p.length,
            encoding: format!("{:?}", p.encoding),
            html_context: resolve_html(body, &p),
            js_context: resolve_js(body, &p),
        })
        .collect()
}

fn resolve_html(body: &str, point: &ReflectionPoint) -> Option<crate::parser::html::HtmlParseContext> {
    let observed = &point.observed;
    let needle = if observed.is_empty() { "" } else { observed.as_str() };
    let ctx = parse_at(body, point.offset, needle);
    // The heuristic fallback is still useful context, but mark confidence
    // honestly by keeping only parsed results as Some.
    match ctx.method {
        crate::parser::html::ContextMethod::Parsed => Some(ctx),
        crate::parser::html::ContextMethod::HeuristicFallback => None,
    }
}

fn resolve_js(
    body: &str,
    point: &ReflectionPoint,
) -> Option<crate::parser::javascript::JavaScriptParseContext> {
    // Only meaningful when the HTML context says we are inside a script.
    let html = crate::parser::html::parse_at(body, point.offset, &point.observed);
    if html.node_type != crate::parser::html::HtmlNodeType::Script {
        return None;
    }
    // Extract the script body and translate the offset into it.
    let script_start = body[..point.offset].rfind("<script").map(|p| {
        body[p..].find('>').map(|g| p + g + 1).unwrap_or(p)
    })?;
    let script_end = body[script_start..]
        .find("</script")
        .map(|p| script_start + p)
        .unwrap_or(body.len());
    let script_body = &body[script_start..script_end];
    let inner_offset = point.offset.saturating_sub(script_start);
    let ctx = lex_at(script_body, inner_offset);
    // Keep real resolutions — the syntax tree, and the token scan it falls
    // back to — and drop the last-resort answer, mirroring `resolve_html`.
    match ctx.method {
        crate::parser::javascript::ContextMethod::Ast
        | crate::parser::javascript::ContextMethod::Lexed => Some(ctx),
        crate::parser::javascript::ContextMethod::Fallback => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_reflection_resolves_to_attribute_context() {
        let body = r#"<input value="xyzzy42" type="text">"#;
        let found = correlate(body, "q", "xyzzy42");
        assert_eq!(found.len(), 1);
        let html = found[0].html_context.as_ref().expect("context unresolved");
        assert_eq!(html.node_type, crate::parser::html::HtmlNodeType::QuotedAttribute);
        assert_eq!(html.attribute_name.as_deref(), Some("value"));
    }

    #[test]
    fn script_reflection_resolves_to_js_context() {
        let body = r#"<script>var x = "xyzzy42";</script>"#;
        let found = correlate(body, "q", "xyzzy42");
        assert_eq!(found.len(), 1);
        let js = found[0].js_context.as_ref().expect("js unresolved");
        assert_eq!(js.node_type, crate::parser::javascript::JavaScriptNodeType::String);
    }

    #[test]
    fn text_reflection_has_no_js_context() {
        let body = "<p>hello xyzzy42 world</p>";
        let found = correlate(body, "q", "xyzzy42");
        assert!(found[0].js_context.is_none());
        let html = found[0].html_context.as_ref().unwrap();
        assert_eq!(html.node_type, crate::parser::html::HtmlNodeType::TextNode);
    }

    #[test]
    fn multiple_points_all_resolve() {
        let body = r#"<a href="/x?q=xyzzy42">xyzzy42</a><script>var s="xyzzy42";</script>"#;
        let found = correlate(body, "q", "xyzzy42");
        assert_eq!(found.len(), 3);
        // One in an attribute, one in text, one in a JS string.
        let kinds: Vec<&str> = found
            .iter()
            .map(|f| {
                f.html_context
                    .as_ref()
                    .map(|c| c.node_type.label())
                    .unwrap_or("?")
            })
            .collect();
        assert!(kinds.contains(&"quoted attribute"));
        assert!(kinds.contains(&"text node"));
        assert!(kinds.contains(&"script"));
    }

    #[test]
    fn absent_reflection_produces_nothing() {
        let found = correlate("<p>nothing</p>", "q", "xyzzy42");
        assert!(found.is_empty());
    }

    #[test]
    fn every_point_carries_its_parameter() {
        let found = correlate("<p>a xyzzy42 b</p>", "search", "xyzzy42");
        assert!(found.iter().all(|f| f.parameter == "search"));
    }
}
