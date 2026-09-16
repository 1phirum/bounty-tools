//! Deep context analyzer (brief §4, §8).
//!
//! Determines *where* attacker-controlled data lands in the response, and
//! enforces the brief's most important distinction:
//!
//! ```text
//! input reflected  ≠  HTML injection  ≠  script execution
//! ```
//!
//! The analyzer reports the narrowest context it can justify from the
//! surrounding syntax, and never upgrades a reflection into an injection
//! claim.

use serde::{Deserialize, Serialize};

/// The parser context an injection point sits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextType {
    HtmlText,
    QuotedAttribute,
    UnquotedAttribute,
    EventHandlerAttribute,
    UrlAttribute,
    JavaScriptString,
    JavaScriptExpression,
    JavaScriptTemplateLiteral,
    CssValue,
    StyleAttribute,
    Svg,
    Xml,
    Json,
    ScriptBlock,
    TemplateExpression,
    Unknown,
}

impl ContextType {
    /// Whether this context can plausibly lead to script execution *without
    /// further conditions*. Used to keep the engine from overclaiming.
    pub fn is_script_capable(&self) -> bool {
        matches!(
            self,
            Self::JavaScriptExpression
                | Self::JavaScriptTemplateLiteral
                | Self::EventHandlerAttribute
                | Self::ScriptBlock
        )
    }

    /// Whether breaking out of this context requires closing a delimiter.
    pub fn requires_delimiter_break(&self) -> bool {
        matches!(
            self,
            Self::QuotedAttribute
                | Self::JavaScriptString
                | Self::JavaScriptTemplateLiteral
                | Self::StyleAttribute
        )
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::HtmlText => "HTML text",
            Self::QuotedAttribute => "quoted attribute",
            Self::UnquotedAttribute => "unquoted attribute",
            Self::EventHandlerAttribute => "event-handler attribute",
            Self::UrlAttribute => "URL attribute",
            Self::JavaScriptString => "JavaScript string",
            Self::JavaScriptExpression => "JavaScript expression",
            Self::JavaScriptTemplateLiteral => "JavaScript template literal",
            Self::CssValue => "CSS value",
            Self::StyleAttribute => "style attribute",
            Self::Svg => "SVG",
            Self::Xml => "XML",
            Self::Json => "JSON",
            Self::ScriptBlock => "script block",
            Self::TemplateExpression => "template expression",
            Self::Unknown => "unknown",
        }
    }
}

/// The analyzer's verdict for one reflection point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssContext {
    pub context_type: ContextType,
    /// Which parser will interpret this region.
    pub parser: String,
    /// The encoding the server applied, if any was detectable.
    pub encoding: Option<String>,
    /// Byte offset of the reflection in the response body.
    pub reflection_offset: usize,
    /// The exact syntax surrounding the reflection.
    pub surrounding_syntax: String,
    pub confidence: f32,
    /// The reason this context was chosen.
    pub rationale: String,
}

/// A reflection observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reflection {
    pub offset: usize,
    /// The payload as submitted.
    pub submitted: String,
    /// What actually appeared in the response.
    pub reflected: String,
    pub encoding: ReflectionEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReflectionEncoding {
    /// Bytes appeared unchanged.
    Exact,
    /// HTML entities were applied.
    HtmlEncoded,
    /// Percent/URL encoding visible in the body.
    UrlEncoded,
    /// A backslash escape was added.
    BackslashEscaped,
    /// Only part of the payload appeared.
    Partial,
    /// The value was normalized (case/whitespace/unicode).
    Normalized,
}

/// Analyse the context of a reflection within a response body.
pub fn analyze_context(body: &str, reflection: &Reflection) -> XssContext {
    let offset = reflection.offset.min(body.len());
    // Look back far enough to see the opening delimiter/tag.
    let window_start = offset.saturating_sub(160);
    let before = &body[window_start..offset];

    let (context_type, parser, rationale) = classify_from_prefix(before);

    XssContext {
        context_type,
        parser: parser.to_string(),
        encoding: Some(format!("{:?}", reflection.encoding)),
        reflection_offset: offset,
        surrounding_syntax: before
            .chars()
            .rev()
            .take(80)
            .collect::<String>()
            .chars()
            .rev()
            .collect(),
        confidence: if context_type == ContextType::Unknown { 0.3 } else { 0.75 },
        rationale: rationale.to_string(),
    }
}

/// Classify a context from the text immediately preceding the injection.
fn classify_from_prefix(before: &str) -> (ContextType, &'static str, &'static str) {
    let lower = before.to_lowercase();

    // Inside a script block?
    let last_script_open = lower.rfind("<script");
    let last_script_close = lower.rfind("</script");
    let in_script = match (last_script_open, last_script_close) {
        (Some(o), Some(c)) => o > c,
        (Some(_), None) => true,
        _ => false,
    };

    if in_script {
        // Within script, determine string vs expression vs template literal.
        // Count unescaped single/double quotes since the script opened.
        let script_body = &lower[last_script_open.unwrap()..];
        let single_quotes = script_body.matches('\'').count();
        let double_quotes = script_body.matches('"').count();
        let backticks = script_body.matches('`').count();

        if backticks % 2 == 1 {
            return (
                ContextType::JavaScriptTemplateLiteral,
                "javascript",
                "odd number of backticks since <script> — inside a template literal",
            );
        }
        if single_quotes % 2 == 1 || double_quotes % 2 == 1 {
            return (
                ContextType::JavaScriptString,
                "javascript",
                "odd quote count since <script> — inside a JS string literal",
            );
        }
        return (
            ContextType::JavaScriptExpression,
            "javascript",
            "inside <script> with balanced quotes — expression position",
        );
    }

    // Event handler attribute: on*="..." that has not been closed.
    for handler in [
        "onerror=", "onload=", "onclick=", "onmouseover=", "onfocus=", "oninput=",
    ] {
        if let Some(pos) = lower.rfind(handler) {
            let after = &before[pos + handler.len()..];
            if !after.contains('>') {
                return (
                    ContextType::EventHandlerAttribute,
                    "html",
                    "inside an on*= event-handler attribute",
                );
            }
        }
    }

    // Attribute context: find the last '<' that opened a tag, and whether we
    // are inside its quoted or unquoted value.
    if let Some(tag_start) = before.rfind('<') {
        let tag = &before[tag_start..];
        if !tag.contains('>') {
            // Find the attribute's `=` — the FIRST `=` outside any quotes.
            // Using the last `=` would incorrectly pick up an `=` inside a
            // URL query string (e.g. href="/x?q=...).
            if let Some(attr_eq) = first_unquoted_equals(tag) {
                let attr_name = tag[..attr_eq]
                    .split_whitespace()
                    .last()
                    .unwrap_or("")
                    .to_lowercase();
                let value = &tag[attr_eq + 1..];
                let trimmed = value.trim_start();

                if attr_name == "style" {
                    return (ContextType::StyleAttribute, "html", "inside a style attribute");
                }
                if matches!(
                    attr_name.as_str(),
                    "href" | "src" | "action" | "data" | "formaction" | "srcset" | "poster"
                ) {
                    return (ContextType::UrlAttribute, "html", "inside a URL-bearing attribute");
                }
                if trimmed.starts_with('\'') || trimmed.starts_with('"') {
                    return (ContextType::QuotedAttribute, "html", "inside a quoted attribute value");
                }
                return (
                    ContextType::UnquotedAttribute,
                    "html",
                    "inside an unquoted attribute value",
                );
            }
            return (
                ContextType::UnquotedAttribute,
                "html",
                "inside an open tag but outside a value",
            );
        }
    }

    // SVG root?
    if lower.rfind("<svg").map(|p| p > lower.rfind("</svg").unwrap_or(0)).unwrap_or(false) {
        return (ContextType::Svg, "html", "inside an <svg> subtree");
    }

    // JSON response?
    let trimmed = before.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') || trimmed.contains("\":") {
        return (
            ContextType::Json,
            "json",
            "response appears to be JSON-structured",
        );
    }

    // Template expression ({{ }} / {% %}).
    if lower.contains("{{") && lower.rfind('{').map(|p| lower[p..].contains("}}") == false).unwrap_or(false) {
        return (
            ContextType::TemplateExpression,
            "template",
            "inside an unclosed {{ }} template expression",
        );
    }

    if before.contains('<') && !before.contains('>') {
        return (ContextType::HtmlText, "html", "in element text content");
    }

    if before.is_empty() {
        return (ContextType::Unknown, "unknown", "no surrounding syntax available");
    }

    (ContextType::HtmlText, "html", "defaulting to HTML text context")
}

/// A reflection alone is NOT a finding. This function states that explicitly
/// and is used by the assessment layer.
pub fn reflection_is_finding(encoding: ReflectionEncoding, context: ContextType) -> bool {
    // Even an exact, unencoded reflection in a script-capable context is only
    // a *candidate*; it has not been shown to execute.
    let _ = (encoding, context);
    false
}

/// Find the index of the first `=` in `tag` that is not inside a quote.
/// The attribute's `=` is the first one; later `=` characters belong to the
/// value (e.g. a query string), so using `rfind` would be wrong.
fn first_unquoted_equals(tag: &str) -> Option<usize> {
    let mut in_single = false;
    let mut in_double = false;
    for (i, ch) in tag.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '=' if !in_single && !in_double => return Some(i),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exploitability::ExploitabilityStage;

    fn reflection_at(body: &str, needle: &str) -> Reflection {
        let offset = body.find(needle).unwrap();
        Reflection {
            offset,
            submitted: needle.to_string(),
            reflected: needle.to_string(),
            encoding: ReflectionEncoding::Exact,
        }
    }

    #[test]
    fn html_text_context_detected() {
        let body = "<html><body><p>MARKER</p></body></html>";
        let ctx = analyze_context(body, &reflection_at(body, "MARKER"));
        assert_eq!(ctx.context_type, ContextType::HtmlText);
    }

    #[test]
    fn quoted_attribute_context_detected() {
        let body = r#"<input value="MARKER" type="text">"#;
        let ctx = analyze_context(body, &reflection_at(body, "MARKER"));
        assert_eq!(ctx.context_type, ContextType::QuotedAttribute);
        assert!(ctx.context_type.requires_delimiter_break());
    }

    #[test]
    fn event_handler_context_detected() {
        let body = r#"<img src=x onerror="MARKER">"#;
        let ctx = analyze_context(body, &reflection_at(body, "MARKER"));
        assert_eq!(ctx.context_type, ContextType::EventHandlerAttribute);
        assert!(ctx.context_type.is_script_capable());
    }

    #[test]
    fn url_attribute_context_detected() {
        let body = r#"<a href="MARKER">x</a>"#;
        let ctx = analyze_context(body, &reflection_at(body, "MARKER"));
        assert_eq!(ctx.context_type, ContextType::UrlAttribute);
    }

    #[test]
    fn style_attribute_context_detected() {
        let body = r#"<div style="color: MARKER">x</div>"#;
        let ctx = analyze_context(body, &reflection_at(body, "MARKER"));
        assert_eq!(ctx.context_type, ContextType::StyleAttribute);
    }

    #[test]
    fn javascript_string_context_detected() {
        let body = r#"<script>var x = 'MARKER';</script>"#;
        let ctx = analyze_context(body, &reflection_at(body, "MARKER"));
        assert_eq!(ctx.context_type, ContextType::JavaScriptString);
        assert!(ctx.context_type.requires_delimiter_break());
    }

    #[test]
    fn javascript_expression_context_detected() {
        let body = r#"<script>var x = MARKER;</script>"#;
        let ctx = analyze_context(body, &reflection_at(body, "MARKER"));
        assert_eq!(ctx.context_type, ContextType::JavaScriptExpression);
        assert!(ctx.context_type.is_script_capable());
    }

    #[test]
    fn template_literal_context_detected() {
        let body = "<script>var x = `MARKER`;</script>";
        let ctx = analyze_context(body, &reflection_at(body, "MARKER"));
        assert_eq!(ctx.context_type, ContextType::JavaScriptTemplateLiteral);
    }

    #[test]
    fn json_context_detected() {
        let body = r#"{"name": "MARKER", "ok": true}"#;
        let ctx = analyze_context(body, &reflection_at(body, "MARKER"));
        assert_eq!(ctx.context_type, ContextType::Json);
    }

    #[test]
    fn reflection_alone_is_not_a_finding() {
        // The brief's core rule, encoded as a test.
        assert!(!reflection_is_finding(
            ReflectionEncoding::Exact,
            ContextType::JavaScriptExpression
        ));
        assert!(!ExploitabilityStage::Reflected.is_finding());
        assert!(!ExploitabilityStage::HtmlInjection.is_finding());
        assert!(!ExploitabilityStage::DomReachability.is_finding());
    }

    #[test]
    fn only_execution_confirmed_counts_as_finding() {
        assert!(ExploitabilityStage::ExecutionConfirmed.is_finding());
        assert!(!ExploitabilityStage::SinkReached.is_finding());
        assert!(!ExploitabilityStage::MitigationBlocked.is_finding());
    }

    #[test]
    fn context_always_carries_rationale() {
        let body = "<p>MARKER</p>";
        let ctx = analyze_context(body, &reflection_at(body, "MARKER"));
        assert!(!ctx.rationale.is_empty());
        assert!(ctx.confidence > 0.0);
    }

    #[test]
    fn context_labels_are_human_readable() {
        assert_eq!(ContextType::QuotedAttribute.label(), "quoted attribute");
        assert_eq!(ExploitabilityStage::ExecutionConfirmed.label(), "EXECUTION_CONFIRMED");
    }
}
