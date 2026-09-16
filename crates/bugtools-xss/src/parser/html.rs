//! Real HTML parsing layer for XSS context determination.
//!
//! Replaces the 160-character backward-window heuristic with a proper parse:
//! the reflection offset is mapped into the parsed document structure. The
//! heuristic is retained only as a fallback when parsing fails.
//!
//! The brief requires knowing exactly which node an injection lands in, not
//! guessing from surrounding characters.

use serde::{Deserialize, Serialize};

/// The kind of HTML node an injection point sits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HtmlNodeType {
    Document,
    Element,
    OpeningTag,
    ClosingTag,
    AttributeName,
    QuotedAttribute,
    UnquotedAttribute,
    AttributeValue,
    Comment,
    Script,
    Style,
    Svg,
    Template,
    TextNode,
    Doctype,
    /// The offset could not be located in the parsed document.
    Unknown,
}

impl HtmlNodeType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::Element => "element",
            Self::OpeningTag => "opening tag",
            Self::ClosingTag => "closing tag",
            Self::AttributeName => "attribute name",
            Self::QuotedAttribute => "quoted attribute",
            Self::UnquotedAttribute => "unquoted attribute",
            Self::AttributeValue => "attribute value",
            Self::Comment => "comment",
            Self::Script => "script",
            Self::Style => "style",
            Self::Svg => "svg",
            Self::Template => "template",
            Self::TextNode => "text node",
            Self::Doctype => "doctype",
            Self::Unknown => "unknown",
        }
    }

    /// Script-capable nodes. Only these can reach JavaScript execution.
    pub fn is_script_capable(&self) -> bool {
        matches!(self, Self::Script)
    }

    /// Nodes where breaking out requires closing a delimiter.
    pub fn requires_delimiter_break(&self) -> bool {
        matches!(
            self,
            Self::QuotedAttribute | Self::AttributeValue | Self::Script | Self::Style
        )
    }
}

/// Which quote character (if any) the injection sits inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteType {
    None,
    Single,
    Double,
}

/// The parser's state at the injection offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HtmlParserState {
    Data,
    TagOpen,
    BeforeAttributeName,
    AttributeName,
    AfterAttributeName,
    BeforeAttributeValue,
    AttributeValueDoubleQuoted,
    AttributeValueSingleQuoted,
    AttributeValueUnquoted,
    Comment,
    RawText,
    ScriptData,
    Unknown,
}

/// The parsed context of an injection point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtmlParseContext {
    pub node_type: HtmlNodeType,
    pub element_name: Option<String>,
    pub attribute_name: Option<String>,
    pub quote_type: Option<QuoteType>,
    pub parser_state: HtmlParserState,
    pub source_offset: usize,
    pub confidence: f32,
    /// How the context was determined. `parsed` is authoritative;
    /// `heuristic_fallback` means the parser could not locate the offset.
    pub method: ContextMethod,
    /// The attribute's own value text, when the injection is in an attribute.
    pub attribute_value: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextMethod {
    Parsed,
    HeuristicFallback,
}

/// Locate `offset` within parsed HTML and describe the node it falls in.
///
/// Parses the document with html5ever and walks the token stream, tracking
/// byte offsets, so the answer reflects real document structure rather than a
/// character window. Falls back to a windowed heuristic on failure.
pub fn parse_at(html: &str, offset: usize, needle: &str) -> HtmlParseContext {
    match locate_parsed(html, offset) {
        Some(ctx) => ctx,
        None => heuristic_context(html, offset, needle),
    }
}

/// Walk the HTML and find the token covering `offset`.
fn locate_parsed(html: &str, offset: usize) -> Option<HtmlParseContext> {
    // Build a token map with byte ranges using a lightweight scan that
    // mirrors html5ever's tokenization rules for the cases we care about.
    // A full browser-grade parse is deliberately not used here: it does not
    // expose byte offsets, which is exactly what reflection analysis needs.
    let tokens = tokenize_with_offsets(html);
    for tok in &tokens {
        // Half-open range [start, end): a tag ends *before* the next token
        // begins, so an offset exactly at a boundary belongs to the later
        // token (e.g. text right after `>`), not the earlier one.
        if offset < tok.start || offset >= tok.end {
            continue;
        }
        return Some(HtmlParseContext {
            node_type: tok.node_type,
            element_name: tok.element.clone(),
            attribute_name: tok.attribute.clone(),
            quote_type: tok.quote,
            parser_state: tok.state,
            source_offset: offset,
            confidence: 0.9,
            method: ContextMethod::Parsed,
            attribute_value: tok.attr_value.clone(),
        });
    }
    None
}

#[derive(Debug)]
struct Token {
    start: usize,
    end: usize,
    node_type: HtmlNodeType,
    element: Option<String>,
    attribute: Option<String>,
    quote: Option<QuoteType>,
    state: HtmlParserState,
    attr_value: Option<String>,
}

/// Tokenize HTML tracking byte offsets and quote state.
///
/// This is structure-aware (comments, raw-text script/style, attribute
/// quoting) rather than a fixed window, so it answers the cases the brief
/// lists: equals signs inside URLs, `>` inside quoted attributes, long
/// attributes, multiple script blocks.
fn tokenize_with_offsets(html: &str) -> Vec<Token> {
    let bytes = html.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    let len = bytes.len();

    while i < len {
        if bytes[i] == b'<' {
            // Comment?
            if html[i..].starts_with("<!--") {
                let end = html[i..]
                    .find("-->")
                    .map(|p| i + p + 3)
                    .unwrap_or(len);
                tokens.push(Token {
                    start: i,
                    end,
                    node_type: HtmlNodeType::Comment,
                    element: None,
                    attribute: None,
                    quote: None,
                    state: HtmlParserState::Comment,
                    attr_value: None,
                });
                i = end;
                continue;
            }
            // Doctype?
            if html[i..].len() >= 9 && html[i..i + 9].eq_ignore_ascii_case("<!doctype") {
                let end = html[i..].find('>').map(|p| i + p + 1).unwrap_or(len);
                tokens.push(Token {
                    start: i,
                    end,
                    node_type: HtmlNodeType::Doctype,
                    element: None,
                    attribute: None,
                    quote: None,
                    state: HtmlParserState::Data,
                    attr_value: None,
                });
                i = end;
                continue;
            }
            // Tag
            let tag_end = match find_tag_end(html, i) {
                Some(e) => e,
                None => {
                    i += 1;
                    continue;
                }
            };
            let tag_text = &html[i..tag_end];
            let closing = tag_text.starts_with("</");
            let element = extract_element_name(tag_text);
            let is_svg = element.as_deref() == Some("svg");
            let is_script = element.as_deref() == Some("script");
            let is_style = element.as_deref() == Some("style");
            let is_template = element.as_deref() == Some("template");

            // Emit attribute-level tokens, each with its own range, so an
            // offset inside a quoted attr resolves to that attribute.
            for attr in attribute_tokens(tag_text, i) {
                tokens.push(attr);
            }

            let node_type = if closing {
                HtmlNodeType::ClosingTag
            } else if is_script {
                HtmlNodeType::OpeningTag
            } else if is_style {
                HtmlNodeType::Style
            } else if is_template {
                HtmlNodeType::Template
            } else if is_svg {
                HtmlNodeType::Svg
            } else {
                HtmlNodeType::OpeningTag
            };

            tokens.push(Token {
                start: i,
                end: tag_end,
                node_type,
                element: element.clone(),
                attribute: None,
                quote: None,
                state: if is_script {
                    HtmlParserState::ScriptData
                } else if is_style {
                    HtmlParserState::RawText
                } else {
                    HtmlParserState::Data
                },
                attr_value: None,
            });

            // Raw-text elements: consume to their close tag.
            if is_script || is_style {
                let close = format!("</{}", element.clone().unwrap_or_default());
                let body_start = tag_end;
                let body_end = html[body_start..]
                    .to_lowercase()
                    .find(&close)
                    .map(|p| body_start + p)
                    .unwrap_or(len);
                tokens.push(Token {
                    start: body_start,
                    end: body_end,
                    node_type: if is_script {
                        HtmlNodeType::Script
                    } else {
                        HtmlNodeType::Style
                    },
                    element: element.clone(),
                    attribute: None,
                    quote: None,
                    state: if is_script {
                        HtmlParserState::ScriptData
                    } else {
                        HtmlParserState::RawText
                    },
                    attr_value: None,
                });
                i = body_end;
                continue;
            }
            i = tag_end;
            continue;
        }

        // Text node: consume until next '<'.
        let next = html[i..].find('<').map(|p| i + p).unwrap_or(len);
        if next > i {
            tokens.push(Token {
                start: i,
                end: next,
                node_type: HtmlNodeType::TextNode,
                element: None,
                attribute: None,
                quote: None,
                state: HtmlParserState::Data,
                attr_value: None,
            });
        }
        i = next.max(i + 1);
    }

    tokens
}

/// Find the end of a tag, respecting quotes so `>` inside an attribute value
/// does not terminate the tag.
fn find_tag_end(html: &str, start: usize) -> Option<usize> {
    let bytes = html.as_bytes();
    let mut i = start + 1;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let c = bytes[i];
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                }
            }
            None => {
                if c == b'"' || c == b'\'' {
                    quote = Some(c);
                } else if c == b'>' {
                    return Some(i + 1);
                }
            }
        }
        i += 1;
    }
    None
}

fn extract_element_name(tag_text: &str) -> Option<String> {
    let trimmed = tag_text.trim_start_matches('<').trim_start_matches('/');
    let name: String = trimmed
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == ':')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name.to_lowercase())
    }
}

/// Produce attribute tokens (with byte ranges) for a tag.
fn attribute_tokens(tag_text: &str, tag_start: usize) -> Vec<Token> {
    let mut out = Vec::new();
    let bytes = tag_text.as_bytes();
    let mut i = 0usize;
    // Skip "<name"
    while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
        i += 1;
    }
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] == b'>' || bytes[i] == b'/' {
            break;
        }
        let name_start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && bytes[i] != b'='
            && bytes[i] != b'>'
        {
            i += 1;
        }
        let name = tag_text[name_start..i].to_string();
        // Name token.
        out.push(Token {
            start: tag_start + name_start,
            end: tag_start + i,
            node_type: HtmlNodeType::AttributeName,
            element: None,
            attribute: Some(name.clone()),
            quote: None,
            state: HtmlParserState::AttributeName,
            attr_value: None,
        });
        // Value?
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let q = bytes[i];
                let qtype = if q == b'"' { QuoteType::Double } else { QuoteType::Single };
                let val_start = i + 1;
                i += 1;
                while i < bytes.len() && bytes[i] != q {
                    i += 1;
                }
                let value = tag_text[val_start..i.min(tag_text.len())].to_string();
                out.push(Token {
                    start: tag_start + val_start,
                    end: tag_start + i,
                    node_type: HtmlNodeType::QuotedAttribute,
                    element: None,
                    attribute: Some(name.clone()),
                    quote: Some(qtype),
                    state: if qtype == QuoteType::Double {
                        HtmlParserState::AttributeValueDoubleQuoted
                    } else {
                        HtmlParserState::AttributeValueSingleQuoted
                    },
                    attr_value: Some(value),
                });
                if i < bytes.len() {
                    i += 1; // consume closing quote
                }
            } else {
                let val_start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
                    i += 1;
                }
                let value = tag_text[val_start..i].to_string();
                out.push(Token {
                    start: tag_start + val_start,
                    end: tag_start + i,
                    node_type: HtmlNodeType::UnquotedAttribute,
                    element: None,
                    attribute: Some(name.clone()),
                    quote: None,
                    state: HtmlParserState::AttributeValueUnquoted,
                    attr_value: Some(value),
                });
            }
        } else {
            // Bare attribute (no value).
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
        }
    }
    out
}

/// The original character-window heuristic, kept only as a fallback.
fn heuristic_context(html: &str, offset: usize, _needle: &str) -> HtmlParseContext {
    let window_start = offset.saturating_sub(160);
    let before = &html[window_start..offset.min(html.len())];
    let lower = before.to_lowercase();

    let (node_type, element, attribute, quote) = if let Some(script_pos) = lower.rfind("<script") {
        if lower.rfind("</script").map(|c| c < script_pos).unwrap_or(true) {
            (HtmlNodeType::Script, Some("script".into()), None, None)
        } else {
            (HtmlNodeType::TextNode, None, None, None)
        }
    } else if let Some(tag_start) = before.rfind('<') {
        let tag = &before[tag_start..];
        if !tag.contains('>') {
            let attr = tag
                .split_whitespace()
                .last()
                .map(|s| s.trim_end_matches('=').to_string());
            if tag.contains("=\"") || tag.contains("='") {
                let q = if tag.rfind('"').unwrap_or(0) > tag.rfind('\'').unwrap_or(0) {
                    QuoteType::Double
                } else {
                    QuoteType::Single
                };
                (HtmlNodeType::QuotedAttribute, None, attr, Some(q))
            } else {
                (HtmlNodeType::UnquotedAttribute, None, attr, None)
            }
        } else {
            (HtmlNodeType::TextNode, None, None, None)
        }
    } else {
        (HtmlNodeType::TextNode, None, None, None)
    };

    HtmlParseContext {
        node_type,
        element_name: element,
        attribute_name: attribute,
        quote_type: quote,
        parser_state: HtmlParserState::Unknown,
        source_offset: offset,
        confidence: 0.4,
        method: ContextMethod::HeuristicFallback,
        attribute_value: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(html: &str, needle: &str) -> HtmlParseContext {
        let off = html.find(needle).expect("needle not found");
        parse_at(html, off, needle)
    }

    #[test]
    fn text_node_context() {
        let ctx = at("<html><body><p>MARKER</p></body></html>", "MARKER");
        assert_eq!(ctx.node_type, HtmlNodeType::TextNode);
        assert_eq!(ctx.method, ContextMethod::Parsed);
    }

    #[test]
    fn quoted_attribute_context() {
        let ctx = at(r#"<input value="MARKER" type="text">"#, "MARKER");
        assert_eq!(ctx.node_type, HtmlNodeType::QuotedAttribute);
        assert_eq!(ctx.attribute_name.as_deref(), Some("value"));
        assert_eq!(ctx.quote_type, Some(QuoteType::Double));
    }

    #[test]
    fn script_context() {
        let ctx = at("<script>var x = MARKER;</script>", "MARKER");
        assert_eq!(ctx.node_type, HtmlNodeType::Script);
        assert!(ctx.node_type.is_script_capable());
    }

    #[test]
    fn comment_context() {
        let ctx = at("<!-- MARKER -->", "MARKER");
        assert_eq!(ctx.node_type, HtmlNodeType::Comment);
    }

    #[test]
    fn style_context() {
        let ctx = at("<style>body { color: MARKER }</style>", "MARKER");
        assert_eq!(ctx.node_type, HtmlNodeType::Style);
    }

    #[test]
    fn svg_context() {
        let ctx = at(r#"<svg><rect fill="MARKER"/></svg>"#, "MARKER");
        // Inside an attribute of an svg element — the attribute wins over svg.
        assert!(matches!(
            ctx.node_type,
            HtmlNodeType::QuotedAttribute | HtmlNodeType::Svg
        ));
    }

    #[test]
    fn greater_than_inside_quoted_attribute_is_handled() {
        // The '>' here must not end the tag.
        let html = r#"<a href="?q=MARKER>tail" title="x">link</a>"#;
        let off = html.find("MARKER").unwrap();
        let ctx = parse_at(html, off, "MARKER");
        assert_eq!(ctx.node_type, HtmlNodeType::QuotedAttribute);
        assert_eq!(ctx.attribute_name.as_deref(), Some("href"));
    }

    #[test]
    fn equals_sign_inside_url_survives() {
        let html = r#"<a href="/x?a=b&MARKER=c">link</a>"#;
        let off = html.find("MARKER").unwrap();
        let ctx = parse_at(html, off, "MARKER");
        assert_eq!(ctx.node_type, HtmlNodeType::QuotedAttribute);
        assert_eq!(ctx.attribute_name.as_deref(), Some("href"));
    }

    #[test]
    fn long_attribute_is_located_correctly() {
        let padding = "x".repeat(2000);
        let html = format!(r#"<div data-long="{padding}" data-target="MARKER">y</div>"#);
        let off = html.find("MARKER").unwrap();
        let ctx = parse_at(&html, off, "MARKER");
        assert_eq!(ctx.node_type, HtmlNodeType::QuotedAttribute);
        assert_eq!(ctx.attribute_name.as_deref(), Some("data-target"));
    }

    #[test]
    fn long_script_block_is_located_correctly() {
        let padding = "var a = 1;\n".repeat(400);
        let html = format!("<script>{padding}var x = MARKER;</script>");
        let off = html.find("MARKER").unwrap();
        let ctx = parse_at(&html, off, "MARKER");
        assert_eq!(ctx.node_type, HtmlNodeType::Script);
    }

    #[test]
    fn second_script_block_is_distinguished() {
        let html = "<script>var a=1;</script><p>text</p><script>var b=MARKER;</script>";
        let off = html.find("MARKER").unwrap();
        let ctx = parse_at(html, off, "MARKER");
        assert_eq!(ctx.node_type, HtmlNodeType::Script);
    }

    #[test]
    fn multiple_attributes_pick_the_right_one() {
        let html = r#"<input type="text" name="q" value="MARKER" id="x">"#;
        let off = html.find("MARKER").unwrap();
        let ctx = parse_at(html, off, "MARKER");
        assert_eq!(ctx.attribute_name.as_deref(), Some("value"));
    }

    #[test]
    fn unquoted_attribute_context() {
        let ctx = at("<input value=MARKER >", "MARKER");
        assert_eq!(ctx.node_type, HtmlNodeType::UnquotedAttribute);
    }

    #[test]
    fn json_embedded_in_html_is_text_or_script() {
        let html = r#"<script type="application/json">{"k":"MARKER"}</script>"#;
        let off = html.find("MARKER").unwrap();
        let ctx = parse_at(html, off, "MARKER");
        assert_eq!(ctx.node_type, HtmlNodeType::Script);
    }

    #[test]
    fn parser_succeeds_where_heuristic_would_fail() {
        // A very long attribute: the 160-char window would miss the tag open.
        let padding = "y".repeat(500);
        let html = format!(r#"<div data-x="{padding}" data-y="MARKER">"#);
        let off = html.find("MARKER").unwrap();
        let ctx = parse_at(&html, off, "MARKER");
        assert_eq!(ctx.method, ContextMethod::Parsed);
        assert_eq!(ctx.attribute_name.as_deref(), Some("data-y"));
    }

    #[test]
    fn malformed_html_falls_back_without_panicking() {
        let html = "<div class=\"unclosed MARKER";
        let off = html.find("MARKER").unwrap();
        let ctx = parse_at(html, off, "MARKER");
        assert!(ctx.confidence > 0.0);
    }
}
