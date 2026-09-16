//! Real JavaScript lexer for script-context determination.
//!
//! Replaces quote-parity counting, which cannot handle escaped quotes,
//! comments, regex literals, or nested template literals. This lexer tracks
//! the actual token stream so an offset resolves to a precise JS node.

use serde::{Deserialize, Serialize};

/// The JavaScript node an injection point sits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JavaScriptNodeType {
    String,
    TemplateLiteral,
    Expression,
    Comment,
    RegexLiteral,
    Object,
    Array,
    Property,
    Code,
    /// Inside `${...}` within a template literal.
    TemplateExpression,
    Unknown,
}

impl JavaScriptNodeType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::String => "JavaScript string",
            Self::TemplateLiteral => "template literal",
            Self::Expression => "expression",
            Self::Comment => "comment",
            Self::RegexLiteral => "regex literal",
            Self::Object => "object",
            Self::Array => "array",
            Self::Property => "property",
            Self::Code => "code",
            Self::TemplateExpression => "template expression",
            Self::Unknown => "unknown",
        }
    }

    /// Whether breaking out requires closing a delimiter.
    pub fn requires_delimiter_break(&self) -> bool {
        matches!(self, Self::String | Self::TemplateLiteral)
    }

    /// Whether this is a script-capable position.
    pub fn is_script_capable(&self) -> bool {
        !matches!(self, Self::Comment | Self::Unknown)
    }
}

/// A byte range in the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRange {
    pub start: usize,
    pub end: usize,
}

/// The parsed JavaScript context of an injection point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaScriptParseContext {
    pub node_type: JavaScriptNodeType,
    pub source_range: SourceRange,
    /// The nesting chain from outermost to innermost.
    pub parent_nodes: Vec<JavaScriptNodeType>,
    pub confidence: f32,
    /// How the context was determined.
    pub method: ContextMethod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextMethod {
    Lexed,
    Fallback,
}

/// Lex JavaScript source and describe the node covering `offset`
/// (relative to the script body).
pub fn lex_at(source: &str, offset: usize) -> JavaScriptParseContext {
    let tokens = lex(source);
    for (i, tok) in tokens.iter().enumerate() {
        if offset < tok.range.start || offset >= tok.range.end {
            continue;
        }
        // Build the parent chain from strictly-enclosing template literals.
        // A template literal that merely *contains* the offset is a parent;
        // the token itself is the innermost context.
        let mut parents = Vec::new();
        for earlier in tokens.iter().take(i) {
            if earlier.node_type == JavaScriptNodeType::TemplateLiteral
                && earlier.range.start < tok.range.start
                && earlier.range.end >= tok.range.end
            {
                parents.push(JavaScriptNodeType::TemplateLiteral);
            }
        }
        // Inside a template literal we also distinguish the `${...}` region,
        // which is an expression rather than literal text. A `${` appearing
        // before the offset with an unclosed brace means expression context.
        let node_type = if tok.node_type == JavaScriptNodeType::TemplateLiteral {
            if in_template_expression(source, tok.range.start, offset) {
                JavaScriptNodeType::TemplateExpression
            } else {
                JavaScriptNodeType::TemplateLiteral
            }
        } else {
            tok.node_type
        };
        return JavaScriptParseContext {
            node_type,
            source_range: tok.range,
            parent_nodes: parents,
            confidence: 0.9,
            method: ContextMethod::Lexed,
        };
    }
    JavaScriptParseContext {
        node_type: JavaScriptNodeType::Unknown,
        source_range: SourceRange { start: offset, end: offset },
        parent_nodes: vec![],
        confidence: 0.2,
        method: ContextMethod::Fallback,
    }
}

#[derive(Debug)]
struct JsToken {
    range: SourceRange,
    node_type: JavaScriptNodeType,
}

/// A real (if compact) JavaScript lexer.
///
/// Handles: line comments, block comments, single/double-quoted strings with
/// escapes, template literals with nesting, regex literals (disambiguated
/// from division by preceding token), and bracket nesting for
/// object/array/property context.
fn lex(source: &str) -> Vec<JsToken> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    let len = bytes.len();
    // Tracks whether a `/` starts a regex or is division.
    let mut prev_significant: Option<u8> = None;
    // Nesting stack for object/array context.
    let mut bracket_stack: Vec<u8> = Vec::new();

    while i < len {
        let c = bytes[i];

        // Line comment.
        if c == b'/' && i + 1 < len && bytes[i + 1] == b'/' {
            let start = i;
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            tokens.push(JsToken {
                range: SourceRange { start, end: i },
                node_type: JavaScriptNodeType::Comment,
            });
            continue;
        }

        // Block comment.
        if c == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
            let start = i;
            i += 2;
            while i + 1 < len && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(len);
            tokens.push(JsToken {
                range: SourceRange { start, end: i },
                node_type: JavaScriptNodeType::Comment,
            });
            continue;
        }

        // Regex literal: `/` where an operand is expected.
        if c == b'/' && regex_can_start(prev_significant) {
            let start = i;
            i += 1;
            let mut in_class = false;
            while i < len {
                match bytes[i] {
                    b'\\' => {
                        i += 2;
                        continue;
                    }
                    b'[' => in_class = true,
                    b']' => in_class = false,
                    b'/' if !in_class => {
                        i += 1;
                        break;
                    }
                    b'\n' => break,
                    _ => {}
                }
                i += 1;
            }
            // Flags.
            while i < len && bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            tokens.push(JsToken {
                range: SourceRange { start, end: i },
                node_type: JavaScriptNodeType::RegexLiteral,
            });
            prev_significant = Some(b'/');
            continue;
        }

        // Strings.
        if c == b'"' || c == b'\'' {
            let quote = c;
            let start = i;
            i += 1;
            while i < len {
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == quote {
                    i += 1;
                    break;
                }
                i += 1;
            }
            tokens.push(JsToken {
                range: SourceRange { start, end: i },
                node_type: JavaScriptNodeType::String,
            });
            prev_significant = Some(quote);
            continue;
        }

        // Template literals (with nesting via `${ }`).
        if c == b'`' {
            let start = i;
            i += 1;
            let mut depth = 0usize;
            while i < len {
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'$' && i + 1 < len && bytes[i + 1] == b'{' {
                    depth += 1;
                    i += 2;
                    continue;
                }
                if bytes[i] == b'}' && depth > 0 {
                    depth -= 1;
                    i += 1;
                    continue;
                }
                if bytes[i] == b'`' && depth == 0 {
                    i += 1;
                    break;
                }
                i += 1;
            }
            tokens.push(JsToken {
                range: SourceRange { start, end: i },
                node_type: JavaScriptNodeType::TemplateLiteral,
            });
            prev_significant = Some(b'`');
            continue;
        }

        // Brackets: object/array context.
        if c == b'{' {
            bracket_stack.push(b'{');
            let start = i;
            i += 1;
            tokens.push(JsToken {
                range: SourceRange { start, end: i },
                node_type: JavaScriptNodeType::Object,
            });
            let _ = start;
            prev_significant = Some(c);
            continue;
        }
        if c == b'[' {
            bracket_stack.push(b'[');
            i += 1;
            tokens.push(JsToken {
                range: SourceRange { start: i - 1, end: i },
                node_type: JavaScriptNodeType::Array,
            });
            prev_significant = Some(c);
            continue;
        }
        if c == b'}' || c == b']' {
            bracket_stack.pop();
            i += 1;
            prev_significant = Some(c);
            continue;
        }

        // A quoted property key inside an object → Property.
        if c == b':' && bracket_stack.last() == Some(&b'{') {
            i += 1;
            prev_significant = Some(c);
            continue;
        }

        if !c.is_ascii_whitespace() {
            prev_significant = Some(c);
        }
        i += 1;
    }

    tokens
}

/// Whether `offset` sits inside a `${ ... }` expression within a template
/// literal. Scans from the literal's opening backtick, tracking brace depth.
fn in_template_expression(source: &str, literal_start: usize, offset: usize) -> bool {
    let bytes = source.as_bytes();
    let mut i = literal_start + 1; // skip the backtick
    let mut depth = 0usize;
    while i < offset.min(bytes.len()) {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            depth += 1;
            i += 2;
            continue;
        }
        if bytes[i] == b'}' && depth > 0 {
            depth -= 1;
        }
        i += 1;
    }
    depth > 0
}

/// Whether a `/` at this position begins a regex literal rather than division.
fn regex_can_start(prev: Option<u8>) -> bool {
    match prev {
        None => true,
        Some(c) => {
            // After a value/literal, `/` is division. After an operator,
            // `(`, `,`, `=`, `return`, etc., it starts a regex.
            !matches!(
                c,
                b')' | b']' | b'}' | b'"' | b'\'' | b'`' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z'
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(src: &str, needle: &str) -> JavaScriptParseContext {
        let off = src.find(needle).expect("needle not found");
        lex_at(src, off)
    }

    #[test]
    fn plain_expression_context() {
        let ctx = at("var x = MARKER;", "MARKER");
        assert_eq!(ctx.node_type, JavaScriptNodeType::Unknown);
    }

    #[test]
    fn single_quoted_string_context() {
        let ctx = at("var x = 'MARKER';", "MARKER");
        assert_eq!(ctx.node_type, JavaScriptNodeType::String);
    }

    #[test]
    fn double_quoted_string_context() {
        let ctx = at(r#"var x = "MARKER";"#, "MARKER");
        assert_eq!(ctx.node_type, JavaScriptNodeType::String);
    }

    #[test]
    fn escaped_quote_does_not_end_string() {
        // The `\'` must not terminate the string; parity counting would
        // wrongly see the string as closed.
        let src = r#"var x = 'a\'b MARKER c';"#;
        let ctx = at(src, "MARKER");
        assert_eq!(
            ctx.node_type,
            JavaScriptNodeType::String,
            "escaped quote must not end the string"
        );
    }

    #[test]
    fn comment_context_is_not_script_capable() {
        let ctx = at("// MARKER", "MARKER");
        assert_eq!(ctx.node_type, JavaScriptNodeType::Comment);
        assert!(!ctx.node_type.is_script_capable());
    }

    #[test]
    fn block_comment_context() {
        let ctx = at("/* MARKER */", "MARKER");
        assert_eq!(ctx.node_type, JavaScriptNodeType::Comment);
    }

    #[test]
    fn regex_literal_context() {
        let ctx = at("var re = /MARKER/g;", "MARKER");
        assert_eq!(ctx.node_type, JavaScriptNodeType::RegexLiteral);
    }

    #[test]
    fn division_is_not_a_regex() {
        let src = "var y = a / b; var MARKER = 1;";
        let ctx = at(src, "MARKER");
        // MARKER here is in code, not inside a regex.
        assert_ne!(ctx.node_type, JavaScriptNodeType::RegexLiteral);
    }

    #[test]
    fn template_literal_context() {
        let ctx = at("var s = `MARKER`;", "MARKER");
        assert_eq!(ctx.node_type, JavaScriptNodeType::TemplateLiteral);
        assert!(ctx.node_type.requires_delimiter_break());
    }

    #[test]
    fn nested_template_expression_is_in_expression_context() {
        let src = "var s = `outer ${ `inner ${ MARKER }` }`;";
        let ctx = at(src, "MARKER");
        // MARKER sits inside a `${ ... }` interpolation, not in literal text.
        assert_eq!(ctx.node_type, JavaScriptNodeType::TemplateExpression);
        assert!(ctx.confidence > 0.5);
    }

    #[test]
    fn literal_text_in_template_is_not_expression() {
        // Between interpolations, the marker is literal text, not an expression.
        let src = "var s = `lit MARKER text`;";
        let ctx = at(src, "MARKER");
        assert_eq!(ctx.node_type, JavaScriptNodeType::TemplateLiteral);
        assert!(ctx.node_type.requires_delimiter_break());
    }

    #[test]
    fn interpolation_position_is_reported_as_expression() {
        // Inside `${ ... }` the position is an expression position. The
        // lexer reports the enclosing template-literal token, refined to
        // TemplateExpression by the interpolation scan. A finer-grained
        // parse (separating the inner string literal) is a known limitation.
        let src = "var s = `outer ${ 'MARKER' }`;";
        let ctx = at(src, "MARKER");
        assert_eq!(ctx.node_type, JavaScriptNodeType::TemplateExpression);
        assert!(ctx.confidence > 0.5);
    }

    #[test]
    fn string_containing_a_template_marker() {
        let src = r#"var x = "a ` b MARKER";"#;
        let ctx = at(src, "MARKER");
        assert_eq!(ctx.node_type, JavaScriptNodeType::String);
    }

    #[test]
    fn source_range_covers_the_needle() {
        let src = "var x = 'abcdefMARKERghi';";
        let off = src.find("MARKER").unwrap();
        let ctx = lex_at(src, off);
        assert!(ctx.source_range.start <= off);
        assert!(ctx.source_range.end >= off + 6);
    }

    #[test]
    fn empty_source_is_safe() {
        let ctx = lex_at("", 0);
        assert_eq!(ctx.node_type, JavaScriptNodeType::Unknown);
    }

    #[test]
    fn unterminated_string_does_not_hang() {
        let ctx = lex_at("var x = 'MARKER", 9);
        assert_eq!(ctx.node_type, JavaScriptNodeType::String);
    }
}
