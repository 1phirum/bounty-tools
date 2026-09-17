//! JavaScript context resolution for an injection offset.
//!
//! Backed by the program-analysis layer in [`crate::parser::js`]: the offset
//! is resolved against a parsed syntax tree, giving a structural answer (an
//! identifier in a call, a string literal, an object literal, …) instead of
//! the old isolated token scan. The token scan is retained as a fallback for
//! offsets the AST does not cover, mirroring how `parser::html::parse_at`
//! keeps its heuristic — an answer is always available, and an AST miss
//! degrades to the previous behaviour rather than to nothing.

use serde::{Deserialize, Serialize};

pub use crate::parser::js::lexer::SourceRange;
use crate::parser::js::lexer::{Token, TokenKind};
use crate::parser::js::{parse_script, SyntaxKind, SyntaxTree};

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
    /// Resolved against the parsed syntax tree.
    Ast,
    /// Resolved by the token scan fallback.
    Lexed,
    /// Neither succeeded; a last-resort answer.
    Fallback,
}

/// Describe the JavaScript node covering `offset` (relative to the script
/// body).
pub fn lex_at(source: &str, offset: usize) -> JavaScriptParseContext {
    match ast_context(source, offset) {
        Some(ctx) => ctx,
        None => token_context(source, offset),
    }
}

/// Structural resolution via the syntax tree.
fn ast_context(source: &str, offset: usize) -> Option<JavaScriptParseContext> {
    let tree = parse_script(source);
    let parents = enclosing_templates(&tree, offset);

    // Token-level classification is authoritative for comments and
    // literals: the AST creates no nodes for comments, and treats literals
    // (including templates) as opaque leaves.
    if let Some(tok) = tree.tokens.iter().find(|t| t.contains(offset)) {
        if let Some(node_type) = token_node_type(tok, source, offset) {
            return Some(JavaScriptParseContext {
                node_type,
                source_range: tok.range,
                parent_nodes: parents,
                confidence: 0.92,
                method: ContextMethod::Ast,
            });
        }
    }

    // Structural classification from the deepest enclosing node.
    let node = tree.node_at(offset)?;
    let node_type = syntax_node_type(node.kind)?;
    Some(JavaScriptParseContext {
        node_type,
        source_range: node.range,
        parent_nodes: parents,
        confidence: 0.9,
        method: ContextMethod::Ast,
    })
}

/// The node type a literal/comment token implies, with the `${ ... }`
/// refinement for template literals. `None` when the token is not a
/// delimiter context (identifiers, operators, punctuation) and the AST
/// should be consulted instead.
fn token_node_type(tok: &Token, source: &str, offset: usize) -> Option<JavaScriptNodeType> {
    match tok.kind {
        TokenKind::Comment => Some(JavaScriptNodeType::Comment),
        TokenKind::String => Some(JavaScriptNodeType::String),
        TokenKind::Regex => Some(JavaScriptNodeType::RegexLiteral),
        TokenKind::Template => {
            if in_template_expression(source, tok.range.start, offset) {
                Some(JavaScriptNodeType::TemplateExpression)
            } else {
                Some(JavaScriptNodeType::TemplateLiteral)
            }
        }
        _ => None,
    }
}

/// Map a syntax node kind onto a context node type. `None` for nodes that
/// do not describe an injection position (so the token fallback can answer).
fn syntax_node_type(kind: SyntaxKind) -> Option<JavaScriptNodeType> {
    match kind {
        // Literals are normally classified at token level; this covers any
        // literal node reached structurally.
        SyntaxKind::StringLit => Some(JavaScriptNodeType::String),
        SyntaxKind::TemplateLit => Some(JavaScriptNodeType::TemplateLiteral),
        SyntaxKind::RegexLit => Some(JavaScriptNodeType::RegexLiteral),
        SyntaxKind::ObjectLit => Some(JavaScriptNodeType::Object),
        SyntaxKind::ArrayLit => Some(JavaScriptNodeType::Array),
        SyntaxKind::Property => Some(JavaScriptNodeType::Property),
        // Anything that yields a value is an expression position.
        SyntaxKind::Ident
        | SyntaxKind::Member
        | SyntaxKind::Call
        | SyntaxKind::New
        | SyntaxKind::Assign
        | SyntaxKind::Binary
        | SyntaxKind::Unary
        | SyntaxKind::Update
        | SyntaxKind::Conditional
        | SyntaxKind::Sequence
        | SyntaxKind::This
        | SyntaxKind::Super
        | SyntaxKind::Spread
        | SyntaxKind::BoolLit
        | SyntaxKind::NullLit
        | SyntaxKind::NumberLit => Some(JavaScriptNodeType::Expression),
        // Statements and declarations: a script-capable but non-expression
        // position.
        SyntaxKind::Script
        | SyntaxKind::VarDecl
        | SyntaxKind::VarDeclarator
        | SyntaxKind::FunctionDecl
        | SyntaxKind::ClassDecl
        | SyntaxKind::FunctionExpr
        | SyntaxKind::ArrowFn
        | SyntaxKind::Block
        | SyntaxKind::ExprStmt
        | SyntaxKind::Return
        | SyntaxKind::If
        | SyntaxKind::For
        | SyntaxKind::While
        | SyntaxKind::Throw
        | SyntaxKind::Try
        | SyntaxKind::Empty
        | SyntaxKind::Param
        | SyntaxKind::Raw => Some(JavaScriptNodeType::Code),
    }
}

/// Strictly enclosing template literals, outermost first. Templates are
/// opaque leaves in the AST, so nesting is read from the token stream —
/// this preserves the parent chain the old token scan produced.
fn enclosing_templates(tree: &SyntaxTree, offset: usize) -> Vec<JavaScriptNodeType> {
    let inner = match tree.tokens.iter().find(|t| t.contains(offset)) {
        Some(t) => t.range,
        None => return Vec::new(),
    };
    tree.tokens
        .iter()
        .filter(|t| {
            t.kind == TokenKind::Template
                && t.range.start < inner.start
                && t.range.end >= inner.end
        })
        .map(|_| JavaScriptNodeType::TemplateLiteral)
        .collect()
}

// ----------------------------------------------------------------------
// Fallback: the original token scan
// ----------------------------------------------------------------------

#[derive(Debug)]
struct JsToken {
    range: SourceRange,
    node_type: JavaScriptNodeType,
}

/// Derive the context-token view from the full token stream. This is the
/// exact set the original context lexer produced — comments, regex literals,
/// strings, templates, and object/array brackets — so the fallback path is
/// unchanged behaviour, not a reimplementation.
fn context_tokens(source: &str) -> Vec<JsToken> {
    crate::parser::js::lex(source)
        .into_iter()
        .filter_map(|t| {
            let node_type = match t.kind {
                TokenKind::Comment => JavaScriptNodeType::Comment,
                TokenKind::Regex => JavaScriptNodeType::RegexLiteral,
                TokenKind::String => JavaScriptNodeType::String,
                TokenKind::Template => JavaScriptNodeType::TemplateLiteral,
                TokenKind::Punct => match t.range.text(source) {
                    "{" => JavaScriptNodeType::Object,
                    "[" => JavaScriptNodeType::Array,
                    _ => return None,
                },
                _ => return None,
            };
            Some(JsToken { range: t.range, node_type })
        })
        .collect()
}

/// The pre-AST behaviour: scan context tokens for the one covering `offset`.
fn token_context(source: &str, offset: usize) -> JavaScriptParseContext {
    let tokens = context_tokens(source);
    for (i, tok) in tokens.iter().enumerate() {
        if !tok.range.contains(offset) {
            continue;
        }
        // Build the parent chain from strictly-enclosing template literals.
        let mut parents = Vec::new();
        for earlier in tokens.iter().take(i) {
            if earlier.node_type == JavaScriptNodeType::TemplateLiteral
                && earlier.range.start < tok.range.start
                && earlier.range.end >= tok.range.end
            {
                parents.push(JavaScriptNodeType::TemplateLiteral);
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn at(src: &str, needle: &str) -> JavaScriptParseContext {
        let off = src.find(needle).expect("needle not found");
        lex_at(src, off)
    }

    #[test]
    fn plain_expression_context() {
        // A bare identifier is an expression position. The AST resolves this
        // where the old token scan could only say Unknown.
        let ctx = at("var x = MARKER;", "MARKER");
        assert_eq!(ctx.node_type, JavaScriptNodeType::Expression);
        assert_eq!(ctx.method, ContextMethod::Ast);
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
        // A comment is a token-level classification the AST does not model,
        // so it still resolves correctly here.
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
        // Inside `${ ... }` the position is an expression position.
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

    #[test]
    fn call_argument_is_an_expression() {
        // The AST resolves the argument position structurally.
        let ctx = at("sink(MARKER);", "MARKER");
        assert_eq!(ctx.node_type, JavaScriptNodeType::Expression);
    }

    #[test]
    fn object_literal_value_is_a_string_context() {
        let ctx = at(r#"var o = { k: "MARKER" };"#, "MARKER");
        assert_eq!(ctx.node_type, JavaScriptNodeType::String);
    }

    #[test]
    fn bare_identifier_in_object_is_an_expression() {
        let ctx = at("var o = { k: MARKER };", "MARKER");
        assert_eq!(ctx.node_type, JavaScriptNodeType::Expression);
    }

    #[test]
    fn fallback_reports_its_method() {
        // No token and no node covers a far-out offset.
        let ctx = lex_at("var x = 1;", 9999);
        assert_eq!(ctx.node_type, JavaScriptNodeType::Unknown);
        assert_eq!(ctx.method, ContextMethod::Fallback);
    }
}
