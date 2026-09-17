//! Real parsing layer: HTML structure and JavaScript program analysis.
//!
//! Replaces the character-window heuristic and quote-parity logic with
//! structure-aware parsing, keeping the heuristic only as a fallback.
//!
//! The JavaScript side is layered: [`js::lexer`] produces a full token
//! stream, [`js::parser`] builds an offset-annotated syntax tree, and
//! [`js::scope`] builds the lexical scope graph. [`javascript`] resolves an
//! offset to a context using that tree, falling back to the token scan.

pub mod html;
pub mod javascript;
pub mod js;

pub use html::{
    parse_at, ContextMethod, HtmlNodeType, HtmlParseContext, HtmlParserState, QuoteType,
};
pub use javascript::{lex_at, JavaScriptNodeType, JavaScriptParseContext, SourceRange};
pub use js::{parse_script, ScopeGraph, SyntaxKind, SyntaxTree, Token, TokenKind};
