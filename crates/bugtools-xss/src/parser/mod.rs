//! Real parsing layer: HTML structure and JavaScript tokens.
//!
//! Replaces the character-window heuristic and quote-parity logic with
//! structure-aware parsing, keeping the heuristic only as a fallback.

pub mod html;
pub mod javascript;

pub use html::{
    parse_at, ContextMethod, HtmlNodeType, HtmlParseContext, HtmlParserState, QuoteType,
};
pub use javascript::{lex_at, JavaScriptNodeType, JavaScriptParseContext, SourceRange};
