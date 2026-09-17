//! JavaScript program-analysis layer.
//!
//! Built in three passes, each preserving byte offsets:
//!
//! 1. [`lexer`] — a full token stream (identifiers, keywords, numbers,
//!    punctuation, operators) supersetting the original context lexer.
//! 2. [`parser`] — a best-effort recursive-descent parser producing an
//!    offset-annotated syntax tree ([`ast`]).
//! 3. [`scope`] — a lexical scope graph with bindings and resolution,
//!    the foundation the data-flow taint layer will consume.
//!
//! The layer is total: malformed input degrades to raw nodes rather than
//! failing, so the context query in [`crate::parser::javascript`] always has
//! an answer.

pub mod ast;
pub mod lexer;
pub mod parser;
pub mod scope;

pub use ast::{NodeId, SyntaxKind, SyntaxNode, SyntaxTree};
pub use lexer::{lex, Cursor, SourceRange, Token, TokenKind};
pub use parser::parse_script;
pub use scope::{Binding, BindingKind, Scope, ScopeGraph, ScopeId, ScopeKind};
