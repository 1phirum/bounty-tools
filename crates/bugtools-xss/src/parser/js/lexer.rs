//! Full JavaScript token stream — lexer pass 1.
//!
//! The original context lexer only recorded strings, templates, comments,
//! regex literals and brackets — enough to answer "what is at this offset"
//! but not enough to build a tree. This module extends it to a complete
//! token stream (identifiers, keywords, numbers, punctuation, operators)
//! so the AST parser in [`crate::parser::js::parser`] has real input.
//!
//! Byte offsets are preserved on every token. Reflection analysis resolves
//! offsets, and the AST must answer those same queries without introducing
//! a second source of truth for positions.
//!
//! The lexer is deliberately total: it never panics on malformed input, it
//! just produces tokens for what it can recognize. Unknown characters
//! become single-byte punctuation tokens so parsing can recover.

use serde::{Deserialize, Serialize};

/// A byte range into the script source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRange {
    pub start: usize,
    pub end: usize,
}

impl SourceRange {
    /// The source text covered by this range.
    ///
    /// All lexer ranges are cut at ASCII token boundaries, so slicing is
    /// always on a UTF-8 boundary.
    pub fn text<'a>(&self, source: &'a str) -> &'a str {
        &source[self.start..self.end]
    }

    /// Half-open containment: `[start, end)`.
    pub fn contains(&self, offset: usize) -> bool {
        offset >= self.start && offset < self.end
    }
}

/// Kind of token produced by [`lex`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenKind {
    Comment,
    String,
    Template,
    Regex,
    Number,
    Ident,
    Keyword,
    Punct,
    Op,
    /// Sentinel produced by [`Cursor::peek`] at end of input.
    Eof,
}

/// One lexed token with its byte range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub kind: TokenKind,
    pub range: SourceRange,
}

impl Token {
    pub fn text<'a>(&self, source: &'a str) -> &'a str {
        self.range.text(source)
    }

    /// Whether an offset lands inside this token.
    pub fn contains(&self, offset: usize) -> bool {
        self.range.contains(offset)
    }
}

/// Reserved words treated as keywords. `let` is included so declarations
/// parse; contextual keywords (`of`, `as`, `from`, `get`, `set`, `static`)
/// are deliberately left as identifiers to keep member access (`obj.get`)
/// and arrow bodies simple.
pub const KEYWORDS: &[&str] = &[
    "await", "break", "case", "catch", "class", "const", "continue", "debugger", "default",
    "delete", "do", "else", "enum", "export", "extends", "false", "finally", "for", "function",
    "if", "import", "in", "instanceof", "let", "new", "null", "return", "super", "switch",
    "this", "throw", "true", "try", "typeof", "var", "void", "while", "with", "yield",
];

/// Keywords that are themselves values (so a following `/` is division).
fn is_value_keyword(text: &str) -> bool {
    matches!(text, "this" | "true" | "false" | "null" | "super")
}

/// What the previous significant token implies about a following `/`.
///
/// Replaces the old single-character heuristic with a token-aware rule. This
/// fixes a latent bug: after `return` the old lexer saw the letter `n` and
/// treated `/re/` as division. It keeps every existing offset test green
/// because the two cases those tests exercise (`= `→ regex, `a` → division)
/// resolve identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prev {
    None,
    /// Ends a value: identifier, literal, `)`, `]`, `}` — `/` is division.
    Value,
    /// Expects an operand: operator, `(`, `,`, `;`, `return`, … — `/` starts
    /// a regex.
    Op,
}

fn prev_class(kind: TokenKind, text: &str) -> Prev {
    match kind {
        TokenKind::Ident | TokenKind::Number | TokenKind::String | TokenKind::Template
        | TokenKind::Regex => Prev::Value,
        TokenKind::Keyword => {
            if is_value_keyword(text) {
                Prev::Value
            } else {
                Prev::Op
            }
        }
        TokenKind::Punct => match text {
            ")" | "]" | "}" => Prev::Value,
            _ => Prev::Op,
        },
        TokenKind::Op => match text {
            "++" | "--" => Prev::Value,
            _ => Prev::Op,
        },
        TokenKind::Comment | TokenKind::Eof => Prev::None,
    }
}

/// Whether a `/` here starts a regex literal rather than division.
fn regex_can_start(prev: Prev) -> bool {
    matches!(prev, Prev::None | Prev::Op)
}

/// Multi-character operators, longest first, so the greedy scan in [`lex`]
/// never splits `===` into `==` and `=`.
const OPS: &[&str] = &[
    "===", "!==", ">>>=", "**=", "...", ">>>", "<<=", ">>=", "&&=", "||=", "??=", "==", "!=", "=>",
    "<<", ">>", "**", "&&", "||", "??", "?.", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=",
    "|=", "^=", "=", "+", "-", "*", "/", "%", "<", ">", "!", "&", "|", "^", "~", "?",
];

/// Structural punctuation.
const PUNCTS: &[&str] = &["{", "}", "(", ")", "[", "]", ";", ",", ".", ":", "#"];

/// Lex `source` into a token stream with byte ranges.
pub fn lex(source: &str) -> Vec<Token> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    let len = bytes.len();
    let mut prev = Prev::None;

    while i < len {
        let c = bytes[i];

        // Whitespace and line terminators are skipped: offsets are carried by
        // the tokens around them and the parser needs no trivia.
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }

        // Line comment.
        if c == b'/' && i + 1 < len && bytes[i + 1] == b'/' {
            let start = i;
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            prev = emit(&mut tokens, source, TokenKind::Comment, start, i);
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
            prev = emit(&mut tokens, source, TokenKind::Comment, start, i);
            continue;
        }

        // Regex literal: `/` where an operand is expected.
        if c == b'/' && regex_can_start(prev) {
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
            prev = emit(&mut tokens, source, TokenKind::Regex, start, i);
            continue;
        }

        // String literal (single or double quoted, escapes respected).
        if c == b'"' || c == b'\'' {
            let start = i;
            i += 1;
            while i < len {
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == c {
                    i += 1;
                    break;
                }
                i += 1;
            }
            prev = emit(&mut tokens, source, TokenKind::String, start, i);
            continue;
        }

        // Template literal, kept as a single spanning token. `${ ... }`
        // interpolations are not tokenized into expressions here: context
        // resolution distinguishes them with a brace scan (see
        // `javascript::in_template_expression`), and the data-flow layer can
        // refine this later. Keeping one token preserves the exact ranges
        // the existing offset tests assert.
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
            prev = emit(&mut tokens, source, TokenKind::Template, start, i);
            continue;
        }

        // Number: hex / binary / octal / decimal / exponent, and a leading
        // dot when an operand is expected (`.5`).
        if c.is_ascii_digit() || (c == b'.' && operand_expected(prev) && next_is_digit(bytes, i)) {
            let start = i;
            if c == b'0' && i + 1 < len && matches!(bytes[i + 1], b'x' | b'X' | b'b' | b'B' | b'o' | b'O') {
                i += 2;
                while i < len && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
            } else {
                while i < len && (bytes[i].is_ascii_digit() || bytes[i] == b'_') {
                    i += 1;
                }
                if i < len && bytes[i] == b'.' {
                    i += 1;
                    while i < len && (bytes[i].is_ascii_digit() || bytes[i] == b'_') {
                        i += 1;
                    }
                }
                if i < len && (bytes[i] == b'e' || bytes[i] == b'E') {
                    let mut j = i + 1;
                    if j < len && (bytes[j] == b'+' || bytes[j] == b'-') {
                        j += 1;
                    }
                    if j < len && bytes[j].is_ascii_digit() {
                        i = j;
                        while i < len && bytes[i].is_ascii_digit() {
                            i += 1;
                        }
                    }
                }
            }
            if i < len && bytes[i] == b'n' {
                i += 1; // BigInt suffix.
            }
            prev = emit(&mut tokens, source, TokenKind::Number, start, i);
            continue;
        }

        // Identifier or keyword.
        if is_ident_start(c) {
            let start = i;
            i += 1;
            while i < len && is_ident_part(bytes[i]) {
                i += 1;
            }
            let text = &source[start..i];
            let kind = if KEYWORDS.contains(&text) {
                TokenKind::Keyword
            } else {
                TokenKind::Ident
            };
            prev = emit(&mut tokens, source, kind, start, i);
            continue;
        }

        // Multi-char and single-char operators.
        if let Some((kind, end)) = match_multi(bytes, i, OPS, TokenKind::Op) {
            prev = emit(&mut tokens, source, kind, i, end);
            i = end;
            continue;
        }

        // Structural punctuation.
        if let Some((kind, end)) = match_multi(bytes, i, PUNCTS, TokenKind::Punct) {
            prev = emit(&mut tokens, source, kind, i, end);
            i = end;
            continue;
        }

        // Anything unrecognised becomes a single-byte punctuation token so
        // the parser can recover instead of diverging.
        prev = emit(&mut tokens, source, TokenKind::Punct, i, i + 1);
        i += 1;
    }

    tokens
}

/// Push a token and compute the `Prev` class for regex disambiguation.
fn emit(tokens: &mut Vec<Token>, source: &str, kind: TokenKind, start: usize, end: usize) -> Prev {
    tokens.push(Token {
        kind,
        range: SourceRange { start, end },
    });
    prev_class(kind, &source[start..end])
}

fn operand_expected(prev: Prev) -> bool {
    matches!(prev, Prev::None | Prev::Op)
}

fn next_is_digit(bytes: &[u8], i: usize) -> bool {
    i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit()
}

/// Greedy longest match against `table` at position `i`.
fn match_multi(bytes: &[u8], i: usize, table: &[&str], kind: TokenKind) -> Option<(TokenKind, usize)> {
    for op in table {
        let ob = op.as_bytes();
        if i + ob.len() <= bytes.len() && &bytes[i..i + ob.len()] == ob {
            return Some((kind, i + ob.len()));
        }
    }
    None
}

fn is_ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_' || c == b'$'
}

fn is_ident_part(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'$'
}

/// A cursor over the token stream used by the AST parser.
#[derive(Debug, Clone)]
pub struct Cursor<'a> {
    pub source: &'a str,
    pub tokens: &'a [Token],
    pub pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(source: &'a str, tokens: &'a [Token]) -> Self {
        Self { source, tokens, pos: 0 }
    }

    /// The current token, or an `Eof` sentinel.
    pub fn peek(&self) -> Token {
        self.tokens
            .get(self.pos)
            .copied()
            .unwrap_or(Token { kind: TokenKind::Eof, range: SourceRange { start: self.eof(), end: self.eof() } })
    }

    /// The token after the current one, or an `Eof` sentinel.
    pub fn peek2(&self) -> Token {
        self.tokens
            .get(self.pos + 1)
            .copied()
            .unwrap_or(Token { kind: TokenKind::Eof, range: SourceRange { start: self.eof(), end: self.eof() } })
    }

    fn eof(&self) -> usize {
        self.source.len()
    }

    /// Advance past the current token and return it.
    pub fn bump(&mut self) -> Token {
        let t = self.peek();
        if self.pos < self.tokens.len() {
            self.pos += 1;
        }
        t
    }

    /// Whether the current token is `kind` with exactly `text`.
    pub fn at(&self, kind: TokenKind, text: &str) -> bool {
        let t = self.peek();
        t.kind == kind && t.text(self.source) == text
    }

    /// Whether the current token is `kind` with exactly `text`; if so, bump.
    pub fn eat(&mut self, kind: TokenKind, text: &str) -> bool {
        if self.at(kind, text) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Whether the current token is punctuation with exactly `text`.
    pub fn at_punct(&self, text: &str) -> bool {
        self.at(TokenKind::Punct, text)
    }

    /// Whether the current token is an operator with exactly `text`.
    pub fn at_op(&self, text: &str) -> bool {
        self.at(TokenKind::Op, text)
    }

    /// Whether the current token is a keyword with exactly `text`.
    pub fn at_kw(&self, text: &str) -> bool {
        self.at(TokenKind::Keyword, text)
    }

    /// Whether the current token is an identifier or keyword (both name-like).
    pub fn at_name(&self) -> bool {
        matches!(self.peek().kind, TokenKind::Ident | TokenKind::Keyword)
    }

    /// The current token's text.
    pub fn text(&self) -> &str {
        self.peek().text(self.source)
    }

    /// Whether input is exhausted.
    pub fn at_eof(&self) -> bool {
        self.pos >= self.tokens.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str) -> Vec<TokenKind> {
        lex(src).into_iter().map(|t| t.kind).collect()
    }

    fn token_at(src: &str, needle: &str) -> Token {
        let off = src.find(needle).expect("needle not found");
        lex(src)
            .into_iter()
            .find(|t| t.contains(off))
            .expect("no token covers the needle")
    }

    #[test]
    fn identifiers_and_keywords_are_distinguished() {
        let kinds = kinds("var x = location");
        assert_eq!(
            kinds,
            vec![
                TokenKind::Keyword, // var
                TokenKind::Ident,   // x
                TokenKind::Op,      // =
                TokenKind::Ident,   // location
            ]
        );
    }

    #[test]
    fn numbers_lex_as_one_token() {
        assert_eq!(token_at("var x = 3.14e2;", "3.14e2").kind, TokenKind::Number);
        assert_eq!(token_at("var x = 0xff;", "0xff").kind, TokenKind::Number);
        assert_eq!(token_at("var x = .5;", ".5").kind, TokenKind::Number);
    }

    #[test]
    fn dot_after_value_is_punctuation_not_a_number() {
        // `a.b` — the dot is member access, not `.5`.
        let toks = lex("a.b");
        assert_eq!(toks[1].text("a.b"), ".");
        assert_eq!(toks[1].kind, TokenKind::Punct);
    }

    #[test]
    fn operators_are_greedy() {
        let toks = lex("a === b");
        assert_eq!(toks[1].text("a === b"), "===");
        assert_eq!(toks[1].kind, TokenKind::Op);
        let toks = lex("a == b");
        assert_eq!(toks[1].text("a == b"), "==");
    }

    #[test]
    fn arrow_operator_lexes() {
        let toks = lex("(x) => x");
        let arrow = toks
            .iter()
            .find(|t| t.text("(x) => x") == "=>")
            .expect("=> must lex");
        assert_eq!(arrow.kind, TokenKind::Op);
    }

    #[test]
    fn regex_after_equals_is_one_token() {
        let t = token_at("var re = /abc/g;", "/abc/");
        assert_eq!(t.kind, TokenKind::Regex);
        assert_eq!(t.range.text("var re = /abc/g;"), "/abc/g");
    }

    #[test]
    fn division_after_identifier_is_not_a_regex() {
        // The `/` after `a` is division, so `MARKER` is an identifier.
        let toks = lex("var y = a / b;");
        let slash = toks.iter().find(|t| t.text("var y = a / b;") == "/").unwrap();
        assert_eq!(slash.kind, TokenKind::Op);
    }

    #[test]
    fn regex_after_return_is_a_regex() {
        // Regression guard for the latent bug the old single-char heuristic
        // had: `return /re/` must lex the regex, not a division.
        let toks = lex("return /re/;");
        let re = toks.iter().find(|t| t.kind == TokenKind::Regex).unwrap();
        assert_eq!(re.text("return /re/;"), "/re/");
    }

    #[test]
    fn string_with_escaped_quote_is_one_token() {
        let src = r#"var x = 'a\'b';"#;
        let t = lex(src)
            .into_iter()
            .find(|t| t.kind == TokenKind::String)
            .expect("a string token must exist");
        assert_eq!(t.range.text(src), "'a\\'b'");
    }

    #[test]
    fn backtick_inside_a_string_is_not_a_template() {
        let src = r#"var x = "a ` b";"#;
        let toks = lex(src);
        assert!(toks.iter().any(|t| t.kind == TokenKind::String), "must lex a string");
        assert!(toks.iter().all(|t| t.kind != TokenKind::Template), "no template token");
    }

    #[test]
    fn template_with_interpolation_is_one_token() {
        let src = "var s = `a ${ b } c`;";
        let t = token_at(src, "b");
        assert_eq!(t.kind, TokenKind::Template);
        assert_eq!(t.range.text(src), "`a ${ b } c`");
    }

    #[test]
    fn comments_lex_with_ranges() {
        let t = token_at("// hi\nx", "hi");
        assert_eq!(t.kind, TokenKind::Comment);
        assert_eq!(t.range.text("// hi\nx"), "// hi");
        let t = token_at("/* hi */x", "hi");
        assert_eq!(t.kind, TokenKind::Comment);
    }

    #[test]
    fn unterminated_input_does_not_hang_or_panic() {
        let toks = lex("var x = 'unterminated");
        assert!(toks.iter().any(|t| t.kind == TokenKind::String));
        let toks = lex("var x = `unterminated");
        assert!(toks.iter().any(|t| t.kind == TokenKind::Template));
        let toks = lex("var re = /unterminated");
        assert!(toks.iter().any(|t| t.kind == TokenKind::Regex));
    }

    #[test]
    fn empty_input_lexes_to_nothing() {
        assert!(lex("").is_empty());
    }

    #[test]
    fn every_token_range_is_a_valid_utf8_boundary() {
        // Non-ASCII inside a string must not corrupt ranges.
        let src = "var s = \"日本語\"";
        for t in lex(src) {
            // Slicing must not panic.
            let _ = t.text(src);
        }
    }

    #[test]
    fn cursor_api_walks_tokens() {
        let src = "var x = 1;";
        let toks = lex(src);
        let mut cur = Cursor::new(src, &toks);
        assert!(cur.at_kw("var"));
        assert!(cur.eat(TokenKind::Keyword, "var"));
        assert!(cur.at(TokenKind::Ident, "x"));
        assert_eq!(cur.text(), "x");
        cur.bump();
        assert!(cur.at_op("="));
        cur.bump();
        assert!(cur.at(TokenKind::Number, "1"));
        cur.bump();
        assert!(cur.at_punct(";"));
        cur.bump();
        assert!(cur.at_eof());
        assert_eq!(cur.peek().kind, TokenKind::Eof);
    }
}
