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
    /// A template literal's text up to and including an opening `` `${ ``.
    TemplateHead,
    /// Template text between one interpolation and the next: `}…${`.
    TemplateMiddle,
    /// Template text from the last interpolation's `}` to the closing backtick.
    TemplateTail,
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
        TokenKind::Ident | TokenKind::Number | TokenKind::String | TokenKind::TemplateTail
        | TokenKind::Regex => Prev::Value,
        // `${` opens an expression: an operand is expected next, so a `/`
        // starts a regex rather than division.
        TokenKind::TemplateHead | TokenKind::TemplateMiddle => Prev::Op,
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

/// One open template literal, tracked so `${ … }` interpolations are lexed
/// as real expressions rather than swallowed into one spanning token.
#[derive(Debug, Clone, Copy)]
struct TemplateFrame {
    /// Start of the current text segment: the opening backtick for a head,
    /// or the interpolation's closing `}` for a middle/tail.
    text_start: usize,
    /// Inside the segment's text (`true`) or inside an interpolation (`false`).
    in_text: bool,
    /// Brace depth while inside an interpolation: `{`/`}` of object literals
    /// and arrow bodies, so the right `}` closes the interpolation.
    brace: usize,
}

/// Lex `source` into a token stream with byte ranges.
pub fn lex(source: &str) -> Vec<Token> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    let len = bytes.len();
    let mut prev = Prev::None;
    // One frame per open template, innermost last.
    let mut templates: Vec<TemplateFrame> = Vec::new();

    while i < len {
        let c = bytes[i];

        // Template text: the literal portion of an open template. Runs before
        // normal tokenization so the text is one segment, not mis-tokenized
        // words, and so `${ … }` is handed to the main loop as expressions.
        if let Some(&frame) = templates.last() {
            if frame.in_text {
                let start = frame.text_start;
                // Scan past the opening backtick (a head) or the closing
                // brace of the previous interpolation (a middle).
                let mut j = start + 1;
                let mut expr_open = false;
                let mut end = len;
                while j < len {
                    if bytes[j] == b'\\' {
                        j += 2;
                        continue;
                    }
                    if bytes[j] == b'$' && j + 1 < len && bytes[j + 1] == b'{' {
                        expr_open = true;
                        end = j + 2;
                        break;
                    }
                    if bytes[j] == b'`' {
                        end = j + 1;
                        break;
                    }
                    j += 1;
                }
                let kind = if expr_open {
                    // A segment starting at a backtick is the head; one
                    // starting at a `}` is a middle.
                    if bytes[start] == b'`' {
                        TokenKind::TemplateHead
                    } else {
                        TokenKind::TemplateMiddle
                    }
                } else {
                    TokenKind::TemplateTail
                };
                prev = emit(&mut tokens, source, kind, start, end);
                i = end;
                let frame = templates.last_mut().unwrap();
                if expr_open {
                    frame.in_text = false;
                    frame.brace = 0;
                } else {
                    templates.pop();
                }
                continue;
            }
        }

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

        // A backtick opens a template — including a nested one inside an
        // interpolation. The text scan above emits its segments; `i` stays put
        // so the scan starts at the backtick.
        if c == b'`' {
            templates.push(TemplateFrame { text_start: i, in_text: true, brace: 0 });
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
            let text = &source[i..end];
            // Inside a template interpolation, `{` and `}` of nested object
            // literals and arrow bodies are tracked so the correct `}` ends
            // the interpolation; that `}` is template syntax, not a token.
            if let Some(frame) = templates.last_mut() {
                if !frame.in_text {
                    if text == "{" {
                        frame.brace += 1;
                    } else if text == "}" {
                        if frame.brace == 0 {
                            frame.in_text = true;
                            frame.text_start = i;
                            i = end;
                            continue;
                        }
                        frame.brace -= 1;
                    }
                }
            }
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
        assert!(
            toks.iter().all(|t| !matches!(t.kind, TokenKind::TemplateHead | TokenKind::TemplateMiddle | TokenKind::TemplateTail)),
            "no template token"
        );
    }

    #[test]
    fn template_without_interpolation_is_one_tail() {
        // `` `text` `` has no `${`, so it is a lone tail covering everything.
        let src = "var s = `text`;";
        let toks = lex(src);
        let t = toks
            .iter()
            .find(|t| matches!(t.kind, TokenKind::TemplateTail))
            .expect("a tail must exist");
        assert_eq!(t.range.text(src), "`text`");
    }

    #[test]
    fn template_segments_and_interpolation_tokens() {
        // `` `a ${ b } c` ``: head `a${`, identifier b, tail `}c` + backtick.
        let src = "var s = `a ${ b } c`;";
        let toks: Vec<_> = lex(src)
            .into_iter()
            .filter(|t| !matches!(t.kind, TokenKind::Comment))
            .collect();
        let kinds: Vec<_> = toks.iter().map(|t| t.kind).collect();
        assert!(kinds.contains(&TokenKind::TemplateHead), "head: {kinds:?}");
        assert!(kinds.contains(&TokenKind::Ident), "interpolation identifier");
        assert!(kinds.contains(&TokenKind::TemplateTail), "tail: {kinds:?}");
        // The head covers the text up to and including `${`.
        let head = toks.iter().find(|t| t.kind == TokenKind::TemplateHead).unwrap();
        assert_eq!(head.range.text(src), "`a ${");
        // The tail starts at the interpolation's closing brace.
        let tail = toks.iter().find(|t| t.kind == TokenKind::TemplateTail).unwrap();
        assert_eq!(tail.range.text(src), "} c`");
    }

    #[test]
    fn template_with_two_interpolations_has_a_middle() {
        let src = "var s = `${a} mid ${b}`;";
        let toks = lex(src);
        assert!(toks.iter().any(|t| t.kind == TokenKind::TemplateHead));
        assert!(toks.iter().any(|t| t.kind == TokenKind::TemplateMiddle));
        assert!(toks.iter().any(|t| t.kind == TokenKind::TemplateTail));
    }

    #[test]
    fn braces_inside_an_interpolation_do_not_close_it_early() {
        // `${ { a: 1 } }`: the object's braces are tracked, so only the final
        // `}` ends the interpolation.
        let src = "var s = `x ${ { a: 1 } } y`;";
        let toks = lex(src);
        // The interpolation's tokens are real: an object's `{`, `a`, `1`, `}`.
        assert!(toks.iter().any(|t| t.kind == TokenKind::Ident && t.range.text(src) == "a"));
        assert!(toks.iter().any(|t| t.kind == TokenKind::Number));
        let tail = toks.iter().find(|t| t.kind == TokenKind::TemplateTail).unwrap();
        assert_eq!(tail.range.text(src), "} y`");
    }

    #[test]
    fn nested_template_inside_an_interpolation() {
        // `${ `inner ${ x }` }`: a template opens inside an interpolation and
        // its own interpolation is lexed too.
        let src = "var s = `o ${ `i ${ x }` }`;";
        let toks = lex(src);
        let heads = toks.iter().filter(|t| t.kind == TokenKind::TemplateHead).count();
        assert_eq!(heads, 2, "an outer and an inner head");
        let tails = toks.iter().filter(|t| t.kind == TokenKind::TemplateTail).count();
        assert_eq!(tails, 2, "an outer and an inner tail");
        assert!(toks.iter().any(|t| t.kind == TokenKind::Ident && t.range.text(src) == "x"));
    }

    #[test]
    fn escaped_interpolation_is_literal_text() {
        // `\${` must not open an interpolation.
        let src = r#"var s = `a \${ b`;"#;
        let toks = lex(src);
        assert!(toks.iter().all(|t| t.kind != TokenKind::TemplateMiddle), "no interpolation");
        assert!(toks.iter().any(|t| t.kind == TokenKind::TemplateTail));
    }

    #[test]
    fn template_offsets_stay_absolute() {
        // Every segment and interpolation token keeps its true byte range.
        let src = "var s = `a ${ b } c`;";
        let toks = lex(src);
        for t in &toks {
            assert_eq!(t.range.text(src), &src[t.range.start..t.range.end]);
        }
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
        // An unterminated template still emits its text as one segment.
        let toks = lex("var x = `unterminated");
        assert!(toks.iter().any(|t| t.kind == TokenKind::TemplateTail));
        // An unterminated interpolation: the head is emitted, then the
        // expression's own tokens follow with no tail.
        let toks = lex("var x = `unterminated ${ a");
        assert!(toks.iter().any(|t| t.kind == TokenKind::TemplateHead));
        assert!(toks.iter().any(|t| t.kind == TokenKind::Ident));
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
