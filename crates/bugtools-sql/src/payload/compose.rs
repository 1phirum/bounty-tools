//! Context-aware payload composition engine (P0 brief §10, §17, §35).
//!
//! Composes candidates from independent concerns — technique, clause
//! strategy, dialect, boundary, representation, mutation — rather than
//! storing literal strings. Nothing here is `<basic payload>`; a candidate
//! is generated because the evidence justifies it.

use crate::detection::DbmsFamily;
use crate::payload::boundary::{Boundary, QuoteMode};
use crate::payload::generate::{render_sql, LogicalTest};
use crate::payload::transform::{
    variants_for, RepresentationContext, TransformKind, TransformationTrace,
};
use crate::types::ProbeType;
use serde::{Deserialize, Serialize};

/// A clause-specific rendering strategy. The same logical test is expressed
/// differently depending on where the input lands in the statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClauseStrategy {
    Where,
    Having,
    OrderBy,
    GroupBy,
    Join,
    Like,
    LimitOffset,
    InsertValues,
    UpdateSet,
    DeleteWhere,
    SelectExpression,
    FunctionArgument,
    /// Unknown position: use the most portable WHERE-style expression.
    Generic,
}

impl ClauseStrategy {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Where => "WHERE",
            Self::Having => "HAVING",
            Self::OrderBy => "ORDER BY",
            Self::GroupBy => "GROUP BY",
            Self::Join => "JOIN",
            Self::Like => "LIKE",
            Self::LimitOffset => "LIMIT/OFFSET",
            Self::InsertValues => "INSERT VALUES",
            Self::UpdateSet => "UPDATE SET",
            Self::DeleteWhere => "DELETE WHERE",
            Self::SelectExpression => "SELECT expression",
            Self::FunctionArgument => "function argument",
            Self::Generic => "unknown",
        }
    }

    /// Render a boolean/binary logical test for this clause.
    ///
    /// ORDER BY and LIMIT/OFFSET cannot take a boolean predicate, so the
    /// engine uses different constructs there — this is the point of
    /// clause-awareness.
    pub fn render_conditional(&self, truth: bool) -> String {
        match self {
            // Boolean-expressible positions.
            Self::Where | Self::Having | Self::Join | Self::DeleteWhere | Self::Generic => {
                if truth { "AND 1=1".into() } else { "AND 1=2".into() }
            }
            // Pattern positions use a wildcard/tautology through LIKE.
            Self::Like => {
                if truth { "OR 1=1-- ".into() } else { "OR 1=2-- ".into() }
            }
            // ORDER BY takes an expression, not a predicate. Use a sort key.
            Self::OrderBy => {
                if truth { ",(SELECT 1)".into() } else { ",(SELECT 1/0)".into() }
            }
            Self::GroupBy => {
                if truth { " AND 1=1 GROUP BY 1".into() } else { " AND 1=2 GROUP BY 1".into() }
            }
            // LIMIT/OFFSET takes integers; a conditional subquery is the
            // only portable way to vary behaviour.
            Self::LimitOffset => {
                if truth { " AND 1=1".into() } else { " AND 1=(SELECT 2)".into() }
            }
            Self::InsertValues | Self::UpdateSet | Self::SelectExpression | Self::FunctionArgument => {
                if truth { " AND 1=1".into() } else { " AND 1=2".into() }
            }
        }
    }

    /// Whether a STACKED statement is even conceptually meaningful here.
    /// It is not inside an expression position (SELECT/WHERE operand).
    pub fn supports_stacked(&self) -> bool {
        matches!(self, Self::Generic)
    }
}

/// Evidence gathered so far, which drives escalation.
#[derive(Debug, Clone, Default)]
pub struct EvidenceSummary {
    /// The error technique produced a DBMS signature.
    pub error_signal: bool,
    /// The boolean pair produced a repeatable divergence.
    pub boolean_signal: bool,
    /// Timing showed a statistically separated distribution.
    pub timing_signal: bool,
    /// A DBMS was fingerprinted.
    pub dbms_known: bool,
    /// The edge layer blocked at least one probe.
    pub waf_interference: bool,
    /// Number of candidates already executed against this parameter.
    pub attempts_so_far: u32,
}

/// How aggressive the generator may be, derived from evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationTier {
    /// No signal yet: cheapest discriminating tests only.
    Recon,
    /// A signal appeared: confirm it independently.
    Confirm,
    /// Confirmed: explore context, dialect and representation breadth.
    Explore,
}

impl EscalationTier {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Recon => "recon",
            Self::Confirm => "confirm",
            Self::Explore => "explore",
        }
    }
}

/// Decide the escalation tier from accumulated evidence.
///
/// This is the rule that prevents the engine blasting every technique at
/// every parameter: with no signal it stays cheap; only corroborated
/// signals unlock the expensive breadth.
pub fn decide_tier(evidence: &EvidenceSummary) -> EscalationTier {
    let strong_signals = [
        evidence.error_signal,
        evidence.boolean_signal,
        evidence.timing_signal,
    ]
    .iter()
    .filter(|s| **s)
    .count();

    if strong_signals >= 2 {
        EscalationTier::Explore
    } else if strong_signals == 1 {
        EscalationTier::Confirm
    } else {
        EscalationTier::Recon
    }
}

/// Techniques to attempt at a tier, in order.
pub fn techniques_for(tier: EscalationTier, has_delay_capability: bool) -> Vec<ProbeType> {
    match tier {
        EscalationTier::Recon => {
            // Cheapest, highest-information tests first.
            vec![ProbeType::ErrorInjection, ProbeType::BooleanBlind]
        }
        EscalationTier::Confirm => {
            let mut v = vec![ProbeType::BooleanBlind, ProbeType::ErrorInjection];
            if has_delay_capability {
                v.push(ProbeType::TimingProbe);
            }
            v
        }
        EscalationTier::Explore => {
            let mut v = vec![
                ProbeType::BooleanBlind,
                ProbeType::ErrorInjection,
                ProbeType::UnionBased,
                ProbeType::ClauseVariant,
            ];
            if has_delay_capability {
                v.push(ProbeType::TimingProbe);
            }
            v
        }
    }
}

/// A fully composed, executable candidate with its complete provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposedCandidate {
    pub id: uuid::Uuid,
    pub technique: ProbeType,
    pub clause: ClauseStrategy,
    pub logical_test: String,
    /// The SQL after dialect rendering, before boundary wrapping.
    pub sql: String,
    /// The final string to place at the injection point.
    pub rendered: String,
    pub boundary: Boundary,
    pub trace: TransformationTrace,
    pub dialect: Option<String>,
    pub expected_dbms: Option<DbmsFamily>,
    /// The tier that produced this candidate.
    pub tier: EscalationTier,
    /// Why this candidate exists — shown in the UI so a test is never opaque.
    pub rationale: String,
}

/// Inputs to composition.
#[derive(Debug, Clone)]
pub struct ComposeContext {
    pub clause: ClauseStrategy,
    pub quote_mode: QuoteMode,
    pub dbms: Option<DbmsFamily>,
    pub representation: RepresentationContext,
    pub original_value: String,
    /// Whether the WAF blocked earlier probes (adds representation breadth).
    pub waf_interference: bool,
}

/// Compose the full candidate set for one technique at one tier.
pub fn compose_for(
    technique: ProbeType,
    ctx: &ComposeContext,
    tier: EscalationTier,
    seconds: u32,
) -> Vec<ComposedCandidate> {
    let mut out = Vec::new();

    // Representation variants: identity first, then (if the WAF interfered
    // or we are exploring) the decoder-differentiating variants.
    let mut rep_variants = variants_for(ctx.representation);
    if !(ctx.waf_interference || tier == EscalationTier::Explore) {
        rep_variants.truncate(1);
    }

    let boundaries = crate::payload::boundary::candidates_for(ctx.quote_mode);

    // The logical tests this technique needs.
    let tests: Vec<(LogicalTest, &str)> = match technique {
        ProbeType::BooleanBlind => vec![
            (LogicalTest::AlwaysTrue, "true condition"),
            (LogicalTest::AlwaysFalse, "false condition"),
        ],
        ProbeType::ErrorInjection => vec![(LogicalTest::SyntaxBreak, "elicit a parser error")],
        ProbeType::TimingProbe => vec![(
            LogicalTest::TimeDelay { seconds },
            "conditional delay",
        )],
        ProbeType::UnionBased => (1..=3)
            .map(|c| (LogicalTest::UnionProbe { columns: c }, "probe UNION column count"))
            .collect(),
        ProbeType::ClauseVariant => vec![
            (LogicalTest::AlwaysTrue, "clause-position probe"),
            (LogicalTest::StackedMarker, "stacked-statement detection"),
        ],
        ProbeType::SyntaxFeature => vec![(LogicalTest::SyntaxBreak, "syntax feature probe")],
        ProbeType::Baseline => Vec::new(),
    };

    for (test, test_label) in tests {
        // Clause-aware rendering: for boolean/conditional tests, the clause
        // strategy decides the actual expression; otherwise the general
        // dialect renderer applies.
        let base_sql = match (&test, technique) {
            (LogicalTest::AlwaysTrue, _) if technique != ProbeType::UnionBased => {
                ctx.clause.render_conditional(true)
            }
            (LogicalTest::AlwaysFalse, _) if technique != ProbeType::UnionBased => {
                ctx.clause.render_conditional(false)
            }
            _ => render_sql(&test, ctx.dbms),
        };

        // A stacked marker only makes sense where a second statement could
        // exist; skip it for expression positions rather than emitting a
        // payload we know cannot work.
        if matches!(test, LogicalTest::StackedMarker) && !ctx.clause.supports_stacked() {
            continue;
        }

        for boundary in &boundaries {
            let wrapped = boundary.render(&base_sql);
            for variant in &rep_variants {
                let mut trace = TransformationTrace::new(&wrapped);
                for step in variant {
                    trace = trace.apply(*step);
                }

                let rationale = build_rationale(
                    technique, test_label, ctx, tier, boundary, variant, seconds,
                );

                out.push(ComposedCandidate {
                    id: uuid::Uuid::new_v4(),
                    technique,
                    clause: ctx.clause,
                    logical_test: format!("{test:?}"),
                    sql: base_sql.clone(),
                    rendered: trace.final_representation.clone(),
                    boundary: boundary.clone(),
                    trace,
                    dialect: ctx.dbms.map(|d| format!("{d:?}")),
                    expected_dbms: ctx.dbms,
                    tier,
                    rationale,
                });
            }
        }
    }

    out
}

/// Build a human explanation of why a candidate exists.
fn build_rationale(
    technique: ProbeType,
    test_label: &str,
    ctx: &ComposeContext,
    tier: EscalationTier,
    boundary: &Boundary,
    variant: &[TransformKind],
    seconds: u32,
) -> String {
    let mut parts = vec![format!(
        "{test_label} via {:?} in a {} {} context",
        technique,
        ctx.clause.label(),
        match ctx.quote_mode {
            QuoteMode::None => "numeric",
            QuoteMode::Single => "single-quoted",
            QuoteMode::Double => "double-quoted",
            QuoteMode::Backtick => "backtick-quoted",
            QuoteMode::Bracket => "bracket-quoted",
        }
    )];
    if let Some(dbms) = ctx.dbms {
        parts.push(format!("rendered for {dbms:?}"));
    } else {
        parts.push("DBMS unknown — portable form".into());
    }
    if boundary.paren_depth > 0 {
        parts.push(format!("closes {} paren level(s)", boundary.paren_depth));
    }
    if !variant.is_empty() {
        parts.push(format!(
            "representation: {}",
            variant
                .iter()
                .map(|t| t.label())
                .collect::<Vec<_>>()
                .join("+")
        ));
    }
    if ctx.waf_interference {
        parts.push("representation breadth widened after edge interference".into());
    }
    parts.push(format!("tier: {}", tier.label()));
    if matches!(technique, ProbeType::TimingProbe) {
        parts.push(format!("{seconds}s delay, requires statistical separation"));
    }
    parts.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ComposeContext {
        ComposeContext {
            clause: ClauseStrategy::Where,
            quote_mode: QuoteMode::Single,
            dbms: Some(DbmsFamily::PostgreSQL),
            representation: RepresentationContext::QueryValue,
            original_value: "1".into(),
            waf_interference: false,
        }
    }

    #[test]
    fn recon_tier_is_cheap() {
        let techniques = techniques_for(EscalationTier::Recon, true);
        assert!(techniques.len() <= 2, "recon must stay cheap");
        assert!(!techniques.contains(&ProbeType::UnionBased));
    }

    #[test]
    fn one_signal_confirms_two_signal_explores() {
        let mut e = EvidenceSummary::default();
        assert_eq!(decide_tier(&e), EscalationTier::Recon);
        e.error_signal = true;
        assert_eq!(decide_tier(&e), EscalationTier::Confirm);
        e.boolean_signal = true;
        assert_eq!(decide_tier(&e), EscalationTier::Explore);
    }

    #[test]
    fn explore_tier_adds_union_and_clause() {
        let techniques = techniques_for(EscalationTier::Explore, true);
        assert!(techniques.contains(&ProbeType::UnionBased));
        assert!(techniques.contains(&ProbeType::ClauseVariant));
    }

    #[test]
    fn no_delay_capability_drops_timing() {
        let techniques = techniques_for(EscalationTier::Explore, false);
        assert!(!techniques.contains(&ProbeType::TimingProbe));
    }

    #[test]
    fn clause_strategy_changes_the_expression() {
        // ORDER BY cannot take a boolean predicate.
        let order = ClauseStrategy::OrderBy.render_conditional(true);
        let where_ = ClauseStrategy::Where.render_conditional(true);
        assert_ne!(order, where_);
        assert!(order.contains("SELECT"));
    }

    #[test]
    fn order_by_does_not_use_boolean_predicate() {
        assert!(!ClauseStrategy::OrderBy.render_conditional(true).contains("1=1"));
    }

    #[test]
    fn stacked_skipped_for_expression_positions() {
        let mut c = ctx();
        c.clause = ClauseStrategy::SelectExpression;
        let candidates = compose_for(ProbeType::ClauseVariant, &c, EscalationTier::Explore, 5);
        assert!(
            !candidates.iter().any(|x| x.logical_test.contains("StackedMarker")),
            "stacked marker emitted for a SELECT expression position"
        );
    }

    #[test]
    fn recon_uses_only_identity_representation() {
        let candidates = compose_for(ProbeType::BooleanBlind, &ctx(), EscalationTier::Recon, 5);
        assert!(candidates.iter().all(|c| c.trace.steps.is_empty()));
    }

    #[test]
    fn waf_interference_widens_representation() {
        let mut c = ctx();
        c.waf_interference = true;
        let candidates = compose_for(ProbeType::BooleanBlind, &c, EscalationTier::Recon, 5);
        assert!(
            candidates.iter().any(|c| !c.trace.steps.is_empty()),
            "WAF interference should widen representation choices"
        );
    }

    #[test]
    fn explore_tier_widens_representation() {
        let candidates = compose_for(ProbeType::BooleanBlind, &ctx(), EscalationTier::Explore, 5);
        assert!(candidates.len() > 2);
        assert!(candidates.iter().any(|c| !c.trace.steps.is_empty()));
    }

    #[test]
    fn boolean_composes_a_true_false_pair() {
        let candidates = compose_for(ProbeType::BooleanBlind, &ctx(), EscalationTier::Recon, 5);
        assert!(candidates.iter().any(|c| c.sql.contains("1=1")));
        assert!(candidates.iter().any(|c| c.sql.contains("1=2")));
    }

    #[test]
    fn every_candidate_has_rationale_and_dialect() {
        for technique in [
            ProbeType::BooleanBlind,
            ProbeType::ErrorInjection,
            ProbeType::UnionBased,
        ] {
            for c in compose_for(technique, &ctx(), EscalationTier::Explore, 5) {
                assert!(!c.rationale.is_empty());
                assert!(c.rationale.contains("tier:"));
                assert_eq!(c.dialect.as_deref(), Some("PostgreSQL"));
            }
        }
    }

    #[test]
    fn candidates_are_unique() {
        let candidates = compose_for(ProbeType::BooleanBlind, &ctx(), EscalationTier::Explore, 5);
        let ids: std::collections::HashSet<_> = candidates.iter().map(|c| c.id).collect();
        assert_eq!(ids.len(), candidates.len());
    }

    #[test]
    fn transformed_candidate_differs_from_untransformed() {
        let candidates = compose_for(ProbeType::BooleanBlind, &ctx(), EscalationTier::Explore, 5);
        let untransformed: Vec<&ComposedCandidate> =
            candidates.iter().filter(|c| c.trace.steps.is_empty()).collect();
        let transformed: Vec<&ComposedCandidate> =
            candidates.iter().filter(|c| !c.trace.steps.is_empty()).collect();
        assert!(!untransformed.is_empty() && !transformed.is_empty());
        assert_ne!(
            untransformed[0].rendered,
            transformed[0].rendered,
            "transformation produced no change"
        );
    }

    #[test]
    fn baseline_composes_nothing() {
        assert!(compose_for(ProbeType::Baseline, &ctx(), EscalationTier::Recon, 5).is_empty());
    }

    #[test]
    fn union_probe_is_bounded_at_recon_explore() {
        let candidates = compose_for(ProbeType::UnionBased, &ctx(), EscalationTier::Explore, 5);
        assert!(!candidates.is_empty());
        // Only column counts 1..=3 are explored at this tier.
        assert!(candidates.iter().all(|c| {
            c.logical_test.contains("columns: 1")
                || c.logical_test.contains("columns: 2")
                || c.logical_test.contains("columns: 3")
        }));
    }
}
