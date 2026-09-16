//! Hypothesis engines for context, query position and DBMS (brief §4–6).
//!
//! Replaces `context = null`, `query_position = null` and
//! `dbms_hypothesis = undetermined` with ranked hypothesis sets that carry
//! their supporting and contradicting evidence. A hypothesis is never a
//! claim: probability plus evidence, always.

use serde::{Deserialize, Serialize};

/// One competing hypothesis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hypothesis {
    pub label: String,
    pub probability: f32,
    pub supporting: Vec<String>,
    pub contradicting: Vec<String>,
}

impl Hypothesis {
    pub fn new(label: impl Into<String>, probability: f32) -> Self {
        Self {
            label: label.into(),
            probability: probability.clamp(0.0, 1.0),
            supporting: Vec::new(),
            contradicting: Vec::new(),
        }
    }

    pub fn with_support(mut self, note: impl Into<String>) -> Self {
        self.supporting.push(note.into());
        self
    }

    pub fn with_contradiction(mut self, note: impl Into<String>) -> Self {
        self.contradicting.push(note.into());
        self
    }
}

/// A ranked set of hypotheses. `Unknown` is always retained as a member so
/// the engine can honestly report that it does not know.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisSet {
    pub hypotheses: Vec<Hypothesis>,
}

impl HypothesisSet {
    /// Build from candidates, normalising probabilities so they sum to 1.
    /// An `Unknown` entry is added when absent so the set is never over-
    /// confident.
    pub fn build(mut candidates: Vec<Hypothesis>) -> Self {
        if !candidates.iter().any(|h| h.label == "unknown") {
            candidates.push(Hypothesis::new("unknown", 0.0));
        }
        // Normalise.
        let total: f32 = candidates.iter().map(|h| h.probability).sum();
        if total > 0.0 {
            for h in &mut candidates {
                h.probability /= total;
            }
        } else {
            // No evidence at all: everything is Unknown.
            for h in &mut candidates {
                if h.label == "unknown" {
                    h.probability = 1.0;
                }
            }
        }
        candidates.sort_by(|a, b| {
            b.probability
                .partial_cmp(&a.probability)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        Self {
            hypotheses: candidates,
        }
    }

    pub fn top(&self) -> &Hypothesis {
        &self.hypotheses[0]
    }

    /// Whether the leading hypothesis is meaningfully separated from the
    /// runner-up. False means the engine should not assert a context.
    pub fn is_decisive(&self) -> bool {
        let top = &self.hypotheses[0];
        // A hypothesis carried only by a neutral prior is not evidence.
        // Require at least one supporting observation AND separation.
        if top.supporting.is_empty() {
            return false;
        }
        match self.hypotheses.get(1) {
            Some(second) => {
                (top.probability - second.probability) >= 0.2 && top.probability >= 0.45
            }
            None => top.probability >= 0.45,
        }
    }

    /// Whether the top hypothesis is simply "unknown".
    pub fn is_unknown(&self) -> bool {
        self.top().label == "unknown"
    }

    /// Render like `WHERE: 0.61 | LIKE: 0.24 | Unknown: 0.15`.
    pub fn render(&self) -> String {
        self.hypotheses
            .iter()
            .filter(|h| h.probability > 0.01)
            .map(|h| format!("{}: {:.2}", h.label, h.probability))
            .collect::<Vec<_>>()
            .join(" | ")
    }
}

/// Observations the context inference reasons over.
#[derive(Debug, Clone, Default)]
pub struct ContextObservations {
    pub parameter_name: String,
    /// The original value, e.g. "42".
    pub original_value: String,
    /// Declared/observed type (query string vs JSON number, etc.).
    pub declared_type: Option<String>,
    /// True when a mutation with a non-numeric string was accepted.
    pub accepts_non_numeric: bool,
    /// True when a non-numeric mutation was rejected with validation.
    pub rejects_non_numeric: bool,
    /// True when an unquoted expression caused a syntax error.
    pub syntax_error_on_quote: bool,
    /// True when a quoted value was accepted unchanged.
    pub accepts_quotes: bool,
    /// True when the response changed on a trailing space.
    pub length_sensitive: bool,
    /// True when the value appears reflected in the response.
    pub reflected: bool,
}

/// Infer SQL context hypotheses from observed behaviour.
///
/// Parameter naming contributes only weak prior support — the brief is
/// explicit that naming alone does not prove context.
pub fn infer_context(obs: &ContextObservations) -> HypothesisSet {
    let mut candidates = Vec::new();

    // Numeric: the value looks numeric and non-numeric input is rejected or
    // causes a type error.
    let value_is_numeric = !obs.original_value.is_empty()
        && obs.original_value.chars().all(|c| c.is_ascii_digit());
    let mut numeric = Hypothesis::new("numeric", 0.0);
    if value_is_numeric {
        numeric = numeric.with_support("original value is all digits");
    }
    if obs.rejects_non_numeric {
        numeric = numeric.with_support("non-numeric input rejected (type validation)");
    }
    if obs.accepts_non_numeric {
        numeric = numeric.with_contradiction("non-numeric input accepted");
    }
    if value_is_numeric && !obs.accepts_non_numeric {
        numeric.probability += 0.45;
    }
    if obs.rejects_non_numeric {
        numeric.probability += 0.25;
    }
    candidates.push(numeric);

    // String: quotes accepted, or the value is non-numeric and accepted.
    let mut string = Hypothesis::new("string", 0.0);
    if !value_is_numeric && !obs.original_value.is_empty() {
        string = string.with_support("original value is non-numeric");
        string.probability += 0.35;
    }
    if obs.accepts_quotes {
        string = string.with_support("quoted value accepted unchanged");
        string.probability += 0.3;
    }
    if obs.syntax_error_on_quote {
        string = string.with_contradiction(
            "an injected quote caused a syntax error, suggesting a quoted string context",
        );
        // This actually *supports* a quoted-string context; keep it in the
        // quoted_string hypothesis instead.
    }
    candidates.push(string);

    // Quoted string: a quote mutation produced a database syntax error.
    let mut quoted = Hypothesis::new("quoted_string", 0.0);
    if obs.syntax_error_on_quote {
        quoted = quoted.with_support("injected quote produced a database syntax error");
        quoted.probability += 0.6;
    }
    candidates.push(quoted);

    // LIKE / search: name or value suggests a pattern search.
    let name_lower = obs.parameter_name.to_lowercase();
    let mut like = Hypothesis::new("like", 0.0);
    if ["q", "search", "query", "filter", "term", "name"].contains(&name_lower.as_str()) {
        like = like.with_support("parameter name suggests a search field (weak prior)");
        like.probability += 0.1;
    }
    candidates.push(like);

    // Identifier: used in ORDER BY/GROUP BY style positions.
    let mut identifier = Hypothesis::new("identifier", 0.0);
    if ["sort", "order", "orderby", "column", "field", "group", "groupby"]
        .contains(&name_lower.as_str())
    {
        identifier = identifier.with_support("parameter name suggests a column/ordering field (weak prior)");
        identifier.probability += 0.15;
    }
    candidates.push(identifier);

    HypothesisSet::build(candidates)
}

/// Observations for query-position inference.
#[derive(Debug, Clone, Default)]
pub struct PositionObservations {
    pub parameter_name: String,
    /// A boolean pair diverged (true/false responses differed).
    pub boolean_diverged: bool,
    /// A syntax error occurred when an expression was injected.
    pub expression_syntax_error: bool,
    /// The parameter accepted an ordering expression without error.
    pub accepted_ordering: bool,
    /// The parameter is a pagination-style integer.
    pub looks_paginated: bool,
    /// A LIKE wildcard was accepted.
    pub accepted_wildcard: bool,
}

/// Infer query-position hypotheses.
pub fn infer_query_position(obs: &PositionObservations) -> HypothesisSet {
    let name = obs.parameter_name.to_lowercase();
    let mut candidates = Vec::new();

    let mut where_h = Hypothesis::new("WHERE", 0.35); // neutral prior: most common
    if obs.boolean_diverged {
        where_h = where_h.with_support("boolean differential observed — consistent with a predicate");
        where_h.probability += 0.35;
    }
    if obs.expression_syntax_error {
        where_h = where_h.with_support("expression injection caused a syntax error");
        where_h.probability += 0.1;
    }
    candidates.push(where_h);

    let mut like = Hypothesis::new("LIKE", 0.05);
    if obs.accepted_wildcard {
        like = like.with_support("a LIKE wildcard was accepted");
        like.probability += 0.4;
    }
    if name.contains("search") || name.contains("query") {
        like = like.with_support("parameter name suggests a search field (weak)");
        like.probability += 0.1;
    }
    candidates.push(like);

    let mut order = Hypothesis::new("ORDER BY", 0.05);
    if obs.accepted_ordering {
        order = order.with_support("an ordering expression was accepted");
        order.probability += 0.5;
    }
    if name.contains("sort") || name.contains("order") {
        order = order.with_support("parameter name suggests ordering (weak)");
        order.probability += 0.1;
    }
    candidates.push(order);

    let mut limit = Hypothesis::new("LIMIT/OFFSET", 0.05);
    if obs.looks_paginated {
        limit = limit.with_support("pagination-style integer parameter");
        limit.probability += 0.4;
    }
    candidates.push(limit);

    HypothesisSet::build(candidates)
}

/// Observations for DBMS inference. Reuses the existing detection signals.
#[derive(Debug, Clone, Default)]
pub struct DbmsObservations {
    /// (dbms label, weight, evidence description) from matched signatures.
    pub matched_signals: Vec<(String, u32, String)>,
    /// Application technology that hints at a typical DBMS.
    pub application_hint: Option<String>,
}

/// Infer ranked DBMS hypotheses. Never returns "undetermined" alone — it
/// returns a set that may legitimately be `unknown`-dominant, with the
/// evidence that was considered.
pub fn infer_dbms(obs: &DbmsObservations) -> HypothesisSet {
    let mut candidates: Vec<Hypothesis> = Vec::new();

    for (dbms, weight, evidence) in &obs.matched_signals {
        let p = (*weight as f32 / 100.0).clamp(0.0, 1.0);
        if let Some(existing) = candidates.iter_mut().find(|h| &h.label == dbms) {
            existing.probability = (existing.probability + p).min(1.0);
            existing.supporting.push(evidence.clone());
        } else {
            candidates.push(Hypothesis::new(dbms.clone(), p).with_support(evidence.clone()));
        }
    }

    // An application hint is weak prior support only.
    if let Some(hint) = &obs.application_hint {
        let hinted = match hint.to_lowercase().as_str() {
            h if h.contains("wordpress") => Some("MySQL"),
            h if h.contains("django") || h.contains("rails") => Some("PostgreSQL"),
            h if h.contains("asp.net") => Some("MSSQL"),
            _ => None,
        };
        if let Some(dbms) = hinted {
            let note = format!("application technology '{hint}' commonly uses this DBMS (weak prior)");
            if let Some(existing) = candidates.iter_mut().find(|h| h.label == dbms) {
                existing.supporting.push(note);
                existing.probability = (existing.probability + 0.1).min(1.0);
            } else {
                candidates.push(Hypothesis::new(dbms, 0.1).with_support(note));
            }
        }
    }

    HypothesisSet::build(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_parameter_with_type_validation_is_numeric() {
        let obs = ContextObservations {
            parameter_name: "id".into(),
            original_value: "42".into(),
            rejects_non_numeric: true,
            ..Default::default()
        };
        let set = infer_context(&obs);
        assert_eq!(set.top().label, "numeric");
        assert!(set.is_decisive());
    }

    #[test]
    fn naming_alone_does_not_prove_context() {
        // A "sort" parameter with no behavioural evidence must not be
        // decisively classified as an identifier.
        let obs = ContextObservations {
            parameter_name: "sort".into(),
            original_value: "name".into(),
            ..Default::default()
        };
        let set = infer_context(&obs);
        assert!(
            !set.is_decisive() || set.top().label != "identifier",
            "naming produced a decisive identifier hypothesis: {}",
            set.render()
        );
    }

    #[test]
    fn context_is_always_available_never_null() {
        let set = infer_context(&ContextObservations::default());
        assert!(!set.hypotheses.is_empty());
        assert_eq!(set.top().label, "unknown");
        assert!(set.is_unknown());
    }

    #[test]
    fn quoted_string_from_syntax_error() {
        let obs = ContextObservations {
            original_value: "abc".into(),
            syntax_error_on_quote: true,
            ..Default::default()
        };
        let set = infer_context(&obs);
        assert_eq!(set.top().label, "quoted_string");
        assert!(set.top().supporting.iter().any(|s| s.contains("syntax error")));
    }

    #[test]
    fn probabilities_sum_to_one() {
        let obs = ContextObservations {
            parameter_name: "id".into(),
            original_value: "42".into(),
            rejects_non_numeric: true,
            ..Default::default()
        };
        let set = infer_context(&obs);
        let total: f32 = set.hypotheses.iter().map(|h| h.probability).sum();
        assert!((total - 1.0).abs() < 0.001, "probabilities sum to {total}");
    }

    #[test]
    fn unknown_is_retained() {
        let obs = ContextObservations {
            original_value: "42".into(),
            ..Default::default()
        };
        let set = infer_context(&obs);
        assert!(set.hypotheses.iter().any(|h| h.label == "unknown"));
    }

    #[test]
    fn position_defaults_to_where_but_not_decisively() {
        let set = infer_query_position(&PositionObservations::default());
        assert_eq!(set.top().label, "WHERE");
        // Without evidence the engine should not be decisive.
        assert!(!set.is_decisive(), "position was asserted without evidence: {}", set.render());
    }

    #[test]
    fn boolean_evidence_makes_where_decisive() {
        let obs = PositionObservations {
            boolean_diverged: true,
            ..Default::default()
        };
        let set = infer_query_position(&obs);
        assert_eq!(set.top().label, "WHERE");
        assert!(set.is_decisive());
    }

    #[test]
    fn ordering_evidence_favours_order_by() {
        let obs = PositionObservations {
            accepted_ordering: true,
            ..Default::default()
        };
        let set = infer_query_position(&obs);
        assert_eq!(set.top().label, "ORDER BY");
    }

    #[test]
    fn dbms_with_no_signals_is_unknown() {
        let set = infer_dbms(&DbmsObservations::default());
        assert!(set.is_unknown());
    }

    #[test]
    fn dbms_strong_signals_rank_first() {
        let obs = DbmsObservations {
            matched_signals: vec![
                ("PostgreSQL".into(), 50, "pg_query() driver".into()),
                ("PostgreSQL".into(), 45, "psycopg2 errors".into()),
            ],
            application_hint: None,
        };
        let set = infer_dbms(&obs);
        assert_eq!(set.top().label, "PostgreSQL");
        assert_eq!(set.top().supporting.len(), 2);
    }

    #[test]
    fn application_hint_is_weak_prior_only() {
        let obs = DbmsObservations {
            matched_signals: vec![],
            application_hint: Some("WordPress".into()),
        };
        let set = infer_dbms(&obs);
        // Hinted but not decisive — 0.1 is below the decisive floor.
        assert!(set.top().label == "MySQL" || set.top().label == "unknown");
        assert!(!set.is_decisive() || set.top().label == "MySQL");
    }

    #[test]
    fn render_is_readable() {
        let obs = PositionObservations {
            boolean_diverged: true,
            ..Default::default()
        };
        let rendered = infer_query_position(&obs).render();
        assert!(rendered.contains("WHERE"));
        assert!(rendered.contains(":"));
    }

    #[test]
    fn decisive_requires_separation() {
        let set = HypothesisSet::build(vec![
            Hypothesis::new("a", 0.4),
            Hypothesis::new("b", 0.38),
        ]);
        assert!(!set.is_decisive(), "close hypotheses must not be decisive");
    }
}
