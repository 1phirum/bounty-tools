//! Evidence model — the observation layer of the research engine.
//!
//! The central design rule (brief §23): an **observation** is a fact we
//! measured; an **interpretation** is a hypothesis we formed. Evidence is
//! the bridge, and it must never collapse the two. A `500` response is an
//! observation; "possible SQL parser interaction" is a hypothesis. Evidence
//! records which observations support or contradict which hypotheses and
//! by how much confidence.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// What kind of measurement produced this evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCategory {
    /// Baseline stability / response shape.
    Baseline,
    /// An HTTP status change versus baseline.
    StatusDifference,
    /// A body-content or length difference versus baseline.
    BodyDifference,
    /// A DBMS error signature matched in the response.
    ErrorSignature,
    /// A dialect-specific syntax feature was accepted/rejected.
    SyntaxFeature,
    /// A boolean differential response was observed.
    BooleanDifferential,
    /// A statistically meaningful timing difference was observed.
    TimingDifference,
    /// Input was reflected in the response (not itself SQL evidence).
    Reflection,
    /// Environmental interference (WAF, rate limit, auth failure).
    Environment,
    /// The response was unchanged from baseline.
    NoDifference,
}

impl EvidenceCategory {
    /// Whether this category can, on its own, support a SQL-*interaction*
    /// hypothesis. Reflection and baseline facts cannot — this is what stops
    /// the engine reporting "reflected input" as "SQL injection".
    pub fn supports_sql_interaction(&self) -> bool {
        matches!(
            self,
            Self::StatusDifference
                | Self::BodyDifference
                | Self::ErrorSignature
                | Self::SyntaxFeature
                | Self::BooleanDifferential
                | Self::TimingDifference
        )
    }
}

/// A single piece of evidence, tied to specific endpoint / parameter / probe.
///
/// `supports` and `contradicts` hold hypothesis labels so the confidence
/// engine can aggregate them without re-deriving anything. Contradictory
/// evidence is retained (brief §22) — it is never discarded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub endpoint_id: Option<Uuid>,
    pub parameter_id: Option<Uuid>,
    pub probe_id: String,
    pub category: EvidenceCategory,
    /// Human-readable statement of what was measured (an observation).
    pub observation: String,
    /// Hypothesis labels this evidence argues *for*.
    pub supports: Vec<String>,
    /// Hypothesis labels this evidence argues *against*.
    pub contradicts: Vec<String>,
    /// Confidence contribution in points (may be negative).
    pub confidence_delta: i32,
    /// Reference keys into stored request/response artefacts (not the bytes).
    pub request_reference: Option<String>,
    pub response_reference: Option<String>,
}

impl Evidence {
    /// Construct evidence with a fresh ID and current timestamp.
    pub fn new(
        category: EvidenceCategory,
        observation: impl Into<String>,
        confidence_delta: i32,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            endpoint_id: None,
            parameter_id: None,
            probe_id: String::new(),
            category,
            observation: observation.into(),
            supports: Vec::new(),
            contradicts: Vec::new(),
            confidence_delta,
            request_reference: None,
            response_reference: None,
        }
    }

    pub fn with_probe(mut self, probe_id: impl Into<String>) -> Self {
        self.probe_id = probe_id.into();
        self
    }

    pub fn supporting(mut self, hypothesis: impl Into<String>) -> Self {
        self.supports.push(hypothesis.into());
        self
    }

    pub fn contradicting(mut self, hypothesis: impl Into<String>) -> Self {
        self.contradicts.push(hypothesis.into());
        self
    }

    pub fn for_parameter(mut self, parameter_id: Uuid) -> Self {
        self.parameter_id = Some(parameter_id);
        self
    }

    pub fn with_references(
        mut self,
        request: impl Into<String>,
        response: impl Into<String>,
    ) -> Self {
        self.request_reference = Some(request.into());
        self.response_reference = Some(response.into());
        self
    }
}

/// The evidence store — an append-only collection with correlation queries.
///
/// Nothing is ever removed; contradictions accumulate alongside support so
/// the final confidence is auditable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceGraph {
    pub evidence: Vec<Evidence>,
}

impl EvidenceGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append evidence, returning its ID.
    pub fn record(&mut self, evidence: Evidence) -> Uuid {
        let id = evidence.id;
        self.evidence.push(evidence);
        id
    }

    /// All evidence for a given parameter.
    pub fn for_parameter(&self, parameter_id: Uuid) -> Vec<&Evidence> {
        self.evidence
            .iter()
            .filter(|e| e.parameter_id == Some(parameter_id))
            .collect()
    }

    /// All evidence that argues for or against a named hypothesis.
    pub fn for_hypothesis(&self, hypothesis: &str) -> Vec<&Evidence> {
        self.evidence
            .iter()
            .filter(|e| {
                e.supports.iter().any(|h| h == hypothesis)
                    || e.contradicts.iter().any(|h| h == hypothesis)
            })
            .collect()
    }

    /// Net confidence contribution per hypothesis label, summing supports
    /// and subtracting contradictions.
    pub fn confidence_by_hypothesis(&self) -> HashMap<String, i32> {
        let mut scores: HashMap<String, i32> = HashMap::new();
        for e in &self.evidence {
            for h in &e.supports {
                *scores.entry(h.clone()).or_insert(0) += e.confidence_delta;
            }
            for h in &e.contradicts {
                *scores.entry(h.clone()).or_insert(0) -= e.confidence_delta;
            }
        }
        scores
    }

    /// Count of evidence categories present — used by the UI summary.
    pub fn category_counts(&self) -> HashMap<EvidenceCategory, usize> {
        let mut counts = HashMap::new();
        for e in &self.evidence {
            *counts.entry(e.category).or_insert(0) += 1;
        }
        counts
    }

    pub fn len(&self) -> usize {
        self.evidence.len()
    }

    pub fn is_empty(&self) -> bool {
        self.evidence.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reflection_alone_cannot_support_sql() {
        assert!(!EvidenceCategory::Reflection.supports_sql_interaction());
        assert!(!EvidenceCategory::Baseline.supports_sql_interaction());
        assert!(EvidenceCategory::ErrorSignature.supports_sql_interaction());
        assert!(EvidenceCategory::BooleanDifferential.supports_sql_interaction());
    }

    #[test]
    fn evidence_builder_sets_fields() {
        let param = Uuid::new_v4();
        let e = Evidence::new(EvidenceCategory::ErrorSignature, "parser error matched", 30)
            .with_probe("error-01")
            .supporting("sql_interaction")
            .for_parameter(param);
        assert_eq!(e.confidence_delta, 30);
        assert_eq!(e.probe_id, "error-01");
        assert_eq!(e.parameter_id, Some(param));
        assert_eq!(e.supports, vec!["sql_interaction".to_string()]);
    }

    #[test]
    fn graph_records_and_queries() {
        let mut graph = EvidenceGraph::new();
        let param = Uuid::new_v4();
        graph.record(
            Evidence::new(EvidenceCategory::ErrorSignature, "err", 30)
                .supporting("sql")
                .for_parameter(param),
        );
        graph.record(
            Evidence::new(EvidenceCategory::TimingDifference, "slow", 10)
                .contradicting("network_noise")
                .for_parameter(param),
        );
        assert_eq!(graph.len(), 2);
        assert_eq!(graph.for_parameter(param).len(), 2);
    }

    #[test]
    fn contradictions_subtract_confidence() {
        let mut graph = EvidenceGraph::new();
        graph.record(
            Evidence::new(EvidenceCategory::ErrorSignature, "a", 30).supporting("sql"),
        );
        graph.record(
            Evidence::new(EvidenceCategory::Environment, "waf", 15).contradicting("sql"),
        );
        let scores = graph.confidence_by_hypothesis();
        assert_eq!(scores.get("sql"), Some(&15)); // 30 - 15
    }

    #[test]
    fn contradictory_evidence_is_retained() {
        let mut graph = EvidenceGraph::new();
        graph.record(Evidence::new(EvidenceCategory::ErrorSignature, "for", 20).supporting("sql"));
        graph.record(Evidence::new(EvidenceCategory::NoDifference, "against", 20).contradicting("sql"));
        // Both remain; nothing is discarded.
        assert_eq!(graph.for_hypothesis("sql").len(), 2);
    }

    #[test]
    fn category_counts() {
        let mut graph = EvidenceGraph::new();
        graph.record(Evidence::new(EvidenceCategory::Baseline, "b", 0));
        graph.record(Evidence::new(EvidenceCategory::ErrorSignature, "e", 10));
        graph.record(Evidence::new(EvidenceCategory::ErrorSignature, "e2", 10));
        let counts = graph.category_counts();
        assert_eq!(counts.get(&EvidenceCategory::ErrorSignature), Some(&2));
        assert_eq!(counts.get(&EvidenceCategory::Baseline), Some(&1));
    }
}
