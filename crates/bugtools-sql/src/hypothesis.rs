//! Probabilistic context and query-position hypotheses.
//!
//! The existing `context.rs` carries a single `ContextClassification`. This
//! module adds the hypothesis layer the brief requires: a context may hold
//! several competing explanations with confidences, alternatives, and the
//! evidence for each — never a bare label.

use serde::{Deserialize, Serialize};

/// A named piece of evidence supporting or contradicting a hypothesis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HypothesisEvidence {
    pub observation: String,
    /// Positive weight increases confidence, negative decreases it.
    pub weight: f32,
}

impl HypothesisEvidence {
    pub fn new(observation: impl Into<String>, weight: f32) -> Self {
        Self {
            observation: observation.into(),
            weight,
        }
    }
}

/// Where in the SQL statement an input appears to land.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryPosition {
    Where,
    OrderBy,
    GroupBy,
    Having,
    Join,
    Insert,
    Update,
    Delete,
    LimitOffset,
    Like,
    Unknown,
}

impl QueryPosition {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Where => "WHERE",
            Self::OrderBy => "ORDER BY",
            Self::GroupBy => "GROUP BY",
            Self::Having => "HAVING",
            Self::Join => "JOIN",
            Self::Insert => "INSERT",
            Self::Update => "UPDATE",
            Self::Delete => "DELETE",
            Self::LimitOffset => "LIMIT/OFFSET",
            Self::Like => "LIKE",
            Self::Unknown => "Unknown",
        }
    }
}

/// A hypothesis about an input's SQL context, with alternatives.
///
/// `confidence` is the winning explanation's confidence; `alternatives`
/// holds the runners-up so the researcher sees ambiguity rather than a
/// false certainty.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextHypothesis {
    /// The most likely context label (e.g. "numeric", "string").
    pub context: String,
    pub confidence: f32,
    pub alternatives: Vec<(String, f32)>,
    pub evidence: Vec<HypothesisEvidence>,
    /// The query position this context implies, if known.
    pub query_position: QueryPosition,
    pub position_confidence: f32,
}

impl ContextHypothesis {
    pub fn new(context: impl Into<String>) -> Self {
        Self {
            context: context.into(),
            confidence: 0.0,
            alternatives: Vec::new(),
            evidence: Vec::new(),
            query_position: QueryPosition::Unknown,
            position_confidence: 0.0,
        }
    }

    /// Add evidence and fold its weight into the confidence, clamped to
    /// [0, 1].
    pub fn with_evidence(mut self, evidence: HypothesisEvidence) -> Self {
        self.confidence = (self.confidence + evidence.weight).clamp(0.0, 1.0);
        self.evidence.push(evidence);
        self
    }

    pub fn with_alternative(mut self, context: impl Into<String>, confidence: f32) -> Self {
        self.alternatives.push((context.into(), confidence));
        self
    }

    pub fn with_position(mut self, position: QueryPosition, confidence: f32) -> Self {
        self.query_position = position;
        self.position_confidence = confidence;
        self
    }

    /// True when no single explanation dominates — the researcher should
    /// treat the classification as uncertain.
    pub fn is_ambiguous(&self) -> bool {
        self.alternatives
            .iter()
            .any(|(_, c)| (self.confidence - c).abs() < 0.15)
    }

    /// Human summary including the leading alternative when ambiguous.
    pub fn summary(&self) -> String {
        let base = format!(
            "{} ({:.0}%)",
            self.context,
            self.confidence * 100.0
        );
        if self.is_ambiguous() {
            if let Some((alt, conf)) = self.alternatives.first() {
                return format!("{base} — ambiguous with {alt} ({:.0}%)", conf * 100.0);
            }
        }
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_folds_into_confidence() {
        let h = ContextHypothesis::new("numeric")
            .with_evidence(HypothesisEvidence::new("value is all digits", 0.5))
            .with_evidence(HypothesisEvidence::new("stable under numeric mutation", 0.3));
        assert!((h.confidence - 0.8).abs() < 0.001);
    }

    #[test]
    fn confidence_clamped_to_unit_range() {
        let h = ContextHypothesis::new("string")
            .with_evidence(HypothesisEvidence::new("a", 0.9))
            .with_evidence(HypothesisEvidence::new("b", 0.9));
        assert_eq!(h.confidence, 1.0);
    }

    #[test]
    fn negative_evidence_reduces_confidence() {
        let h = ContextHypothesis::new("numeric")
            .with_evidence(HypothesisEvidence::new("digits", 0.6))
            .with_evidence(HypothesisEvidence::new("also accepts text", -0.4));
        assert!((h.confidence - 0.2).abs() < 0.001);
    }

    #[test]
    fn ambiguity_detected_when_runner_up_is_close() {
        let h = ContextHypothesis::new("numeric")
            .with_evidence(HypothesisEvidence::new("digits", 0.6))
            .with_alternative("string", 0.5);
        assert!(h.is_ambiguous());
        assert!(h.summary().contains("ambiguous"));
    }

    #[test]
    fn not_ambiguous_when_runner_up_is_distant() {
        let h = ContextHypothesis::new("numeric")
            .with_evidence(HypothesisEvidence::new("digits", 0.9))
            .with_alternative("string", 0.05);
        assert!(!h.is_ambiguous());
    }

    #[test]
    fn query_position_recorded() {
        let h = ContextHypothesis::new("identifier")
            .with_position(QueryPosition::OrderBy, 0.7);
        assert_eq!(h.query_position, QueryPosition::OrderBy);
        assert_eq!(h.query_position.label(), "ORDER BY");
    }
}
