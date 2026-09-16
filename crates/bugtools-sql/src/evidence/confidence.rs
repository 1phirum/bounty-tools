//! Explainable confidence engine (brief §24).
//!
//! Produces a confidence level *with the evidence breakdown that justifies
//! it*. It never emits a bare percentage: every point of confidence traces
//! to a recorded `Evidence` entry.

use super::model::{Evidence, EvidenceCategory, EvidenceGraph};
use serde::{Deserialize, Serialize};

/// The confidence tier a hypothesis has reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLevel {
    None,
    Low,
    Medium,
    High,
}

impl ConfidenceLevel {
    /// Map a raw score to a tier. Thresholds are intentionally conservative:
    /// MEDIUM requires corroboration, HIGH requires multiple independent
    /// categories — a single signal cannot reach HIGH.
    pub fn from_score(score: i32, distinct_categories: usize) -> Self {
        if score <= 0 {
            ConfidenceLevel::None
        } else if score >= 70 && distinct_categories >= 3 {
            ConfidenceLevel::High
        } else if score >= 35 && distinct_categories >= 2 {
            ConfidenceLevel::Medium
        } else {
            ConfidenceLevel::Low
        }
    }
}

/// One line of the confidence breakdown shown to the researcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceFactor {
    pub supported: bool,
    pub category: EvidenceCategory,
    pub observation: String,
    pub delta: i32,
}

/// The full, explainable confidence result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceReport {
    pub hypothesis: String,
    pub score: i32,
    pub level: ConfidenceLevel,
    pub supporting: Vec<ConfidenceFactor>,
    pub contradicting: Vec<ConfidenceFactor>,
    /// Number of distinct evidence categories involved (a HIGH-confidence
    /// prerequisite).
    pub distinct_categories: usize,
    /// Caveats the researcher should weigh, e.g. baseline instability.
    pub caveats: Vec<String>,
}

impl ConfidenceReport {
    /// Compute confidence for a hypothesis label from the evidence graph.
    pub fn compute(graph: &EvidenceGraph, hypothesis: &str) -> Self {
        let mut score = 0i32;
        let mut supporting = Vec::new();
        let mut contradicting = Vec::new();
        let mut categories = std::collections::HashSet::new();
        let mut caveats = Vec::new();

        for e in &graph.evidence {
            let supports = e.supports.iter().any(|h| h == hypothesis);
            let contradicts = e.contradicts.iter().any(|h| h == hypothesis);
            if !supports && !contradicts {
                continue;
            }
            categories.insert(e.category);
            let factor = ConfidenceFactor {
                supported: supports,
                category: e.category,
                observation: e.observation.clone(),
                delta: e.confidence_delta,
            };
            if supports {
                score += e.confidence_delta;
                supporting.push(factor);
            } else {
                score -= e.confidence_delta;
                contradicting.push(factor);
            }
        }

        // An unstable baseline undermines every conclusion drawn against it.
        if graph
            .evidence
            .iter()
            .any(|e| e.category == EvidenceCategory::Baseline && e.contradicts.iter().any(|h| h == hypothesis))
        {
            caveats.push(
                "Baseline instability was recorded — differential results may be unreliable."
                    .to_string(),
            );
        }

        let distinct_categories = categories.len();
        let level = ConfidenceLevel::from_score(score, distinct_categories);

        Self {
            hypothesis: hypothesis.to_string(),
            score,
            level,
            supporting,
            contradicting,
            distinct_categories,
            caveats,
        }
    }

    /// A one-line human summary, e.g. "HIGH (3 independent signals)".
    pub fn summary(&self) -> String {
        let tier = match self.level {
            ConfidenceLevel::None => "NONE",
            ConfidenceLevel::Low => "LOW",
            ConfidenceLevel::Medium => "MEDIUM",
            ConfidenceLevel::High => "HIGH",
        };
        format!(
            "{} ({} supporting, {} contradicting, {} categories)",
            tier,
            self.supporting.len(),
            self.contradicting.len(),
            self.distinct_categories
        )
    }
}

/// Build "sql_interaction" evidence from a probe outcome, preserving the
/// observation/interpretation separation. Returns evidence reflecting only
/// what was actually measured.
pub fn evidence_from_probe(
    category: EvidenceCategory,
    observation: impl Into<String>,
    supports_sql: bool,
    delta: i32,
) -> Evidence {
    let mut e = Evidence::new(category, observation, delta);
    if supports_sql && category.supports_sql_interaction() {
        e = e.supporting("sql_interaction");
    } else if !supports_sql {
        e = e.contradicting("sql_interaction");
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn param() -> Uuid {
        Uuid::new_v4()
    }

    #[test]
    fn single_signal_cannot_reach_high() {
        // One strong error signature alone is at most MEDIUM.
        let mut graph = EvidenceGraph::new();
        graph.record(
            Evidence::new(EvidenceCategory::ErrorSignature, "parser error", 60)
                .supporting("sql_interaction")
                .for_parameter(param()),
        );
        let report = ConfidenceReport::compute(&graph, "sql_interaction");
        assert_ne!(report.level, ConfidenceLevel::High, "one category must not be HIGH");
    }

    #[test]
    fn three_categories_reach_high() {
        let mut graph = EvidenceGraph::new();
        let p = param();
        graph.record(
            Evidence::new(EvidenceCategory::ErrorSignature, "err", 30)
                .supporting("sql_interaction")
                .for_parameter(p),
        );
        graph.record(
            Evidence::new(EvidenceCategory::BooleanDifferential, "bool", 30)
                .supporting("sql_interaction")
                .for_parameter(p),
        );
        graph.record(
            Evidence::new(EvidenceCategory::TimingDifference, "timing", 30)
                .supporting("sql_interaction")
                .for_parameter(p),
        );
        let report = ConfidenceReport::compute(&graph, "sql_interaction");
        assert_eq!(report.level, ConfidenceLevel::High);
        assert_eq!(report.score, 90);
        assert_eq!(report.distinct_categories, 3);
    }

    #[test]
    fn contradiction_lowers_score() {
        let mut graph = EvidenceGraph::new();
        graph.record(Evidence::new(EvidenceCategory::ErrorSignature, "for", 40).supporting("sql"));
        graph.record(
            Evidence::new(EvidenceCategory::Environment, "waf blocks", 30).contradicting("sql"),
        );
        let report = ConfidenceReport::compute(&graph, "sql");
        assert_eq!(report.score, 10);
        assert_eq!(report.supporting.len(), 1);
        assert_eq!(report.contradicting.len(), 1);
    }

    #[test]
    fn no_evidence_is_none() {
        let graph = EvidenceGraph::new();
        let report = ConfidenceReport::compute(&graph, "sql_interaction");
        assert_eq!(report.level, ConfidenceLevel::None);
        assert_eq!(report.score, 0);
    }

    #[test]
    fn unstable_baseline_adds_caveat() {
        let mut graph = EvidenceGraph::new();
        graph.record(
            Evidence::new(EvidenceCategory::Baseline, "noisy baseline", 10)
                .contradicting("sql_interaction"),
        );
        let report = ConfidenceReport::compute(&graph, "sql_interaction");
        assert!(!report.caveats.is_empty());
    }

    #[test]
    fn reflection_does_not_support_sql() {
        // A reflection observation passed with supports_sql=true still must
        // not become SQL interaction evidence, because the category forbids it.
        let e = evidence_from_probe(EvidenceCategory::Reflection, "input reflected", true, 20);
        assert!(!e.supports.contains(&"sql_interaction".to_string()));
    }

    #[test]
    fn summary_is_readable() {
        let mut graph = EvidenceGraph::new();
        graph.record(Evidence::new(EvidenceCategory::ErrorSignature, "e", 50).supporting("sql"));
        graph.record(Evidence::new(EvidenceCategory::BodyDifference, "b", 30).supporting("sql"));
        let report = ConfidenceReport::compute(&graph, "sql");
        assert!(report.summary().contains("HIGH") || report.summary().contains("MEDIUM"));
        assert!(report.summary().contains("supporting"));
    }
}
