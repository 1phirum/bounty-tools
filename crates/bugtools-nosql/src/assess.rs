//! NoSQL assessment result types — the honesty model.
//!
//! Mirrors `bugtools_sql::AdaptiveResult`: a NoSQL scan reports what it
//! established, what it could not, and a coverage verdict — including a
//! NOT_INTERPRETED negative finding when operator injection produced no
//! differential against a stable baseline.

use serde::{Deserialize, Serialize};

/// The lifecycle verdict for a parameter under NoSQL investigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NoSqlCoverage {
    /// Baseline captured; no experiments run yet.
    Baselined,
    /// Experiments ran but nothing separated from baseline or noise.
    Inconclusive,
    /// A repeatable differential tied to operator injection was observed.
    Interesting,
    /// Corroborated across techniques — high confidence.
    Confirmed,
    /// Operator injection ran verified against a stable baseline with no
    /// divergence: positive evidence the parameter is not interpreted as a
    /// NoSQL query object. A negative finding, not proof of total safety.
    NotInterpreted,
    /// The edge/environment blocked observation.
    Blocked,
}

impl NoSqlCoverage {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Baselined => "BASELINED",
            Self::Inconclusive => "INCONCLUSIVE",
            Self::Interesting => "INTERESTING",
            Self::Confirmed => "CONFIRMED",
            Self::NotInterpreted => "NOT_INTERPRETED",
            Self::Blocked => "BLOCKED",
        }
    }
}

/// A per-technique summary line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueSummary {
    pub technique: String,
    pub executed: usize,
    pub repeatable_differential: bool,
    pub evidence_strength: f32,
}

/// The full result of a NoSQL run against one parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoSqlAssessment {
    pub target: String,
    pub endpoint: String,
    pub parameter: String,

    pub baseline_summary: String,
    pub baseline_stable: bool,

    /// Datastore hypotheses inferred from observed error signatures.
    pub datastore_hypotheses: Vec<(String, u32)>,

    pub signals: Vec<String>,
    pub techniques: Vec<TechniqueSummary>,
    pub experiments_executed: usize,
    pub duplicates_avoided: usize,
    pub repetitions_verified: usize,
    pub flaky_tests: usize,

    /// If a bounded `$regex` extraction ran, the recovered prefix (read-only).
    pub extracted_prefix: Option<String>,

    pub coverage: String,
    pub confidence: f32,
    pub confirmed: bool,

    pub diagnostic_report: Vec<String>,
    pub remaining_uncertainty: Vec<String>,
    pub limitations: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_labels_are_stable() {
        assert_eq!(NoSqlCoverage::NotInterpreted.label(), "NOT_INTERPRETED");
        assert_eq!(NoSqlCoverage::Confirmed.label(), "CONFIRMED");
    }
}
