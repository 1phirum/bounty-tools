//! The final SQLi assessment model (brief §30).
//!
//! Every conclusion the engine reaches is expressed here, and `limitations`
//! is **mandatory** — the type will not construct without it. This is the
//! structural guarantee that the engine never presents a bare "vulnerable"
//! verdict without stating what weakens it.

use crate::evidence::ConfidenceLevel;
use serde::{Deserialize, Serialize};

/// A limitation on the assessment's strength. Cannot be empty when a
/// finding is reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limitation {
    pub category: LimitationCategory,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitationCategory {
    NetworkVariance,
    BaselineInstability,
    DbmsAmbiguity,
    ContextAmbiguity,
    WafInterference,
    SessionDependency,
    IncompleteEvidence,
    NonRepeatable,
}

impl LimitationCategory {
    pub fn label(&self) -> &'static str {
        match self {
            Self::NetworkVariance => "network variance",
            Self::BaselineInstability => "baseline instability",
            Self::DbmsAmbiguity => "DBMS ambiguity",
            Self::ContextAmbiguity => "context ambiguity",
            Self::WafInterference => "WAF interference",
            Self::SessionDependency => "session dependency",
            Self::IncompleteEvidence => "incomplete evidence",
            Self::NonRepeatable => "non-repeatable observation",
        }
    }
}

impl Limitation {
    pub fn new(category: LimitationCategory, detail: impl Into<String>) -> Self {
        Self {
            category,
            detail: detail.into(),
        }
    }
}

/// The single, complete result of a SQLi investigation.
///
/// Constructed through the builder so that `limitations` cannot be omitted:
/// `build()` returns `Err` when the assessment asserts anything stronger
/// than "no finding" while carrying no limitations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlInjectionAssessment {
    pub target: String,
    pub endpoint: String,
    pub parameter: String,
    pub input_location: String,
    /// Context label (e.g. "numeric"), if classified.
    pub context: Option<String>,
    /// Query position, if inferred.
    pub query_position: Option<String>,
    pub dbms_hypothesis: Option<String>,
    pub techniques_observed: Vec<String>,
    pub signals: Vec<String>,
    pub evidence_ids: Vec<uuid::Uuid>,
    pub repeatability: Repeatability,
    pub confidence: i32,
    pub confidence_level: ConfidenceLevel,
    /// MANDATORY when anything stronger than None is asserted.
    pub limitations: Vec<Limitation>,
    /// Explicit statement of what could not be established.
    pub uncertainty: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Repeatability {
    /// Not attempted.
    Unknown,
    /// Difference seen once.
    SingleObservation,
    /// Difference reproduced across repeated requests.
    Repeated,
    /// Difference reproduced and controls held stable.
    ControlledAndRepeated,
}

impl Repeatability {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::SingleObservation => "single observation",
            Self::Repeated => "repeated",
            Self::ControlledAndRepeated => "controlled and repeated",
        }
    }
}

/// Builder for `SqlInjectionAssessment` enforcing the limitations rule.
#[derive(Debug, Clone)]
pub struct AssessmentBuilder {
    assessment: SqlInjectionAssessment,
}

#[derive(Debug, thiserror::Error)]
pub enum AssessmentError {
    #[error(
        "a finding stronger than 'None' was asserted without stating its limitations; \
         add at least one Limitation or lower the confidence"
    )]
    MissingLimitations,
}

impl AssessmentBuilder {
    pub fn new(
        target: impl Into<String>,
        endpoint: impl Into<String>,
        parameter: impl Into<String>,
        input_location: impl Into<String>,
    ) -> Self {
        Self {
            assessment: SqlInjectionAssessment {
                target: target.into(),
                endpoint: endpoint.into(),
                parameter: parameter.into(),
                input_location: input_location.into(),
                context: None,
                query_position: None,
                dbms_hypothesis: None,
                techniques_observed: Vec::new(),
                signals: Vec::new(),
                evidence_ids: Vec::new(),
                repeatability: Repeatability::Unknown,
                confidence: 0,
                confidence_level: ConfidenceLevel::None,
                limitations: Vec::new(),
                uncertainty: Vec::new(),
            },
        }
    }

    pub fn context(mut self, context: impl Into<String>) -> Self {
        self.assessment.context = Some(context.into());
        self
    }

    pub fn query_position(mut self, position: impl Into<String>) -> Self {
        self.assessment.query_position = Some(position.into());
        self
    }

    pub fn dbms(mut self, dbms: impl Into<String>) -> Self {
        self.assessment.dbms_hypothesis = Some(dbms.into());
        self
    }

    pub fn technique(mut self, technique: impl Into<String>) -> Self {
        self.assessment.techniques_observed.push(technique.into());
        self
    }

    pub fn signal(mut self, signal: impl Into<String>) -> Self {
        self.assessment.signals.push(signal.into());
        self
    }

    pub fn evidence(mut self, id: uuid::Uuid) -> Self {
        self.assessment.evidence_ids.push(id);
        self
    }

    pub fn repeatability(mut self, r: Repeatability) -> Self {
        self.assessment.repeatability = r;
        self
    }

    pub fn confidence(mut self, score: i32, level: ConfidenceLevel) -> Self {
        self.assessment.confidence = score;
        self.assessment.confidence_level = level;
        self
    }

    pub fn limitation(mut self, limitation: Limitation) -> Self {
        self.assessment.limitations.push(limitation);
        self
    }

    pub fn uncertainty(mut self, note: impl Into<String>) -> Self {
        self.assessment.uncertainty.push(note.into());
        self
    }

    /// Finalize. Fails when a finding stronger than `None` carries no
    /// limitations — the core guarantee of this module.
    pub fn build(self) -> Result<SqlInjectionAssessment, AssessmentError> {
        let asserts_finding = self.assessment.confidence_level != ConfidenceLevel::None;
        if asserts_finding && self.assessment.limitations.is_empty() {
            return Err(AssessmentError::MissingLimitations);
        }
        Ok(self.assessment)
    }

    /// Human summary for the CLI.
    pub fn summary(&self) -> String {
        format!(
            "{} on {} ({}) — {}",
            self.assessment.parameter,
            self.assessment.endpoint,
            self.assessment.input_location,
            self.assessment.confidence_level_label()
        )
    }
}

impl SqlInjectionAssessment {
    fn confidence_level_label(&self) -> &'static str {
        match self.confidence_level {
            ConfidenceLevel::None => "no finding",
            ConfidenceLevel::Low => "LOW confidence",
            ConfidenceLevel::Medium => "MEDIUM confidence",
            ConfidenceLevel::High => "HIGH confidence",
        }
    }

    /// Whether this assessment asserts an actual finding.
    pub fn asserts_finding(&self) -> bool {
        self.confidence_level != ConfidenceLevel::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_without_limitations_is_rejected() {
        let result = AssessmentBuilder::new("t", "/e", "id", "query")
            .confidence(50, ConfidenceLevel::Medium)
            .build();
        assert!(matches!(result, Err(AssessmentError::MissingLimitations)));
    }

    #[test]
    fn no_finding_needs_no_limitations() {
        let result = AssessmentBuilder::new("t", "/e", "id", "query").build();
        assert!(result.is_ok());
        assert!(!result.unwrap().asserts_finding());
    }

    #[test]
    fn finding_with_limitation_is_accepted() {
        let a = AssessmentBuilder::new("t", "/e", "id", "query")
            .confidence(50, ConfidenceLevel::Medium)
            .limitation(Limitation::new(
                LimitationCategory::NetworkVariance,
                "timing evidence weakened by jitter",
            ))
            .build()
            .unwrap();
        assert!(a.asserts_finding());
        assert_eq!(a.limitations.len(), 1);
    }

    #[test]
    fn builder_populates_all_fields() {
        let a = AssessmentBuilder::new("example.test", "/api/search", "q", "json")
            .context("string")
            .query_position("WHERE")
            .dbms("PostgreSQL")
            .technique("ErrorInjection")
            .technique("BooleanDifferential")
            .signal("syntax error at or near")
            .repeatability(Repeatability::ControlledAndRepeated)
            .confidence(75, ConfidenceLevel::High)
            .limitation(Limitation::new(
                LimitationCategory::DbmsAmbiguity,
                "could not distinguish PostgreSQL from compatible drivers",
            ))
            .uncertainty("timing probes not attempted")
            .build()
            .unwrap();
        assert_eq!(a.context.as_deref(), Some("string"));
        assert_eq!(a.query_position.as_deref(), Some("WHERE"));
        assert_eq!(a.dbms_hypothesis.as_deref(), Some("PostgreSQL"));
        assert_eq!(a.techniques_observed.len(), 2);
        assert_eq!(a.repeatability, Repeatability::ControlledAndRepeated);
        assert_eq!(a.uncertainty.len(), 1);
    }

    #[test]
    fn limitation_categories_have_labels() {
        assert_eq!(LimitationCategory::NetworkVariance.label(), "network variance");
        assert_eq!(LimitationCategory::DbmsAmbiguity.label(), "DBMS ambiguity");
    }
}
