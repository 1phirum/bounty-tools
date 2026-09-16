//! Final XSS assessment (brief §20) and the engine that produces it.
//!
//! The `confirmed` flag has exactly one source of truth: the exploitability
//! machine reaching `ExecutionConfirmed`. Nothing else may set it, and
//! limitations are mandatory whenever a finding is asserted.

use crate::confidence::{ConfidenceAssessment, ConfidenceLevel};
use crate::exploitability::{ExploitabilityMachine, ExploitabilityStage, StageTransition};
use crate::parser::{HtmlParseContext, JavaScriptParseContext};
use crate::strategy::RenderingModel;
use crate::technology::TechnologyFinding;
use serde::{Deserialize, Serialize};

/// Where a reflection was found and how it was encoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentReflection {
    pub parameter: String,
    pub response_offset: usize,
    pub length: usize,
    pub encoding: String,
    /// Parsed HTML context, when parsing succeeded.
    pub html_context: Option<HtmlParseContext>,
    /// Parsed JavaScript context, when the reflection is inside a script.
    pub js_context: Option<JavaScriptParseContext>,
}

/// The complete assessment for one target/endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssAssessment {
    pub target: String,
    pub endpoint: String,
    pub parameter: Option<String>,

    pub technology: Vec<TechnologyFinding>,
    pub rendering_model: RenderingModel,

    pub reflection: Option<AssessmentReflection>,

    pub exploitability_stage: ExploitabilityStage,
    pub transitions: Vec<StageTransition>,

    pub confidence: ConfidenceAssessment,
    /// True only when the exploitability stage is ExecutionConfirmed.
    pub confirmed: bool,
    pub limitations: Vec<String>,
    pub remaining_uncertainty: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AssessmentError {
    #[error(
        "a finding was asserted without limitations; every finding must state what weakens it"
    )]
    MissingLimitations,
}

/// Builder that enforces the limitations rule.
#[derive(Debug, Clone)]
pub struct AssessmentBuilder {
    assessment: XssAssessment,
}

impl AssessmentBuilder {
    pub fn new(target: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            assessment: XssAssessment {
                target: target.into(),
                endpoint: endpoint.into(),
                parameter: None,
                technology: Vec::new(),
                rendering_model: RenderingModel::Unknown,
                reflection: None,
                exploitability_stage: ExploitabilityStage::NotObserved,
                transitions: Vec::new(),
                confidence: ConfidenceAssessment {
                    score: 0.0,
                    level: ConfidenceLevel::Unknown,
                    explanation: Vec::new(),
                    independent_sources: 0,
                    conflicts: 0,
                },
                confirmed: false,
                limitations: Vec::new(),
                remaining_uncertainty: Vec::new(),
            },
        }
    }

    pub fn parameter(mut self, p: impl Into<String>) -> Self {
        self.assessment.parameter = Some(p.into());
        self
    }

    pub fn technology(mut self, findings: Vec<TechnologyFinding>) -> Self {
        self.assessment.technology = findings;
        self
    }

    pub fn rendering_model(mut self, model: RenderingModel) -> Self {
        self.assessment.rendering_model = model;
        self
    }

    pub fn reflection(mut self, r: AssessmentReflection) -> Self {
        self.assessment.reflection = Some(r);
        self
    }

    /// Take the stage and transition history from the machine. `confirmed`
    /// is derived here and nowhere else.
    pub fn exploitability(mut self, machine: &ExploitabilityMachine) -> Self {
        self.assessment.exploitability_stage = machine.current;
        self.assessment.transitions = machine.transitions.clone();
        self.assessment.confirmed = machine.current.is_finding();
        self
    }

    pub fn confidence(mut self, c: ConfidenceAssessment) -> Self {
        self.assessment.confidence = c;
        self
    }

    pub fn limitation(mut self, l: impl Into<String>) -> Self {
        self.assessment.limitations.push(l.into());
        self
    }

    pub fn uncertainty(mut self, u: impl Into<String>) -> Self {
        self.assessment.remaining_uncertainty.push(u.into());
        self
    }

    /// Finalize. Fails when a finding is asserted without limitations.
    pub fn build(self) -> Result<XssAssessment, AssessmentError> {
        if self.assessment.confirmed && self.assessment.limitations.is_empty() {
            return Err(AssessmentError::MissingLimitations);
        }
        Ok(self.assessment)
    }
}

impl XssAssessment {
    /// A one-line summary for the console.
    pub fn summary(&self) -> String {
        format!(
            "{} {} — {} · confidence {}",
            self.endpoint,
            self.parameter.as_deref().unwrap_or("-"),
            self.exploitability_stage.label(),
            self.confidence.level.label()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exploitability::{ObservationKind, XssObservation};

    fn machine_at_execution() -> ExploitabilityMachine {
        let mut m = ExploitabilityMachine::new();
        for (i, kind) in [
            ObservationKind::Reflection,
            ObservationKind::ContextResolved,
            ObservationKind::ContextBreakout,
            ObservationKind::ContextBreakout,
            ObservationKind::SinkReachable,
            ObservationKind::SinkReachable,
            ObservationKind::SinkInvoked,
            ObservationKind::ExecutionAttempt,
            ObservationKind::ExecutionObserved,
        ]
        .into_iter()
        .enumerate()
        {
            m.observe(XssObservation {
                kind,
                evidence_id: format!("e{i}"),
                detail: "test".into(),
            })
            .unwrap();
        }
        m
    }

    #[test]
    fn confirmed_is_derived_only_from_the_machine() {
        let m = machine_at_execution();
        let a = AssessmentBuilder::new("t", "/e")
            .exploitability(&m)
            .limitation("browser evidence is single-run")
            .build()
            .unwrap();
        assert!(a.confirmed);
        assert_eq!(a.exploitability_stage, ExploitabilityStage::ExecutionConfirmed);
    }

    #[test]
    fn reflection_only_is_not_confirmed() {
        let mut m = ExploitabilityMachine::new();
        m.observe(XssObservation {
            kind: ObservationKind::Reflection,
            evidence_id: "e1".into(),
            detail: "reflected".into(),
        })
        .unwrap();
        let a = AssessmentBuilder::new("t", "/e").exploitability(&m).build().unwrap();
        assert!(!a.confirmed);
        assert_eq!(a.exploitability_stage, ExploitabilityStage::Reflected);
    }

    #[test]
    fn finding_without_limitations_is_rejected() {
        let m = machine_at_execution();
        let result = AssessmentBuilder::new("t", "/e").exploitability(&m).build();
        assert!(matches!(result, Err(AssessmentError::MissingLimitations)));
    }

    #[test]
    fn non_finding_needs_no_limitations() {
        let a = AssessmentBuilder::new("t", "/e").build().unwrap();
        assert!(!a.confirmed);
    }

    #[test]
    fn transitions_are_recorded() {
        let m = machine_at_execution();
        let a = AssessmentBuilder::new("t", "/e")
            .exploitability(&m)
            .limitation("x")
            .build()
            .unwrap();
        assert!(!a.transitions.is_empty());
        assert_eq!(a.transitions.len(), 9);
    }

    #[test]
    fn summary_mentions_stage_and_confidence() {
        let a = AssessmentBuilder::new("t", "/api/item")
            .parameter("id")
            .build()
            .unwrap();
        let s = a.summary();
        assert!(s.contains("/api/item"));
        assert!(s.contains("NOT_OBSERVED"));
    }
}
