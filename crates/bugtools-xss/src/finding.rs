//! Mapping from an XSS assessment to a BugTools finding.
//!
//! This is the single place that decides whether an assessment becomes a
//! finding, and it enforces the engine's core invariant: only a *confirmed*
//! assessment (browser-observed execution) may produce one.
//!
//! The severity is deliberately conservative. The engine has no impact
//! evidence model yet, and proven execution is not proven impact — so a
//! confirmed XSS is reported as `Medium` with the impact gap stated in its
//! notes, rather than inflated to `High`/`Critical` on speculation.

use bugtools_core::finding::{Confidence, Finding, FindingStatus, Severity};
use chrono::Utc;
use uuid::Uuid;

use crate::assessment::XssAssessment;

impl XssAssessment {
    /// Produce a finding, but only when execution was confirmed. Nothing
    /// short of `ExecutionConfirmed` may create one.
    pub fn to_finding(&self, project_id: Uuid) -> Option<Finding> {
        if !self.confirmed {
            return None;
        }

        let parameter = self.parameter.as_deref().unwrap_or("-");
        let mut notes = String::from(
            "Execution was confirmed by browser evidence; impact has not been \
             assessed, so severity stays conservative.",
        );
        if !self.limitations.is_empty() {
            notes.push_str(" Limitations: ");
            notes.push_str(&self.limitations.join("; "));
        }

        let now = Utc::now();
        Some(Finding {
            id: Uuid::new_v4(),
            project_id,
            title: format!("XSS via {parameter} at {}", self.endpoint),
            severity: Severity::Medium,
            confidence: Confidence::High,
            status: FindingStatus::Verified,
            target: self.target.clone(),
            endpoint: self.endpoint.clone(),
            parameter: self.parameter.clone(),
            module: "xss".to_string(),
            technique: self.exploitability_stage.label().to_string(),
            dbms_hypothesis: None,
            notes: Some(notes),
            created_at: now,
            updated_at: now,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assessment::AssessmentBuilder;
    use crate::exploitability::{ExploitabilityMachine, ObservationKind, XssObservation};

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
    fn unconfirmed_assessment_makes_no_finding() {
        let mut m = ExploitabilityMachine::new();
        m.observe(XssObservation {
            kind: ObservationKind::Reflection,
            evidence_id: "e1".into(),
            detail: "reflected".into(),
        })
        .unwrap();
        let a = AssessmentBuilder::new("t.test", "/item")
            .parameter("q")
            .exploitability(&m)
            .build()
            .unwrap();
        assert!(a.to_finding(Uuid::nil()).is_none());
    }

    #[test]
    fn confirmed_assessment_makes_a_verified_finding() {
        let m = machine_at_execution();
        let a = AssessmentBuilder::new("t.test", "/item")
            .parameter("q")
            .exploitability(&m)
            .limitation("impact not assessed")
            .build()
            .unwrap();
        let f = a.to_finding(Uuid::nil()).expect("confirmed must produce a finding");
        assert_eq!(f.status, FindingStatus::Verified);
        assert_eq!(f.module, "xss");
        assert_eq!(f.technique, "EXECUTION_CONFIRMED");
        assert_eq!(f.parameter.as_deref(), Some("q"));
    }

    #[test]
    fn severity_is_conservative_until_impact_is_proven() {
        let m = machine_at_execution();
        let a = AssessmentBuilder::new("t.test", "/item")
            .exploitability(&m)
            .limitation("x")
            .build()
            .unwrap();
        let f = a.to_finding(Uuid::nil()).unwrap();
        assert_eq!(
            f.severity,
            Severity::Medium,
            "execution alone must not be inflated past Medium"
        );
        assert!(f.notes.as_deref().unwrap_or("").contains("impact"));
    }

    #[test]
    fn finding_records_limitations() {
        let m = machine_at_execution();
        let a = AssessmentBuilder::new("t.test", "/item")
            .exploitability(&m)
            .limitation("browser evidence is single-run")
            .build()
            .unwrap();
        let f = a.to_finding(Uuid::nil()).unwrap();
        assert!(f
            .notes
            .as_deref()
            .unwrap_or("")
            .contains("browser evidence is single-run"));
    }
}
