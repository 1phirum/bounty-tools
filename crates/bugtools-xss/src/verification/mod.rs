//! Browser verification boundary.
//!
//! Static analysis can prove *reachability*; only a browser can prove
//! *execution*. This module defines the contract between the two without
//! pulling a browser into the analyzer:
//!
//! ```text
//! static candidate → VerificationRequest → browser worker
//!                                            ↓
//!                                     ExecutionEvidence
//!                                            ↓
//!                                  VerificationResult
//!                                            ↓
//!                              exploitability observations
//! ```
//!
//! The analyzer describes what to verify and which harmless marker would
//! prove execution. A browser worker (a separate crate, behind this trait)
//! carries it out. `confirm_on_execution` consumes the result, so the only
//! path to `ExecutionConfirmed` runs through this interface.
//!
//! ## Safety
//!
//! Every request carries [`VerificationSafety`], whose default is maximally
//! restrictive: non-destructive, low-rate, single-target, scope-checked and
//! reproducible. A verifier must refuse any request whose constraints are
//! not enforced. Markers are harmless signals (a global property, a DOM
//! node, a console string) — never destructive or exfiltrating payloads.

use crate::exploitability::{ObservationKind, XssObservation};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A request to verify one static candidate in a real browser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequest {
    /// Correlates back to the static candidate that motivated this request.
    pub candidate_id: Uuid,
    /// The exact URL to load.
    pub url: String,
    /// The parameter the candidate was found in.
    pub parameter: String,
    /// The probe value as submitted (harmless; no destructive payload).
    pub submitted: String,
    /// The sink static analysis reached, e.g. `innerHTML`.
    pub expected_sink: String,
    /// The harmless signal execution would produce.
    pub execution_marker: ExecutionMarker,
    /// Safety constraints the verifier must honour.
    pub safety: VerificationSafety,
}

impl VerificationRequest {
    /// Build a request for a candidate, applying the default (maximally
    /// safe) constraints.
    pub fn new(
        candidate_id: Uuid,
        url: impl Into<String>,
        parameter: impl Into<String>,
        submitted: impl Into<String>,
        expected_sink: impl Into<String>,
        execution_marker: ExecutionMarker,
    ) -> Self {
        Self {
            candidate_id,
            url: url.into(),
            parameter: parameter.into(),
            submitted: submitted.into(),
            expected_sink: expected_sink.into(),
            execution_marker,
            safety: VerificationSafety::default(),
        }
    }
}

/// A harmless signal that proves code execution. The payload is constructed
/// to produce this marker; the verifier observes whether it appeared. No
/// marker ever causes destruction, exfiltration, or third-party impact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMarker {
    /// A unique value assigned to a global property, e.g.
    /// `window.__bt_executed = "<uuid>"`.
    GlobalProperty {
        property: String,
        value: String,
    },
    /// An element with a known selector appears in the DOM via injected
    /// markup, e.g. `#bt-marker-<uuid>`.
    DomNode {
        selector: String,
    },
    /// A unique string reaches the console (a log line or an exception
    /// message), e.g. `console.log("<uuid>")`.
    ConsoleSignal(String),
}

impl ExecutionMarker {
    /// Generate the standard marker for a candidate: a unique global
    /// property that cannot collide with page code.
    pub fn for_candidate(candidate_id: Uuid) -> Self {
        Self::GlobalProperty {
            property: "__bt_executed".to_string(),
            value: format!("bt-exec-{}", candidate_id.simple()),
        }
    }
}

/// The browser's observation of one verification attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEvidence {
    pub id: Uuid,
    /// The request this evidence belongs to.
    pub request_id: Uuid,
    pub kind: ExecutionEvidenceKind,
    /// Whether the marker actually fired.
    pub marker_observed: bool,
    pub detail: String,
    pub browser: BrowserEnvironment,
    pub observed_at: DateTime<Utc>,
}

/// What the browser observed, independent of whether it proves execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionEvidenceKind {
    /// The DOM mutated as the candidate predicted.
    DomMutation,
    /// JavaScript executed.
    JavaScriptExecuted,
    /// Navigation occurred.
    Navigation,
    /// A console signal fired.
    ConsoleSignal,
    /// An exception was thrown.
    Exception,
    /// A Content-Security-Policy directive blocked the execution.
    CspViolation,
    /// A Trusted Types policy rejected the value.
    TrustedTypesViolation,
}

/// The outcome of a verification attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum VerificationResult {
    /// Execution was observed: the marker fired in the browser.
    Executed(ExecutionEvidence),
    /// A security control (CSP, Trusted Types, sanitizer) blocked execution.
    Mitigated {
        evidence: ExecutionEvidence,
        policy: MitigationPolicy,
    },
    /// The payload did not execute; no marker fired.
    NotExecuted {
        reason: String,
    },
    /// The verifier declined to run at all (no browser available, safety or
    /// scope refusal). The static assessment stands unchanged.
    Declined {
        reason: String,
    },
}

/// The defense that blocked execution, when one did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MitigationPolicy {
    ContentSecurityPolicy,
    TrustedTypes,
    Sanitizer,
    Other,
}

impl VerificationResult {
    /// Whether execution was actually confirmed.
    pub fn executed(&self) -> bool {
        matches!(self, Self::Executed(_))
    }

    /// Convert the result into the observations that advance the
    /// exploitability machine. This is the only route from a browser result
    /// into the state machine.
    pub fn into_observations(self) -> Vec<XssObservation> {
        match self {
            Self::Executed(evidence) => vec![XssObservation {
                kind: ObservationKind::ExecutionObserved,
                evidence_id: evidence.id.to_string(),
                detail: format!("browser observed execution: {}", evidence.detail),
            }],
            Self::Mitigated { evidence, policy } => vec![XssObservation {
                kind: ObservationKind::Mitigation,
                evidence_id: evidence.id.to_string(),
                detail: format!("{policy:?} blocked execution: {}", evidence.detail),
            }],
            // No marker fired: the evidence is insufficient to advance, and
            // this is explicitly *not* proof of safety.
            Self::NotExecuted { reason } => vec![XssObservation {
                kind: ObservationKind::Inconclusive,
                evidence_id: "verifier".to_string(),
                detail: format!("payload did not execute: {reason}"),
            }],
            // The verifier never ran: no observation, the static assessment
            // stands exactly as static analysis left it.
            Self::Declined { .. } => Vec::new(),
        }
    }
}

/// The browser environment a verification ran in, for reproducibility.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserEnvironment {
    pub user_agent: Option<String>,
    /// The Content-Security-Policy in force, if one was observed.
    pub content_security_policy: Option<String>,
    /// Whether the page required Trusted Types.
    pub trusted_types_required: bool,
}

/// Safety constraints every verification must honour. The default is
/// maximally restrictive; there is no constructor that lifts a constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationSafety {
    /// Never delete data, modify accounts, or act destructively.
    pub non_destructive: bool,
    /// Rate-limited; one verification at a time.
    pub low_rate: bool,
    /// Only the target named in the request; never a third party.
    pub single_target: bool,
    /// The target passed scope checks before this request.
    pub scope_checked: bool,
    /// The test is deterministic and repeatable.
    pub reproducible: bool,
}

impl Default for VerificationSafety {
    fn default() -> Self {
        Self {
            non_destructive: true,
            low_rate: true,
            single_target: true,
            scope_checked: true,
            reproducible: true,
        }
    }
}

impl VerificationSafety {
    /// Whether every constraint is in force. Verifiers must refuse requests
    /// for which this is false.
    pub fn enforced(&self) -> bool {
        self.non_destructive
            && self.low_rate
            && self.single_target
            && self.scope_checked
            && self.reproducible
    }
}

/// A browser verification worker. Implementations live outside the analyzer
/// (a dedicated browser crate); the analyzer depends only on this trait.
#[async_trait::async_trait]
pub trait BrowserVerifier: Send + Sync {
    /// Verify one static candidate in a real browser. Never panics on
    /// verification failure — scope, safety and availability problems are
    /// reported as [`VerificationResult::Declined`].
    async fn verify(&self, request: &VerificationRequest) -> VerificationResult;
}

/// The honest default: no browser is available. Every request is declined,
/// so nothing can reach `ExecutionConfirmed` without a real verifier. This
/// is what the engine uses until a browser crate supplies an implementor.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoVerifier;

#[async_trait::async_trait]
impl BrowserVerifier for NoVerifier {
    async fn verify(&self, _request: &VerificationRequest) -> VerificationResult {
        VerificationResult::Declined {
            reason: "no browser verifier is configured; execution cannot be confirmed"
                .to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(request_id: Uuid, kind: ExecutionEvidenceKind) -> ExecutionEvidence {
        ExecutionEvidence {
            id: Uuid::new_v4(),
            request_id,
            kind,
            marker_observed: true,
            detail: "marker fired".to_string(),
            browser: BrowserEnvironment::default(),
            observed_at: Utc::now(),
        }
    }

    #[test]
    fn default_safety_is_maximally_restrictive() {
        let s = VerificationSafety::default();
        assert!(s.enforced(), "the default safety profile must be enforced");
        assert!(s.non_destructive);
        assert!(s.single_target);
    }

    #[test]
    fn lifting_any_constraint_disables_enforcement() {
        let mut s = VerificationSafety::default();
        s.reproducible = false;
        assert!(!s.enforced());
    }

    #[test]
    fn candidate_marker_is_unique_and_namespaced() {
        let a = ExecutionMarker::for_candidate(Uuid::new_v4());
        let b = ExecutionMarker::for_candidate(Uuid::new_v4());
        assert_ne!(a, b, "two candidates must not share a marker");
        match &a {
            ExecutionMarker::GlobalProperty { property, .. } => {
                assert_eq!(property, "__bt_executed");
            }
            _ => panic!("expected a global-property marker"),
        }
    }

    #[test]
    fn executed_result_is_the_only_execution() {
        let id = Uuid::new_v4();
        assert!(VerificationResult::Executed(evidence(id, ExecutionEvidenceKind::JavaScriptExecuted)).executed());
        assert!(!VerificationResult::NotExecuted { reason: "x".into() }.executed());
        assert!(!VerificationResult::Declined { reason: "x".into() }.executed());
    }

    #[test]
    fn executed_becomes_execution_observed() {
        let id = Uuid::new_v4();
        let result = VerificationResult::Executed(evidence(id, ExecutionEvidenceKind::DomMutation));
        let obs = result.into_observations();
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].kind, ObservationKind::ExecutionObserved);
        assert!(!obs[0].evidence_id.is_empty());
    }

    #[test]
    fn mitigated_becomes_mitigation_observation() {
        let id = Uuid::new_v4();
        let result = VerificationResult::Mitigated {
            evidence: evidence(id, ExecutionEvidenceKind::CspViolation),
            policy: MitigationPolicy::ContentSecurityPolicy,
        };
        let obs = result.into_observations();
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].kind, ObservationKind::Mitigation);
        assert!(obs[0].detail.contains("ContentSecurityPolicy"));
    }

    #[test]
    fn not_executed_is_inconclusive_not_proof_of_safety() {
        let result = VerificationResult::NotExecuted {
            reason: "no marker within timeout".into(),
        };
        let obs = result.into_observations();
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].kind, ObservationKind::Inconclusive);
    }

    #[test]
    fn declined_produces_no_observations() {
        let result = VerificationResult::Declined { reason: "no browser".into() };
        assert!(result.into_observations().is_empty());
    }

    #[tokio::test]
    async fn no_verifier_always_declines() {
        let verifier = NoVerifier;
        let request = VerificationRequest::new(
            Uuid::new_v4(),
            "https://t.test/",
            "q",
            "probe",
            "innerHTML",
            ExecutionMarker::for_candidate(Uuid::new_v4()),
        );
        match verifier.verify(&request).await {
            VerificationResult::Declined { reason } => {
                assert!(reason.contains("no browser verifier"));
            }
            other => panic!("NoVerifier must decline, got {other:?}"),
        }
    }

    #[test]
    fn request_applies_default_safety() {
        let request = VerificationRequest::new(
            Uuid::new_v4(),
            "https://t.test/",
            "q",
            "probe",
            "innerHTML",
            ExecutionMarker::for_candidate(Uuid::new_v4()),
        );
        assert!(request.safety.enforced());
        assert_eq!(request.expected_sink, "innerHTML");
    }

    #[test]
    fn evidence_kinds_serialize() {
        let kind = ExecutionEvidenceKind::TrustedTypesViolation;
        let json = serde_json::to_string(&kind).unwrap();
        assert!(json.contains("trusted_types_violation"));
    }
}
