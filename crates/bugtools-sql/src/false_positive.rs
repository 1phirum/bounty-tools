//! False-positive engine (brief §27).
//!
//! Before any conclusion is reached, run explicit contradiction checks. Each
//! check can raise a *contradiction* that reduces confidence; some are severe
//! enough to block a finding entirely. This is the module that stops the
//! engine reporting SQLi when the real explanation is cache, WAF, session
//! expiry, or an unstable endpoint.

use serde::{Deserialize, Serialize};

/// The kind of contradiction check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContradictionKind {
    /// Response variation exists between identical requests (baseline noise).
    RandomVariation,
    /// A caching layer is serving stale/varied content.
    CacheBehavior,
    /// Rate limiting changed the response.
    RateLimiting,
    /// A WAF or bot challenge interfered.
    WafBehavior,
    /// The session expired mid-run.
    SessionExpiry,
    /// CSRF or another rotating token changed between requests.
    TokenRotation,
    /// The page contains dynamic content between requests.
    DynamicContent,
    /// Network jitter explains a timing difference.
    NetworkInstability,
    /// An application error unrelated to input parsing.
    UnrelatedApplicationError,
    /// A redirect changed the resource being compared.
    RedirectChange,
    /// The backend was unavailable for some requests.
    BackendOutage,
}

impl ContradictionKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::RandomVariation => "random response variation",
            Self::CacheBehavior => "cache behaviour",
            Self::RateLimiting => "rate limiting",
            Self::WafBehavior => "WAF/bot interference",
            Self::SessionExpiry => "session expiry",
            Self::TokenRotation => "token rotation",
            Self::DynamicContent => "dynamic content",
            Self::NetworkInstability => "network instability",
            Self::UnrelatedApplicationError => "unrelated application error",
            Self::RedirectChange => "redirect change",
            Self::BackendOutage => "backend outage",
        }
    }

    /// Whether this contradiction is severe enough to block a finding.
    /// Severe causes are environmental — a finding built on them is invalid.
    pub fn blocks_finding(&self) -> bool {
        matches!(
            self,
            Self::WafBehavior
                | Self::SessionExpiry
                | Self::RateLimiting
                | Self::BackendOutage
                | Self::RedirectChange
        )
    }
}

/// A raised contradiction with its impact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contradiction {
    pub kind: ContradictionKind,
    pub detail: String,
    /// Confidence points this contradiction removes.
    pub confidence_penalty: i32,
}

impl Contradiction {
    pub fn new(kind: ContradictionKind, detail: impl Into<String>) -> Self {
        let penalty = match kind {
            ContradictionKind::WafBehavior | ContradictionKind::BackendOutage => 60,
            ContradictionKind::SessionExpiry | ContradictionKind::RateLimiting => 50,
            ContradictionKind::RedirectChange => 35,
            ContradictionKind::RandomVariation | ContradictionKind::NetworkInstability => 30,
            ContradictionKind::DynamicContent | ContradictionKind::TokenRotation => 20,
            ContradictionKind::CacheBehavior => 25,
            ContradictionKind::UnrelatedApplicationError => 15,
        };
        Self {
            kind,
            detail: detail.into(),
            confidence_penalty: penalty,
        }
    }
}

/// Inputs the checks reason over. Callers fill only what they observed;
/// absent signals do not fabricate contradictions.
#[derive(Debug, Clone, Default)]
pub struct FalsePositiveSignals {
    /// Varying status codes observed across identical baseline requests.
    pub baseline_statuses: Vec<u16>,
    /// Varying body lengths across identical baseline requests.
    pub baseline_lengths: Vec<usize>,
    /// Whether a rate-limit response was seen at any point.
    pub rate_limited_seen: bool,
    /// Whether a WAF/bot challenge was seen.
    pub waf_seen: bool,
    /// Whether an auth failure / login redirect was seen.
    pub auth_failure_seen: bool,
    /// Whether identical requests produced different bodies.
    pub body_varied_identical_requests: bool,
    /// Whether a redirect target changed between requests.
    pub redirect_changed: bool,
    /// Whether the backend returned 5xx during the run.
    pub server_errors_seen: bool,
    /// A rotating token name that changed value (e.g. csrf).
    pub rotated_token: Option<String>,
}

/// The outcome of running all contradiction checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositiveReport {
    pub contradictions: Vec<Contradiction>,
    /// Recommendations for what to fix before re-running.
    pub remediation: Vec<String>,
}

impl FalsePositiveReport {
    /// Whether any contradiction is severe enough to block a finding.
    pub fn blocks_finding(&self) -> bool {
        self.contradictions.iter().any(|c| c.kind.blocks_finding())
    }

    /// Total confidence penalty across contradictions.
    pub fn total_penalty(&self) -> i32 {
        self.contradictions.iter().map(|c| c.confidence_penalty).sum()
    }

    pub fn is_clean(&self) -> bool {
        self.contradictions.is_empty()
    }
}

/// Run every contradiction check against the observed signals.
pub fn run_checks(signals: &FalsePositiveSignals) -> FalsePositiveReport {
    let mut contradictions = Vec::new();

    // Baseline instability: identical requests disagreeing.
    let distinct_statuses: std::collections::HashSet<_> = signals.baseline_statuses.iter().collect();
    if distinct_statuses.len() > 1 {
        contradictions.push(Contradiction::new(
            ContradictionKind::RandomVariation,
            format!("baseline returned {} distinct status codes", distinct_statuses.len()),
        ));
    }
    if signals.body_varied_identical_requests {
        contradictions.push(Contradiction::new(
            ContradictionKind::DynamicContent,
            "identical requests returned different response bodies",
        ));
    }

    if signals.rate_limited_seen {
        contradictions.push(Contradiction::new(
            ContradictionKind::RateLimiting,
            "a rate-limit response was observed during the run",
        ));
    }
    if signals.waf_seen {
        contradictions.push(Contradiction::new(
            ContradictionKind::WafBehavior,
            "a WAF or bot challenge was observed",
        ));
    }
    if signals.auth_failure_seen {
        contradictions.push(Contradiction::new(
            ContradictionKind::SessionExpiry,
            "an authentication failure was observed",
        ));
    }
    if signals.redirect_changed {
        contradictions.push(Contradiction::new(
            ContradictionKind::RedirectChange,
            "the redirect target changed between requests",
        ));
    }
    if signals.server_errors_seen {
        contradictions.push(Contradiction::new(
            ContradictionKind::BackendOutage,
            "5xx responses were observed during the run",
        ));
    }
    if let Some(token) = &signals.rotated_token {
        contradictions.push(Contradiction::new(
            ContradictionKind::TokenRotation,
            format!("{token} changed value between requests"),
        ));
    }

    // Remediation guidance derived from what actually fired.
    let mut remediation = Vec::new();
    if signals.body_varied_identical_requests || distinct_statuses.len() > 1 {
        remediation.push(
            "Establish a stable baseline: repeat the unmodified request until responses agree."
                .to_string(),
        );
    }
    if signals.rate_limited_seen {
        remediation.push("Lower the request rate and re-run.".to_string());
    }
    if signals.waf_seen {
        remediation.push(
            "A WAF is interfering; results cannot be attributed to SQL behaviour.".to_string(),
        );
    }
    if signals.auth_failure_seen {
        remediation.push("Refresh the session and confirm authentication before re-running.".to_string());
    }
    if signals.server_errors_seen {
        remediation.push("The backend was unstable; re-run when it is healthy.".to_string());
    }

    FalsePositiveReport {
        contradictions,
        remediation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_signals_produce_no_contradictions() {
        let report = run_checks(&FalsePositiveSignals::default());
        assert!(report.is_clean());
        assert!(!report.blocks_finding());
        assert_eq!(report.total_penalty(), 0);
    }

    #[test]
    fn waf_blocks_finding() {
        let signals = FalsePositiveSignals {
            waf_seen: true,
            ..Default::default()
        };
        let report = run_checks(&signals);
        assert!(report.blocks_finding());
        assert!(report.remediation.iter().any(|r| r.contains("WAF")));
    }

    #[test]
    fn session_expiry_blocks_finding() {
        let signals = FalsePositiveSignals {
            auth_failure_seen: true,
            ..Default::default()
        };
        assert!(run_checks(&signals).blocks_finding());
    }

    #[test]
    fn dynamic_content_penalises_but_does_not_block() {
        let signals = FalsePositiveSignals {
            body_varied_identical_requests: true,
            ..Default::default()
        };
        let report = run_checks(&signals);
        assert!(!report.blocks_finding());
        assert!(report.total_penalty() > 0);
    }

    #[test]
    fn unstable_baseline_flagged() {
        let signals = FalsePositiveSignals {
            baseline_statuses: vec![200, 200, 500],
            ..Default::default()
        };
        let report = run_checks(&signals);
        assert!(report
            .contradictions
            .iter()
            .any(|c| c.kind == ContradictionKind::RandomVariation));
        assert!(report.remediation.iter().any(|r| r.contains("baseline")));
    }

    #[test]
    fn token_rotation_flagged() {
        let signals = FalsePositiveSignals {
            rotated_token: Some("csrf".into()),
            ..Default::default()
        };
        let report = run_checks(&signals);
        assert!(report
            .contradictions
            .iter()
            .any(|c| c.kind == ContradictionKind::TokenRotation));
    }

    #[test]
    fn penalty_accumulates() {
        let signals = FalsePositiveSignals {
            waf_seen: true,
            rate_limited_seen: true,
            ..Default::default()
        };
        let report = run_checks(&signals);
        assert_eq!(report.contradictions.len(), 2);
        assert!(report.total_penalty() >= 100);
    }
}
