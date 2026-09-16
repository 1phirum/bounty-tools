//! Adaptive probe scheduling (brief §12).
//!
//! Instead of running every probe against every parameter, the scheduler
//! scores candidate probes by expected information gain and picks the most
//! valuable *safe* one next. The scoring is explicit and inspectable: the
//! UI can show *why* a probe was chosen.

use serde::{Deserialize, Serialize};

/// A probe descriptor the scheduler can rank.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeCandidate {
    pub id: String,
    pub name: String,
    /// Which hypothesis labels this probe would help confirm or rule out.
    pub discriminates: Vec<String>,
    /// Estimated request cost (1 = single request, N = N requests).
    pub cost: u32,
    /// How reliable the probe's signal is when it fires (0.0–1.0).
    pub reliability: f32,
    /// Risk level: higher means more likely to be disruptive/noisy.
    pub risk: f32,
    /// Whether this probe has already been run for this parameter.
    pub already_run: bool,
}

/// The reason the scheduler selected a probe — surfaced in the UI so the
/// researcher understands the choice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulingDecision {
    pub probe_id: String,
    pub probe_name: String,
    pub score: f32,
    pub reason: String,
    pub expected_cost: u32,
}

/// Score a probe given current hypothesis uncertainty.
///
/// The score is: (discriminating power) × reliability ÷ (cost × risk penalty).
/// Probes that discriminate among *currently competing* hypotheses score
/// higher; already-run probes score zero.
pub fn score_probe(probe: &ProbeCandidate, competing_hypotheses: &[String]) -> f32 {
    if probe.already_run {
        return 0.0;
    }
    // Discriminating power: how many of the live hypotheses this probe
    // would help separate. At least 1.0 so a probe is never zero merely
    // because no hypothesis list was supplied.
    let overlap = probe
        .discriminates
        .iter()
        .filter(|d| competing_hypotheses.iter().any(|h| h == *d))
        .count() as f32;
    let discrimination = (overlap.max(1.0)).min(competing_hypotheses.len().max(1) as f32);

    let cost_penalty = probe.cost.max(1) as f32;
    let risk_penalty = 1.0 + probe.risk.max(0.0);

    (discrimination * probe.reliability.max(0.0)) / (cost_penalty * risk_penalty)
}

/// Pick the highest-value probe, returning the decision and its rationale.
/// Returns `None` when no probe is worth running.
pub fn select_next_probe(
    candidates: &[ProbeCandidate],
    competing_hypotheses: &[String],
) -> Option<SchedulingDecision> {
    let best = candidates
        .iter()
        .map(|p| (p, score_probe(p, competing_hypotheses)))
        .filter(|(_, score)| *score > 0.0)
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))?;

    let (probe, score) = best;
    let matched: Vec<&String> = probe
        .discriminates
        .iter()
        .filter(|d| competing_hypotheses.iter().any(|h| h == *d))
        .collect();

    let reason = if matched.is_empty() {
        format!(
            "Reliable low-cost probe ({} request{}, risk {:.1}); no competing hypotheses to target.",
            probe.cost,
            if probe.cost == 1 { "" } else { "s" },
            probe.risk
        )
    } else {
        format!(
            "Discriminates among {} live hypothesis(es) at cost {} and risk {:.1}.",
            matched.len(),
            probe.cost,
            probe.risk
        )
    };

    Some(SchedulingDecision {
        probe_id: probe.id.clone(),
        probe_name: probe.name.clone(),
        score,
        reason,
        expected_cost: probe.cost,
    })
}

/// Request budget guard (brief §21). Tracks consumption and refuses to
/// exceed configured limits.
#[derive(Debug, Clone)]
pub struct RequestBudget {
    pub max_requests: u64,
    pub used: u64,
    pub max_crawl_depth: u32,
    pub max_parameters: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDecision {
    Allowed,
    Exhausted,
}

impl RequestBudget {
    pub fn new(max_requests: u64) -> Self {
        Self {
            max_requests,
            used: 0,
            max_crawl_depth: 3,
            max_parameters: 500,
        }
    }

    /// Try to reserve `count` requests. Denies wholesale if it would exceed
    /// the budget — never partially consumes.
    pub fn try_reserve(&mut self, count: u64) -> BudgetDecision {
        if self.used + count > self.max_requests {
            BudgetDecision::Exhausted
        } else {
            self.used += count;
            BudgetDecision::Allowed
        }
    }

    pub fn remaining(&self) -> u64 {
        self.max_requests.saturating_sub(self.used)
    }

    pub fn is_exhausted(&self) -> bool {
        self.used >= self.max_requests
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(id: &str, cost: u32, reliability: f32, risk: f32, discriminates: &[&str]) -> ProbeCandidate {
        ProbeCandidate {
            id: id.into(),
            name: id.into(),
            discriminates: discriminates.iter().map(|s| s.to_string()).collect(),
            cost,
            reliability,
            risk,
            already_run: false,
        }
    }

    #[test]
    fn already_run_probes_score_zero() {
        let mut p = probe("baseline", 1, 1.0, 0.0, &["sql"]);
        p.already_run = true;
        assert_eq!(score_probe(&p, &["sql".into()]), 0.0);
    }

    #[test]
    fn expensive_probe_scores_lower() {
        let cheap = probe("cheap", 1, 1.0, 0.0, &["sql"]);
        let expensive = probe("timing", 6, 1.0, 0.2, &["sql"]);
        assert!(score_probe(&cheap, &["sql".into()]) > score_probe(&expensive, &["sql".into()]));
    }

    #[test]
    fn discriminating_probe_beats_generic() {
        let targeted = probe("ctx", 1, 0.9, 0.0, &["string_ctx", "numeric_ctx"]);
        let generic = probe("fmt", 1, 0.9, 0.0, &["unrelated"]);
        let hypotheses = vec!["string_ctx".to_string(), "numeric_ctx".to_string()];
        assert!(score_probe(&targeted, &hypotheses) > score_probe(&generic, &hypotheses));
    }

    #[test]
    fn scheduler_picks_highest_value() {
        let candidates = vec![
            probe("expensive", 6, 0.5, 0.3, &["sql"]),
            probe("cheap-reliable", 1, 0.95, 0.0, &["sql"]),
            probe("medium", 2, 0.8, 0.1, &["sql"]),
        ];
        let decision = select_next_probe(&candidates, &["sql".into()]).unwrap();
        assert_eq!(decision.probe_id, "cheap-reliable");
        assert!(decision.score > 0.0);
        assert!(!decision.reason.is_empty());
    }

    #[test]
    fn scheduler_returns_none_when_all_run() {
        let mut a = probe("a", 1, 1.0, 0.0, &["sql"]);
        a.already_run = true;
        assert!(select_next_probe(&[a], &["sql".into()]).is_none());
    }

    #[test]
    fn budget_reserves_or_denies_wholesale() {
        let mut b = RequestBudget::new(10);
        assert_eq!(b.try_reserve(4), BudgetDecision::Allowed);
        assert_eq!(b.remaining(), 6);
        // A 7-request batch must be denied entirely, not partially applied.
        assert_eq!(b.try_reserve(7), BudgetDecision::Exhausted);
        assert_eq!(b.remaining(), 6, "denied reservation must not consume budget");
        assert_eq!(b.try_reserve(6), BudgetDecision::Allowed);
        assert!(b.is_exhausted());
    }

    #[test]
    fn decision_reason_mentions_discrimination() {
        let candidates = vec![probe("ctx", 1, 0.9, 0.0, &["string_ctx"])];
        let d = select_next_probe(&candidates, &["string_ctx".into()]).unwrap();
        assert!(d.reason.contains("Discriminates"));
    }
}
