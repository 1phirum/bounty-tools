//! Repetition verification — the core reliability mechanism.
//!
//! A single differential proves nothing: dynamic content, cache, and timing
//! jitter all produce one-off differences. Before any signal is allowed to
//! raise confidence, the same test must be executed repeatedly and the
//! observation must reproduce. This module owns that rule.

use crate::adaptive::signals::{Signal, SignalKind};
use serde::{Deserialize, Serialize};

/// How many times a test must be executed before its result is trusted.
pub const REQUIRED_REPETITIONS: usize = 2;

/// One execution's outcome for a test.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Repetition {
    /// A stable description of what was observed (e.g. the signal set).
    pub outcome_signature: String,
    /// Strength of the strongest supporting signal in this execution.
    pub strength: f32,
}

/// The verdict for a repeatedly-executed test.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RepetitionVerdict {
    /// Not enough executions yet.
    Pending,
    /// Every execution produced the same outcome — trustworthy.
    Reproduced { strength: f32 },
    /// Executions disagreed — the observation is not reliable.
    Flaky { detail: String },
    /// Every execution produced no difference — a stable negative.
    ConsistentlyNoDifference,
}

impl RepetitionVerdict {
    /// Whether this verdict may contribute to confidence.
    pub fn is_trustworthy(&self) -> bool {
        matches!(
            self,
            Self::Reproduced { .. } | Self::ConsistentlyNoDifference
        )
    }

    pub fn label(&self) -> String {
        match self {
            Self::Pending => "pending".into(),
            Self::Reproduced { strength } => format!("reproduced ({strength:.2})"),
            Self::Flaky { .. } => "FLAKY".into(),
            Self::ConsistentlyNoDifference => "consistently-no-difference".into(),
        }
    }
}

/// Build a stable signature from a signal set: the ordered kinds plus a
/// coarse strength bucket, so minor jitter does not read as a difference.
pub fn outcome_signature(signals: &[Signal]) -> String {
    let mut kinds: Vec<(String, u32)> = signals
        .iter()
        .filter(|s| s.kind != SignalKind::NoDifference)
        .map(|s| {
            // Bucket strength to 1 decimal so 0.71 and 0.73 agree.
            let bucket = (s.strength * 10.0).round() as u32;
            (s.kind.label().to_string(), bucket)
        })
        .collect();
    kinds.sort();
    kinds.dedup();
    if kinds.is_empty() {
        "no_difference".to_string()
    } else {
        kinds
            .iter()
            .map(|(k, b)| format!("{k}@{b}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Accumulates repetitions for one test and decides whether to trust it.
#[derive(Debug, Clone, Default)]
pub struct RepetitionTracker {
    runs: Vec<Repetition>,
}

impl RepetitionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, signals: &[Signal]) {
        let strongest = signals
            .iter()
            .filter(|s| s.kind.supports_sql_hypothesis())
            .map(|s| s.strength)
            .fold(0.0f32, f32::max);
        self.runs.push(Repetition {
            outcome_signature: outcome_signature(signals),
            strength: strongest,
        });
    }

    pub fn runs(&self) -> usize {
        self.runs.len()
    }

    /// If the first run showed no difference, one more agreeing run settles it.
    /// Otherwise require `REQUIRED_REPETITIONS` agreeing runs.
    pub fn needed(&self) -> usize {
        match self.runs.first() {
            Some(first) if first.outcome_signature == "no_difference" => 2,
            _ => REQUIRED_REPETITIONS,
        }
    }

    /// Decide the verdict from what has been collected so far.
    pub fn verdict(&self) -> RepetitionVerdict {
        if self.runs.len() < self.needed() {
            return RepetitionVerdict::Pending;
        }
        let first = &self.runs[0];
        if first.outcome_signature == "no_difference"
            && self.runs.iter().all(|r| r.outcome_signature == "no_difference")
        {
            return RepetitionVerdict::ConsistentlyNoDifference;
        }
        if self.runs.iter().all(|r| r.outcome_signature == first.outcome_signature) {
            return RepetitionVerdict::Reproduced {
                strength: self.runs.iter().map(|r| r.strength).fold(0.0f32, f32::max),
            };
        }
        let distinct: std::collections::BTreeSet<&str> = self
            .runs
            .iter()
            .map(|r| r.outcome_signature.as_str())
            .collect();
        RepetitionVerdict::Flaky {
            detail: format!(
                "{} differing outcomes across {} runs: {}",
                distinct.len(),
                self.runs.len(),
                distinct.into_iter().collect::<Vec<_>>().join(" vs ")
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(kind: SignalKind, strength: f32) -> Signal {
        Signal::new(kind, strength, "b", "o")
    }

    #[test]
    fn single_run_is_pending() {
        let mut t = RepetitionTracker::new();
        t.push(&[sig(SignalKind::StatusChanged, 0.7)]);
        assert_eq!(t.verdict(), RepetitionVerdict::Pending);
        assert!(!t.verdict().is_trustworthy());
    }

    #[test]
    fn identical_runs_reproduce() {
        let mut t = RepetitionTracker::new();
        let s = [sig(SignalKind::StatusChanged, 0.7)];
        t.push(&s);
        t.push(&s);
        assert!(matches!(t.verdict(), RepetitionVerdict::Reproduced { .. }));
        assert!(t.verdict().is_trustworthy());
    }

    #[test]
    fn disagreeing_runs_are_flaky() {
        let mut t = RepetitionTracker::new();
        t.push(&[sig(SignalKind::StatusChanged, 0.7)]);
        t.push(&[sig(SignalKind::NoDifference, 0.0)]);
        assert!(matches!(t.verdict(), RepetitionVerdict::Flaky { .. }));
        assert!(!t.verdict().is_trustworthy(), "a flaky result must not be trusted");
    }

    #[test]
    fn consistent_no_difference_settles() {
        let mut t = RepetitionTracker::new();
        let s = [sig(SignalKind::NoDifference, 0.0)];
        t.push(&s);
        t.push(&s);
        assert_eq!(t.verdict(), RepetitionVerdict::ConsistentlyNoDifference);
        assert!(t.verdict().is_trustworthy());
    }

    #[test]
    fn strength_bucketing_tolerates_jitter() {
        let a = outcome_signature(&[sig(SignalKind::StatusChanged, 0.71)]);
        let b = outcome_signature(&[sig(SignalKind::StatusChanged, 0.73)]);
        assert_eq!(a, b, "minor strength jitter must not read as a difference");
    }

    #[test]
    fn large_strength_change_is_detected() {
        let a = outcome_signature(&[sig(SignalKind::StatusChanged, 0.2)]);
        let b = outcome_signature(&[sig(SignalKind::StatusChanged, 0.9)]);
        assert_ne!(a, b);
    }

    #[test]
    fn signature_is_order_independent() {
        let a = outcome_signature(&[
            sig(SignalKind::StatusChanged, 0.7),
            sig(SignalKind::LengthChanged, 0.2),
        ]);
        let b = outcome_signature(&[
            sig(SignalKind::LengthChanged, 0.2),
            sig(SignalKind::StatusChanged, 0.7),
        ]);
        assert_eq!(a, b, "signal order must not affect the signature");
    }

    #[test]
    fn environmental_signals_do_not_count_as_strength() {
        let mut t = RepetitionTracker::new();
        t.push(&[sig(SignalKind::WafBlock, 0.9)]);
        assert_eq!(t.runs[0].strength, 0.0, "a WAF block is not SQL evidence");
    }

    #[test]
    fn verdict_labels_are_readable() {
        assert_eq!(RepetitionVerdict::Pending.label(), "pending");
        assert!(RepetitionVerdict::Flaky {
            detail: "x".into()
        }
        .label()
        .contains("FLAKY"));
    }
}
