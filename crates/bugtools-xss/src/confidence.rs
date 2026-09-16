//! Confidence model (brief §4).
//!
//! The brief's correction: do not call an accumulated weight a "probability".
//! This module separates a raw evidence score from the *level* it justifies,
//! and reports how many independent sources agreed.

use serde::{Deserialize, Serialize};

/// An accumulated evidence score.
///
/// This is NOT a probability. `raw_score` is a sum of weighted contributions
/// clamped to [0, 1]; its meaning is "how much corroborated evidence we have",
/// not "the chance this is exploitable".
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvidenceScore {
    pub raw_score: f32,
    /// How many distinct evidence sources contributed. Corroboration across
    /// independent sources is what makes a claim strong.
    pub independent_sources: usize,
    pub evidence_count: usize,
    /// Evidence that argued against the hypothesis.
    pub conflicts: usize,
    /// Distinct source names seen, used to count corroboration. Two pieces of
    /// evidence from the same source are not independent corroboration.
    #[serde(default)]
    pub sources: Vec<String>,
}

impl EvidenceScore {
    pub fn add(&mut self, weight: f32, source: &str) {
        self.raw_score = (self.raw_score + weight).clamp(0.0, 1.0);
        self.evidence_count += 1;
        self.register_source(source);
    }

    pub fn conflict(&mut self, weight: f32, source: &str) {
        self.raw_score = (self.raw_score - weight).clamp(0.0, 1.0);
        self.conflicts += 1;
        self.register_source(source);
    }

    fn register_source(&mut self, source: &str) {
        if !self.sources.contains(&source.to_string()) {
            self.sources.push(source.to_string());
            self.independent_sources = self.sources.len();
        }
    }
}

/// The confidence level a score justifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConfidenceLevel {
    Unknown,
    Weak,
    Possible,
    Corroborated,
    Strong,
    Confirmed,
}

impl ConfidenceLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN",
            Self::Weak => "WEAK",
            Self::Possible => "POSSIBLE",
            Self::Corroborated => "CORROBORATED",
            Self::Strong => "STRONG",
            Self::Confirmed => "CONFIRMED",
        }
    }
}

/// A confidence assessment with its justification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceAssessment {
    pub score: f32,
    pub level: ConfidenceLevel,
    pub explanation: Vec<String>,
    pub independent_sources: usize,
    pub conflicts: usize,
}

/// Calibrate a score into a level.
///
/// The gates encode the brief's requirement that a single source cannot make
/// a claim strong: `Corroborated` needs ≥2 independent sources, `Strong` ≥3.
/// `Confirmed` is reserved for observed execution and is never produced here.
pub fn calibrate(score: &EvidenceScore) -> ConfidenceAssessment {
    let s = score.raw_score;
    let sources = score.independent_sources;
    let mut explanation = Vec::new();

    let level = if score.evidence_count == 0 {
        explanation.push("no evidence recorded".into());
        ConfidenceLevel::Unknown
    } else if s < 0.2 {
        explanation.push(format!("evidence score {s:.2} is below the Weak threshold"));
        ConfidenceLevel::Weak
    } else if s < 0.45 || sources < 2 {
        if sources < 2 && s >= 0.45 {
            explanation.push(format!(
                "score {s:.2} but only {sources} independent source(s); \
                 corroboration is required for a stronger claim"
            ));
        } else {
            explanation.push(format!("evidence score {s:.2}"));
        }
        ConfidenceLevel::Possible
    } else if s < 0.7 || sources < 3 {
        explanation.push(format!("{sources} independent source(s) agree at score {s:.2}"));
        ConfidenceLevel::Corroborated
    } else {
        explanation.push(format!(
            "{sources} independent sources agree at score {s:.2}"
        ));
        ConfidenceLevel::Strong
    };

    if score.conflicts > 0 {
        explanation.push(format!(
            "{} contradicting observation(s) reduced the score",
            score.conflicts
        ));
    }
    explanation.push(
        "a weighted score is not a statistical probability; Confirmed requires observed execution"
            .into(),
    );

    ConfidenceAssessment {
        score: s,
        level,
        explanation,
        independent_sources: sources,
        conflicts: score.conflicts,
    }
}

/// Promote an assessment to `Confirmed` only when execution was actually
/// observed. This is the single gate that allows a Confirmed level.
pub fn confirm_on_execution(mut assessment: ConfidenceAssessment, execution_observed: bool) -> ConfidenceAssessment {
    if execution_observed {
        assessment.level = ConfidenceLevel::Confirmed;
        assessment.explanation.push(
            "execution was observed, which is the only basis for a Confirmed level".into(),
        );
    }
    assessment
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_evidence_is_unknown() {
        let a = calibrate(&EvidenceScore::default());
        assert_eq!(a.level, ConfidenceLevel::Unknown);
    }

    #[test]
    fn single_source_cannot_reach_strong() {
        let mut s = EvidenceScore::default();
        s.add(0.5, "error-signature");
        let a = calibrate(&s);
        assert_eq!(a.independent_sources, 1);
        assert!(
            a.level < ConfidenceLevel::Strong,
            "one source must not be Strong: {:?}",
            a.level
        );
    }

    #[test]
    fn repeated_same_source_does_not_corroborate() {
        let mut s = EvidenceScore::default();
        s.add(0.3, "header");
        s.add(0.3, "header");
        assert_eq!(s.independent_sources, 1, "same source must not count twice");
        assert_eq!(s.evidence_count, 2);
    }

    #[test]
    fn three_sources_can_reach_strong() {
        let mut s = EvidenceScore::default();
        s.add(0.3, "header");
        s.add(0.3, "cookie");
        s.add(0.3, "html-structure");
        let a = calibrate(&s);
        assert_eq!(a.independent_sources, 3);
        assert_eq!(a.level, ConfidenceLevel::Strong);
    }

    #[test]
    fn conflicts_reduce_score() {
        let mut s = EvidenceScore::default();
        s.add(0.6, "a");
        s.conflict(0.4, "b");
        let a = calibrate(&s);
        assert!((a.score - 0.2).abs() < 0.001);
        assert_eq!(a.conflicts, 1);
        assert!(a.explanation.iter().any(|e| e.contains("contradicting")));
    }

    #[test]
    fn score_is_never_called_a_probability() {
        let mut s = EvidenceScore::default();
        s.add(0.5, "a");
        let a = calibrate(&s);
        assert!(
            a.explanation.iter().any(|e| e.contains("not a statistical probability")),
            "the explanation must state the score is not a probability"
        );
    }

    #[test]
    fn confirmed_requires_execution() {
        let mut s = EvidenceScore::default();
        s.add(0.9, "a");
        s.add(0.9, "b");
        s.add(0.9, "c");
        let a = calibrate(&s);
        assert_ne!(a.level, ConfidenceLevel::Confirmed, "calibration alone must not Confirm");
        let confirmed = confirm_on_execution(a, true);
        assert_eq!(confirmed.level, ConfidenceLevel::Confirmed);
    }

    #[test]
    fn execution_flag_false_leaves_level_unchanged() {
        let mut s = EvidenceScore::default();
        s.add(0.5, "a");
        let a = calibrate(&s);
        let before = a.level;
        let same = confirm_on_execution(a, false);
        assert_eq!(same.level, before);
    }

    #[test]
    fn levels_are_ordered() {
        assert!(ConfidenceLevel::Unknown < ConfidenceLevel::Weak);
        assert!(ConfidenceLevel::Weak < ConfidenceLevel::Possible);
        assert!(ConfidenceLevel::Possible < ConfidenceLevel::Corroborated);
        assert!(ConfidenceLevel::Corroborated < ConfidenceLevel::Strong);
        assert!(ConfidenceLevel::Strong < ConfidenceLevel::Confirmed);
    }
}
