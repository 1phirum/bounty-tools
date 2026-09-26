//! Adaptive experiment planner (brief §7, §15, §16).
//!
//! The engine asks: *what do I know, what is uncertain, and what is the
//! safest informative next experiment?* Every experiment names the question
//! it answers, the variable it changes, and what would count as an
//! observation.

use crate::adaptive::hypotheses::HypothesisSet;
use crate::adaptive::signals::{Signal, SignalKind};
use crate::adaptive::baseline::BaselineProfile;
use serde::{Deserialize, Serialize};

/// Lifecycle state of a parameter under investigation (brief §16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageState {
    Discovered,
    Baselined,
    TypeInferred,
    ContextInferred,
    DbmsInferred,
    Tested,
    Interesting,
    Repeated,
    Confirmed,
    Inconclusive,
    /// A battery of techniques executed against a stable baseline and none
    /// produced a repeated differential, but the strict boolean-pair condition
    /// for NOT_SQL_INTERPRETED was not fully met (e.g. the pair was starved by
    /// the experiment budget, or only error/timing/union channels ran). This is
    /// an honest "tested clean on the channels exercised" — distinct from
    /// INCONCLUSIVE (undermined by baseline instability or partial coverage)
    /// and from BASELINED (nothing was tested at all).
    TestedClean,
    /// Both AlwaysTrue and AlwaysFalse boolean tests executed against a stable
    /// baseline without diverging — positive evidence the parameter is not
    /// evaluated in a SQL boolean context. A negative finding, not proof of
    /// safety against every technique.
    NotSqlInterpreted,
    Blocked,
    Exhausted,
}

impl CoverageState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Discovered => "DISCOVERED",
            Self::Baselined => "BASELINED",
            Self::TypeInferred => "TYPE_INFERRED",
            Self::ContextInferred => "CONTEXT_INFERRED",
            Self::DbmsInferred => "DBMS_INFERRED",
            Self::Tested => "TESTED",
            Self::Interesting => "INTERESTING",
            Self::Repeated => "REPEATED",
            Self::Confirmed => "CONFIRMED",
            Self::Inconclusive => "INCONCLUSIVE",
            Self::TestedClean => "TESTED_CLEAN",
            Self::NotSqlInterpreted => "NOT_SQL_INTERPRETED",
            Self::Blocked => "BLOCKED",
            Self::Exhausted => "EXHAUSTED",
        }
    }

    /// Whether the planner should keep spending requests in this state.
    pub fn should_continue(&self) -> bool {
        matches!(
            self,
            Self::TypeInferred | Self::ContextInferred | Self::DbmsInferred | Self::Tested | Self::Interesting | Self::Repeated
        )
    }
}

/// An experiment with its question and expected observation (brief §7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Experiment {
    /// The specific question this experiment answers.
    pub question: String,
    /// The hypothesis under test.
    pub hypothesis: String,
    /// What is held constant.
    pub control: String,
    /// The single variable changed.
    pub variable: String,
    /// What observation would be informative.
    pub expected_observation: String,
    /// Filled in after execution.
    pub actual_observation: Option<String>,
    /// The conclusion, once known.
    pub conclusion: Option<String>,
    /// What to consider next.
    pub next_actions: Vec<String>,
}

impl Experiment {
    pub fn new(
        question: impl Into<String>,
        hypothesis: impl Into<String>,
        control: impl Into<String>,
        variable: impl Into<String>,
        expected_observation: impl Into<String>,
    ) -> Self {
        Self {
            question: question.into(),
            hypothesis: hypothesis.into(),
            control: control.into(),
            variable: variable.into(),
            expected_observation: expected_observation.into(),
            actual_observation: None,
            conclusion: None,
            next_actions: Vec::new(),
        }
    }

    pub fn conclude(mut self, observation: impl Into<String>, conclusion: impl Into<String>) -> Self {
        let observation = observation.into();
        let conclusion = conclusion.into();
        self.actual_observation = Some(observation);
        self.conclusion = Some(conclusion);
        self
    }
}

/// The planner's state for one parameter.
#[derive(Debug, Clone)]
pub struct PlannerState {
    pub coverage: CoverageState,
    pub baseline_stable: bool,
    pub signals: Vec<Signal>,
    /// True when a differential repeated across controlled repeats.
    pub repeatable_differential: bool,
    /// Number of distinct experiments executed.
    pub experiments_run: usize,
    /// Remaining request allowance.
    pub requests_remaining: u64,
    /// Context hypotheses, if inferred.
    pub context: Option<HypothesisSet>,
    /// Whether the edge blocked us.
    pub waf_interference: bool,
}

impl Default for PlannerState {
    fn default() -> Self {
        Self {
            coverage: CoverageState::Discovered,
            baseline_stable: false,
            signals: Vec::new(),
            repeatable_differential: false,
            experiments_run: 0,
            requests_remaining: 50,
            context: None,
            waf_interference: false,
        }
    }
}

/// The planner's decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NextAction {
    /// Collect more baseline samples first.
    CollectBaseline { additional_samples: usize, reason: String },
    /// Run the given experiment.
    RunExperiment(Box<Experiment>),
    /// Retry with a control to test repeatability.
    RepeatWithControl { reason: String },
    /// Stop: no meaningful uncertainty remains, or budget exhausted.
    Stop { reason: String },
}

impl NextAction {
    pub fn reason(&self) -> String {
        match self {
            Self::CollectBaseline { reason, .. } => reason.clone(),
            Self::RunExperiment(e) => e.question.clone(),
            Self::RepeatWithControl { reason } => reason.clone(),
            Self::Stop { reason } => reason.clone(),
        }
    }
}

/// Decide the next action from the current state.
///
/// This is the replacement for "run the whole matrix": every branch is
/// justified by what has actually been observed.
pub fn plan(state: &PlannerState) -> NextAction {
    // 1. Budget first — never exceed the allowance.
    if state.requests_remaining == 0 {
        return NextAction::Stop {
            reason: "request budget exhausted".into(),
        };
    }

    // 2. Edge interference invalidates application-level conclusions.
    if state.waf_interference && !state.repeatable_differential {
        return NextAction::Stop {
            reason: "edge layer interfered; application behaviour could not be observed reliably"
                .into(),
        };
    }

    // 3. A stable baseline is the prerequisite for any differential claim.
    if !state.baseline_stable {
        return NextAction::CollectBaseline {
            additional_samples: 3,
            reason: "baseline is not yet stable; diffs would be untrustworthy".into(),
        };
    }

    // 4. A differential that has not been repeated needs a control run
    //    before it can raise confidence.
    let has_positive_signal = state
        .signals
        .iter()
        .any(|s| s.kind.supports_sql_hypothesis() && s.strength > 0.3);
    if has_positive_signal && !state.repeatable_differential && state.experiments_run > 0 {
        return NextAction::RepeatWithControl {
            reason:
                "a differential was observed once; repeat with an unchanged control to test reproducibility"
                    .into(),
        };
    }

    // 5. Nothing observed yet: run the cheapest discriminating experiment.
    if state.experiments_run == 0 {
        return NextAction::RunExperiment(Box::new(Experiment::new(
            "Does a syntactically invalid value produce a database error rather than application validation?",
            "the parameter reaches a SQL parser",
            "unmodified request, repeated",
            "one delimiter character appended to the value",
            "either a database error signature, an application validation error, or no change",
        )));
    }

    // 6. Context is still unknown: the informative experiment is one that
    //    distinguishes numeric from string handling.
    if let Some(ctx) = &state.context {
        if !ctx.is_decisive() {
            return NextAction::RunExperiment(Box::new(Experiment::new(
                "Is the value handled as a number or as a string?",
                "context is numeric rather than string",
                "unmodified request",
                "a non-numeric string in place of the numeric value",
                "acceptance (numeric coercion) vs rejection (type validation) vs error",
            )));
        }
    }

    // 7. Everything settled: stop rather than spend more requests.
    NextAction::Stop {
        reason: format!(
            "coverage reached {} with {} experiment(s) run and no outstanding uncertainty",
            state.coverage.label(),
            state.experiments_run
        ),
    }
}

/// Build the diagnostic narrative for a scan that found nothing (brief §15).
///
/// A zero-result scan must still tell the researcher what was established and
/// what remains unknown.
pub fn negative_result_report(
    baseline: &BaselineProfile,
    signals: &[Signal],
    experiments_run: usize,
) -> Vec<String> {
    let mut out = Vec::new();

    if baseline.stable {
        out.push(format!(
            "Baseline stable across {} samples (median {}ms, similarity {:.2})",
            baseline.responses.len(),
            baseline.timing_median_ms,
            baseline.body_similarity
        ));
    } else {
        out.push(format!(
            "Baseline NOT stable — {}",
            baseline
                .instability_reason
                .as_deref()
                .unwrap_or("insufficient samples")
        ));
    }

    let kinds: Vec<SignalKind> = signals.iter().map(|s| s.kind).collect();

    if kinds.contains(&SignalKind::NoDifference) {
        out.push("No response difference from the baseline for any tested variation".into());
    }
    if kinds.iter().any(|k| k.is_environmental()) {
        let env: Vec<&str> = signals
            .iter()
            .filter(|s| s.kind.is_environmental())
            .map(|s| s.label())
            .collect();
        out.push(format!("Environmental interference observed: {}", env.join(", ")));
    }
    if !kinds.contains(&SignalKind::TimingShift) {
        out.push("No timing separation observed".into());
    }
    if !kinds
        .iter()
        .any(|k| matches!(k, SignalKind::ErrorSignatureChanged | SignalKind::ApplicationError))
    {
        out.push("No database-specific error signature appeared".into());
    }
    if kinds.contains(&SignalKind::ValidationChanged) {
        out.push("The parameter appears to be type-validated by the application".into());
    }

    out.push(format!(
        "{experiments_run} distinct experiment(s) executed; no repeatable causal differential was established"
    ));

    out
}

/// Remaining uncertainty statements for the assessment (brief §15/§17).
pub fn remaining_uncertainty(context_known: bool, dbms_known: bool, repeated: bool) -> Vec<String> {
    let mut out = Vec::new();
    if !context_known {
        out.push("SQL context unknown — parameter semantics were not resolved from observed behaviour".into());
    }
    if !dbms_known {
        out.push("Backend DBMS not determined — no DBMS-specific behaviour was observed".into());
    }
    if !repeated {
        out.push("No repeatable differential — any single observation remains unconfirmed".into());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptive::signals::Signal;

    fn stable_state() -> PlannerState {
        PlannerState {
            baseline_stable: true,
            ..Default::default()
        }
    }

    #[test]
    fn budget_exhaustion_stops() {
        let state = PlannerState {
            requests_remaining: 0,
            ..stable_state()
        };
        assert!(matches!(plan(&state), NextAction::Stop { .. }));
    }

    #[test]
    fn unstable_baseline_requests_more_samples() {
        let state = PlannerState::default();
        match plan(&state) {
            NextAction::CollectBaseline { additional_samples, reason } => {
                assert!(additional_samples > 0);
                assert!(reason.contains("stable"));
            }
            other => panic!("expected CollectBaseline, got {other:?}"),
        }
    }

    #[test]
    fn waf_interference_stops_when_no_differential() {
        let state = PlannerState {
            waf_interference: true,
            ..stable_state()
        };
        match plan(&state) {
            NextAction::Stop { reason } => assert!(reason.contains("edge")),
            other => panic!("expected Stop, got {other:?}"),
        }
    }

    #[test]
    fn first_experiment_is_cheap_and_question_driven() {
        let state = stable_state();
        match plan(&state) {
            NextAction::RunExperiment(e) => {
                assert!(e.question.contains("syntactically invalid"));
                assert!(!e.control.is_empty());
                assert!(!e.variable.is_empty());
                assert!(!e.expected_observation.is_empty());
            }
            other => panic!("expected RunExperiment, got {other:?}"),
        }
    }

    #[test]
    fn positive_signal_triggers_control_repeat() {
        let state = PlannerState {
            signals: vec![Signal::new(SignalKind::StatusChanged, 0.7, "b", "o")],
            experiments_run: 1,
            ..stable_state()
        };
        assert!(matches!(plan(&state), NextAction::RepeatWithControl { .. }));
    }

    #[test]
    fn repeated_differential_does_not_re_repeat() {
        let state = PlannerState {
            signals: vec![Signal::new(SignalKind::StatusChanged, 0.7, "b", "o")],
            experiments_run: 1,
            repeatable_differential: true,
            ..stable_state()
        };
        assert!(!matches!(plan(&state), NextAction::RepeatWithControl { .. }));
    }

    #[test]
    fn settled_state_stops() {
        let state = PlannerState {
            experiments_run: 5,
            coverage: CoverageState::Exhausted,
            ..stable_state()
        };
        match plan(&state) {
            NextAction::Stop { reason } => assert!(reason.contains("EXHAUSTED")),
            other => panic!("expected Stop, got {other:?}"),
        }
    }

    #[test]
    fn negative_report_lists_what_was_established() {
        use crate::adaptive::baseline::{BaselineProfile, BaselineSample};
        use crate::adaptive::signals::ResponseView;

        let profile = BaselineProfile::from_samples(vec![
            BaselineSample::from_view(&ResponseView::simple(200, "x", 100)),
            BaselineSample::from_view(&ResponseView::simple(200, "x", 100)),
            BaselineSample::from_view(&ResponseView::simple(200, "x", 100)),
        ]);
        let signals = vec![Signal::new(SignalKind::NoDifference, 0.0, "b", "o")];
        let report = negative_result_report(&profile, &signals, 3);
        assert!(report.iter().any(|l| l.contains("Baseline stable")));
        assert!(report.iter().any(|l| l.contains("No response difference")));
        assert!(report.iter().any(|l| l.contains("No timing separation")));
        assert!(report.iter().any(|l| l.contains("3 distinct experiment")));
    }

    #[test]
    fn uncertainty_lists_gaps() {
        let u = remaining_uncertainty(false, false, false);
        assert_eq!(u.len(), 3);
        let none = remaining_uncertainty(true, true, true);
        assert!(none.is_empty());
    }

    #[test]
    fn coverage_states_continue_only_while_uncertain() {
        assert!(CoverageState::Tested.should_continue());
        assert!(!CoverageState::Confirmed.should_continue());
        assert!(!CoverageState::Exhausted.should_continue());
        assert!(!CoverageState::Blocked.should_continue());
    }

    #[test]
    fn negative_verdicts_are_terminal_and_labelled() {
        // The two honest negatives are distinct, terminal states — neither
        // should keep spending requests, and each carries its own label.
        assert!(!CoverageState::TestedClean.should_continue());
        assert!(!CoverageState::NotSqlInterpreted.should_continue());
        assert_eq!(CoverageState::TestedClean.label(), "TESTED_CLEAN");
        assert_eq!(CoverageState::NotSqlInterpreted.label(), "NOT_SQL_INTERPRETED");
    }

    #[test]
    fn experiment_concludes_with_observation() {
        let e = Experiment::new("q?", "h", "control", "var", "expected").conclude(
            "observed X",
            "therefore Y",
        );
        assert_eq!(e.actual_observation.as_deref(), Some("observed X"));
        assert_eq!(e.conclusion.as_deref(), Some("therefore Y"));
    }
}
