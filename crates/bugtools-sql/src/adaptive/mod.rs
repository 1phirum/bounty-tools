//! Adaptive, evidence-driven SQLi research engine.
//!
//! Replaces the "run every probe against every parameter" pipeline. The
//! pieces:
//!
//! - `fingerprint` — deterministic test identity + family collapsing, so
//!   equivalent tests are not re-run.
//! - `signals` — typed observation extraction, so `signals` is never empty.
//! - `baseline` — a first-class baseline profile with stable/dynamic fields.
//! - `hypotheses` — ranked context / query-position / DBMS hypothesis sets.
//! - `planner` — chooses the next experiment from evidence, and produces a
//!   diagnostic report when nothing is found.

pub mod baseline;
pub mod fingerprint;
pub mod hypotheses;
pub mod planner;
pub mod repetition;
pub mod signals;

pub use baseline::{BaselineProfile, BaselineSample, MIN_BASELINE_SAMPLES};
pub use fingerprint::{TestFamily, TestFingerprint, TestLedger, TestStatus};
pub use hypotheses::{
    infer_context, infer_dbms, infer_query_position, ContextObservations, DbmsObservations,
    Hypothesis, HypothesisSet, PositionObservations,
};
pub use repetition::{outcome_signature, RepetitionTracker, RepetitionVerdict, REQUIRED_REPETITIONS};
pub use planner::{
    negative_result_report, plan, remaining_uncertainty, CoverageState, Experiment, NextAction,
    PlannerState,
};
pub use signals::{extract_signals, ResponseView, Signal, SignalKind};
