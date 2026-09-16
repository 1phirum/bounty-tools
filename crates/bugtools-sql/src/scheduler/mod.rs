//! Adaptive scheduler: probe scoring, selection, and request budgeting.

pub mod planner;

pub use planner::{
    score_probe, select_next_probe, BudgetDecision, ProbeCandidate, RequestBudget,
    SchedulingDecision,
};
