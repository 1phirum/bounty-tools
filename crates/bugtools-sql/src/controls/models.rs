use crate::types::ProbeType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlRole {
    /// The unadulterated baseline value
    Neutral,
    /// A value intentionally designed to cause a syntax error (e.g. adding a single quote)
    SyntaxInvalid,
    /// A value representing valid SQL that evaluates to false (e.g. `' AND 1=2--`)
    LogicFalse,
    /// A value representing valid SQL that evaluates to true (e.g. `' AND 1=1--`)
    LogicTrue,
    /// A value causing a type mismatch error (e.g. supplying a string to an integer field)
    TypeMismatch,
}

#[derive(Debug, Clone)]
pub struct ControlPayload {
    pub role: ControlRole,
    pub payload: String,
}

/// An explicit experiment representing a hypothesis, with required controls to isolate the cause.
#[derive(Debug, Clone)]
pub struct Experiment {
    pub name: String,
    pub probe_type: ProbeType,
    pub controls: Vec<ControlPayload>,
    pub candidates: Vec<ControlPayload>,
    pub budget_cost: u32,
}
