use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputLocation {
    Query,
    Path,
    Form,
    Json,
    Multipart,
    Header,
    Cookie,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueKind {
    IntegerLike,
    DecimalLike,
    BooleanLike,
    StringLike,
    EnumLike,
    IdentifierLike,
    SortLike,
    FilterLike,
    SearchLike,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueryRole {
    Predicate,
    Projection,
    Ordering,
    Pagination,
    Aggregation,
    Identifier,
    Search,
    Unknown,
}

/// A probabilistic context classification of a parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextClassification {
    pub location: InputLocation,
    pub value_kind: ValueKind,
    pub role: QueryRole,
    pub confidence: f32,
    pub reasons: Vec<String>,
}

impl Default for ContextClassification {
    fn default() -> Self {
        Self {
            location: InputLocation::Unknown,
            value_kind: ValueKind::Unknown,
            role: QueryRole::Unknown,
            confidence: 0.0,
            reasons: vec![],
        }
    }
}

/// The current scientific hypothesis for a parameter's behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Hypothesis {
    NormalBehavior,
    InputValidation,
    WafInterference,
    QueryInfluence,
    SqlEvaluation,
    ErrorBasedSignal,
    BooleanDifferential,
    TimingDifferential,
    Unknown,
}

/// The lifecycle state of a parameter in the research pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParameterState {
    Discovered,
    Baselined,
    Classified,
    WafProfileBuilt,
    Candidate,
    LayerClassified,
    Interesting,
    Confirming,
    Confirmed,
    // Failure / terminal states
    BaselineUnstable,
    Blocked,
    OutOfScope,
    Inconclusive,
    Rejected,
    Duplicate,
}

impl ParameterState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Confirmed
                | Self::BaselineUnstable
                | Self::Blocked
                | Self::OutOfScope
                | Self::Inconclusive
                | Self::Rejected
                | Self::Duplicate
        )
    }
}
