//! Payload system: boundaries, dialect rendering, clause-aware generation.

pub mod boundary;
pub mod compose;
pub mod generate;
pub mod transform;

pub use boundary::{candidates_for, Boundary, QuoteMode, Termination};
pub use compose::{
    compose_for, decide_tier, techniques_for, ClauseStrategy, ComposedCandidate, ComposeContext,
    EscalationTier, EvidenceSummary,
};
pub use transform::{
    apply_transform, variants_for, RepresentationContext, TransformKind, TransformationTrace,
};
pub use generate::{
    generate_boolean, generate_error, generate_for, generate_stacked, generate_timing,
    generate_union, render_sql, GenerationContext, LogicalTest, PayloadCandidate,
};
