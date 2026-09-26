//! Payload system: boundaries, dialect rendering, clause-aware generation.

pub mod boundary;
pub mod compose;
pub mod generate;
pub mod tampers;
pub mod transform;
pub mod vectors;

pub use boundary::{candidates_for, Boundary, QuoteMode, Termination};
pub use compose::{
    compose_for, compose_oob, decide_tier, techniques_for, ClauseStrategy, ComposedCandidate,
    ComposeContext, EscalationTier, EvidenceSummary,
};
pub use transform::{
    apply_transform, variants_for, RepresentationContext, TransformKind, TransformationTrace,
};
pub use vectors::{
    all_for as all_vectors_for, catalog_size, catalogue_total, extraction_query,
    primitives_for as vector_primitives_for, vectors_for, EvidenceGate, Vector, VectorChannel,
    VectorContext,
};
pub use generate::{
    generate_boolean, generate_error, generate_for, generate_stacked, generate_timing,
    generate_union, render_sql, GenerationContext, LogicalTest, PayloadCandidate,
};
