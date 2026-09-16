//! Payload system: boundaries, dialect rendering, clause-aware generation.

pub mod boundary;
pub mod generate;

pub use boundary::{candidates_for, Boundary, QuoteMode, Termination};
pub use generate::{
    generate_boolean, generate_error, generate_for, generate_stacked, generate_timing,
    generate_union, render_sql, GenerationContext, LogicalTest, PayloadCandidate,
};
