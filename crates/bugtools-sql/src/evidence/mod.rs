//! Evidence subsystem: the observation layer and the explainable confidence
//! engine built on top of it.
//!
//! Design invariants (from the brief):
//! - Observations are recorded; interpretations are hypotheses.
//! - Contradictory evidence is retained, never discarded.
//! - Confidence is always accompanied by its breakdown.

pub mod confidence;
pub mod model;

pub use confidence::{evidence_from_probe, ConfidenceFactor, ConfidenceLevel, ConfidenceReport};
pub use model::{Evidence, EvidenceCategory, EvidenceGraph};
