//! DOM XSS sources: the places attacker-controlled data can enter a
//! client-side application.

pub mod detector;

pub use detector::{detect_sources, SourceKind};
