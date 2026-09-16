//! DOM XSS sinks: the dangerous operations that can execute injected content.

pub mod detector;

pub use detector::{detect_sinks, SinkRisk, SinkTarget};
