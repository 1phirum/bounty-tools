//! Response analysis: timing statistics and environmental classification.

pub mod environment;
pub mod timing;

pub use environment::{classify_environment, EnvironmentClass};
pub use timing::{TimingAnalysis, TimingStats, TimingVerdict, MIN_TIMING_SAMPLES};
