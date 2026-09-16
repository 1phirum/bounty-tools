//! Response analysis: timing statistics, differentials, and classification.

pub mod diff;
pub mod environment;
pub mod timing;

pub use diff::{normalize_body, similarity, ResponseDifference, ResponseSample};
pub use environment::{classify_environment, EnvironmentClass};
pub use timing::{TimingAnalysis, TimingStats, TimingVerdict, MIN_TIMING_SAMPLES};
