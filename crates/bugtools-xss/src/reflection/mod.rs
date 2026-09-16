//! Reflection analysis: detect, locate, and classify every point where
//! attacker-controlled input appears in a response.

pub mod correlation;
pub mod detector;
pub mod encoding;
pub mod normalizer;

pub use correlation::correlate;
pub use detector::{detect_reflections, DetectionConfig};
pub use encoding::{classify_encoding, EncodingTransform};
pub use detector::ReflectionPoint;
pub use normalizer::normalize_for_comparison;
