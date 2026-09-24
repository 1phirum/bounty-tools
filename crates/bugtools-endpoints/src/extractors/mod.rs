//! The extractor implementations.
//!
//! Each is pure over the document text and tagged with an [`ExtractorKind`]
//! so the engine can weight and corroborate their findings. They are additive:
//! all three run over whatever content is supplied (an HTML page, a bundled
//! `.js` file, or a raw response body) and the engine merges the overlap.

pub mod heuristic;
pub mod html;
pub mod javascript;

pub use heuristic::PathHeuristicExtractor;
pub use html::HtmlExtractor;
pub use javascript::JavaScriptExtractor;
