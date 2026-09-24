//! Native endpoint discovery engine.
//!
//! Turns a document — an HTML page, a bundled `.js` file, or a raw response
//! body — into a list of classified, templated [`Endpoint`]s with a confidence
//! that reflects how many independent extractors corroborate each one.
//!
//! Design mirrors `bugtools-discovery`: a trait ([`EndpointExtractor`]) with
//! composable implementations, an engine ([`EndpointEngine`]) that runs them
//! and merges the results, typed models, and pure normalization/classification
//! helpers. Extraction is entirely static — no JavaScript is executed and this
//! crate performs no network I/O of its own. Live/dynamic discovery is layered
//! on top by the CLI, which feeds fetched bodies through [`EndpointEngine`]
//! using the scope-checked `SafeHttpClient`.

pub mod classify;
pub mod engine;
pub mod extractors;
pub mod models;
pub mod normalization;

pub use engine::EndpointEngine;
pub use models::{
    Endpoint, EndpointError, EndpointExtractor, EndpointKind, EndpointParam, EndpointReport,
    ExtractionStats, ExtractorKind, MethodHint, ParamLocation, RawEndpoint,
};

/// Convenience: analyze `content` with the standard extractor set and no base.
pub fn analyze(content: &str) -> EndpointReport {
    EndpointEngine::default_set().analyze(content)
}

/// Convenience: analyze `content` resolving relative references against `base`.
pub fn analyze_with_base(content: &str, base: url::Url) -> EndpointReport {
    EndpointEngine::default_set().with_base(base).analyze(content)
}
