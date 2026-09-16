//! Native subdomain discovery engine.
//!
//! Implements BugTools' own discovery pipeline. No external reconnaissance
//! tools are invoked — sources are implemented natively behind a trait so
//! the engine composes and deduplicates their results.

pub mod deduplication;
pub mod engine;
pub mod models;
pub mod normalization;
pub mod sources;

pub use deduplication::deduplicate;
pub use engine::DiscoveryEngine;
pub use models::{AssetSource, DiscoveryError, DiscoverySource, DiscoveredAsset, Target};
pub use normalization::{normalize_hostname, parent_domain};
