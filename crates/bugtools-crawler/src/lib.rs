//! Native web crawler: frontier, normalization, HTML extraction.

pub mod extraction;
pub mod frontier;
pub mod normalization;

pub use extraction::{extract_endpoints, ExtractedLink};
pub use frontier::{CrawlFrontier, FrontierConfig, FrontierItem};
pub use normalization::{canonicalize, same_resource};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CrawlerError {
    #[error("network error: {0}")]
    Network(String),
    #[error("invalid url: {0}")]
    InvalidUrl(String),
}

/// A page fetched during a crawl.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawledPage {
    pub url: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub depth: u32,
    pub links: Vec<String>,
}

/// Configuration for a crawl run.
#[derive(Debug, Clone)]
pub struct CrawlConfig {
    pub max_depth: u32,
    pub max_urls: usize,
    pub per_host_concurrency: usize,
    pub timeout_secs: u64,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            max_depth: 2,
            max_urls: 500,
            per_host_concurrency: 4,
            timeout_secs: 15,
        }
    }
}
