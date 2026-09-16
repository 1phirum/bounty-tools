//! Discovery data models.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

use crate::normalization;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("network error: {0}")]
    Network(String),
    #[error("source unavailable: {0}")]
    SourceUnavailable(String),
    #[error("invalid target: {0}")]
    InvalidTarget(String),
}

/// Where a discovered hostname came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetSource {
    CertificateTransparency,
    DnsBruteForce,
    Wordlist,
    Permutation,
    PassiveDns,
    Manual,
}

/// A single discovered hostname and its provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredAsset {
    pub hostname: String,
    pub source: AssetSource,
    /// Additional source-specific detail (e.g. certificate issuer).
    pub detail: Option<String>,
}

/// A discovery target: the apex domain plus any seed hostnames.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub domain: String,
    pub seeds: Vec<String>,
}

impl Target {
    /// Parse a target from a domain or URL.
    pub fn parse(input: &str) -> Result<Self, DiscoveryError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(DiscoveryError::InvalidTarget("empty target".into()));
        }
        let host = if trimmed.contains("://") {
            url::Url::parse(trimmed)
                .ok()
                .and_then(|u| u.host_str().map(|h| h.to_string()))
                .ok_or_else(|| DiscoveryError::InvalidTarget(trimmed.to_string()))?
        } else {
            trimmed.split('/').next().unwrap_or(trimmed).to_string()
        };
        let host = normalization::normalize_hostname(&host);
        if !host.contains('.') {
            return Err(DiscoveryError::InvalidTarget(format!(
                "{host} is not a registrable domain"
            )));
        }
        let apex = normalization::parent_domain(&host);
        Ok(Self {
            domain: apex,
            seeds: vec![host],
        })
    }
}

/// The trait every discovery source implements. Implementations are native
/// BugTools code — no external tool is shelled out to.
#[async_trait]
pub trait DiscoverySource: Send + Sync {
    fn name(&self) -> &'static str;

    fn asset_source(&self) -> AssetSource;

    async fn discover(&self, target: &Target) -> Result<Vec<DiscoveredAsset>, DiscoveryError>;
}

/// Aggregate per-source statistics, useful for the CLI summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveryStats {
    pub per_source: HashMap<String, usize>,
    pub total_before_dedup: usize,
    pub total_after_dedup: usize,
}
