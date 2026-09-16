//! The discovery engine: composes sources, deduplicates, and streams results.

use super::deduplication::deduplicate;
use super::models::{DiscoveredAsset, DiscoveryError, DiscoverySource, DiscoveryStats, Target};
use futures::stream::{self, StreamExt};
use std::sync::Arc;

pub struct DiscoveryEngine {
    sources: Vec<Arc<dyn DiscoverySource>>,
    /// Maximum sources queried in parallel.
    max_parallel_sources: usize,
}

impl DiscoveryEngine {
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            max_parallel_sources: 4,
        }
    }

    pub fn with_source(mut self, source: Arc<dyn DiscoverySource>) -> Self {
        self.sources.push(source);
        self
    }

    pub fn source_names(&self) -> Vec<&'static str> {
        self.sources.iter().map(|s| s.name()).collect()
    }

    /// Run every source, collecting results and per-source statistics.
    /// A failing source is reported in the stats but does not abort the run.
    pub async fn run(&self, target: &Target) -> (Vec<DiscoveredAsset>, DiscoveryStats) {
        let mut stats = DiscoveryStats::default();

        // Bound how many sources run simultaneously.
        let results = stream::iter(self.sources.iter().cloned())
            .map(|source| {
                let target = target.clone();
                async move {
                    let name = source.name();
                    let result = source.discover(&target).await;
                    (name, result)
                }
            })
            .buffer_unordered(self.max_parallel_sources)
            .collect::<Vec<_>>()
            .await;

        let mut all = Vec::new();
        for (name, result) in results {
            match result {
                Ok(assets) => {
                    stats.per_source.insert(name.to_string(), assets.len());
                    all.extend(assets);
                }
                Err(DiscoveryError::SourceUnavailable(reason)) => {
                    tracing::warn!(source = name, reason, "discovery source unavailable");
                    stats.per_source.insert(name.to_string(), 0);
                }
                Err(e) => {
                    tracing::warn!(source = name, error = %e, "discovery source failed");
                    stats.per_source.insert(name.to_string(), 0);
                }
            }
        }

        stats.total_before_dedup = all.len();
        let deduped = deduplicate(all);
        stats.total_after_dedup = deduped.len();
        (deduped, stats)
    }
}

impl Default for DiscoveryEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AssetSource, DiscoveryError};

    struct FakeSource {
        name: &'static str,
        assets: Vec<String>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl DiscoverySource for FakeSource {
        fn name(&self) -> &'static str {
            self.name
        }
        fn asset_source(&self) -> AssetSource {
            AssetSource::Manual
        }
        async fn discover(
            &self,
            _target: &Target,
        ) -> Result<Vec<DiscoveredAsset>, DiscoveryError> {
            if self.fail {
                return Err(DiscoveryError::SourceUnavailable("simulated".into()));
            }
            Ok(self
                .assets
                .iter()
                .map(|h| DiscoveredAsset {
                    hostname: h.clone(),
                    source: AssetSource::Manual,
                    detail: None,
                })
                .collect())
        }
    }

    fn target() -> Target {
        Target {
            domain: "example.com".into(),
            seeds: vec![],
        }
    }

    #[tokio::test]
    async fn merges_and_dedupes_across_sources() {
        let engine = DiscoveryEngine::new()
            .with_source(Arc::new(FakeSource {
                name: "a",
                assets: vec!["api.example.com".into(), "www.example.com".into()],
                fail: false,
            }))
            .with_source(Arc::new(FakeSource {
                name: "b",
                assets: vec!["api.example.com".into(), "dev.example.com".into()],
                fail: false,
            }));
        let (assets, stats) = engine.run(&target()).await;
        assert_eq!(assets.len(), 3, "api/www/dev after dedup");
        assert_eq!(stats.total_before_dedup, 4);
        assert_eq!(stats.total_after_dedup, 3);
    }

    #[tokio::test]
    async fn failing_source_does_not_abort_run() {
        let engine = DiscoveryEngine::new()
            .with_source(Arc::new(FakeSource {
                name: "broken",
                assets: vec![],
                fail: true,
            }))
            .with_source(Arc::new(FakeSource {
                name: "good",
                assets: vec!["x.example.com".into()],
                fail: false,
            }));
        let (assets, stats) = engine.run(&target()).await;
        assert_eq!(assets.len(), 1);
        assert_eq!(stats.per_source.get("broken"), Some(&0));
        assert_eq!(stats.per_source.get("good"), Some(&1));
    }

    #[test]
    fn source_names_listed() {
        let engine = DiscoveryEngine::new().with_source(Arc::new(FakeSource {
            name: "ct",
            assets: vec![],
            fail: false,
        }));
        assert_eq!(engine.source_names(), vec!["ct"]);
    }
}
