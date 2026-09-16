//! Deduplication of discovered assets.

use super::models::DiscoveredAsset;
use super::normalization::normalize_hostname;
use std::collections::HashMap;

/// Deduplicate assets by normalized hostname, merging their sources so a
/// hostname found by several sources is retained once with combined
/// provenance. Output is sorted for deterministic results.
pub fn deduplicate(assets: Vec<DiscoveredAsset>) -> Vec<DiscoveredAsset> {
    let mut by_host: HashMap<String, DiscoveredAsset> = HashMap::new();
    for asset in assets {
        let host = normalize_hostname(&asset.hostname);
        if host.is_empty() {
            continue;
        }
        by_host
            .entry(host.clone())
            .and_modify(|existing| {
                // Keep the first source but record that others also saw it.
                if let Some(detail) = &existing.detail {
                    if !detail.contains(asset.source_name()) {
                        existing.detail = Some(format!("{detail},{}", asset.source_name()));
                    }
                } else {
                    existing.detail = Some(asset.source_name().to_string());
                }
            })
            .or_insert_with(|| DiscoveredAsset {
                hostname: host,
                ..asset
            });
    }
    let mut out: Vec<DiscoveredAsset> = by_host.into_values().collect();
    out.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    out
}

impl DiscoveredAsset {
    fn source_name(&self) -> &'static str {
        match self.source {
            super::models::AssetSource::CertificateTransparency => "ct",
            super::models::AssetSource::DnsBruteForce => "dns",
            super::models::AssetSource::Wordlist => "wordlist",
            super::models::AssetSource::Permutation => "permutation",
            super::models::AssetSource::PassiveDns => "passive",
            super::models::AssetSource::Manual => "manual",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AssetSource;

    fn asset(host: &str, source: AssetSource) -> DiscoveredAsset {
        DiscoveredAsset {
            hostname: host.into(),
            source,
            detail: None,
        }
    }

    #[test]
    fn removes_duplicates_case_insensitively() {
        let assets = vec![
            asset("API.example.com", AssetSource::CertificateTransparency),
            asset("api.EXAMPLE.com", AssetSource::DnsBruteForce),
        ];
        let out = deduplicate(assets);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].hostname, "api.example.com");
    }

    #[test]
    fn output_is_sorted() {
        let assets = vec![
            asset("z.example.com", AssetSource::Manual),
            asset("a.example.com", AssetSource::Manual),
        ];
        let out = deduplicate(assets);
        assert_eq!(out[0].hostname, "a.example.com");
    }

    #[test]
    fn empty_hostnames_dropped() {
        let assets = vec![asset("  ", AssetSource::Manual)];
        assert!(deduplicate(assets).is_empty());
    }

    #[test]
    fn multiple_sources_recorded() {
        let assets = vec![
            asset("x.example.com", AssetSource::CertificateTransparency),
            asset("x.example.com", AssetSource::DnsBruteForce),
        ];
        let out = deduplicate(assets);
        assert_eq!(out.len(), 1);
        assert!(out[0].detail.as_deref().unwrap().contains("dns"));
    }
}
