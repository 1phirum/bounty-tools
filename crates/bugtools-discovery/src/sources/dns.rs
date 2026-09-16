//! DNS brute-force / wordlist discovery source.
//!
//! Resolves candidate hostnames built from a built-in wordlist against the
//! target domain. Uses the BugTools DNS engine, so concurrency, timeouts,
//! caching and retries are all bounded — this never floods a resolver.

use super::super::models::{AssetSource, DiscoveredAsset, DiscoveryError, DiscoverySource, Target};
use async_trait::async_trait;
use bugtools_dns::{DnsConfig, DnsEngine, RecordType};

/// A small default wordlist of high-signal subdomain labels. Kept short on
/// purpose: this is a discovery seed, not a dictionary attack. Callers can
/// supply their own list via `with_wordlist`.
pub const DEFAULT_WORDLIST: &[&str] = &[
    "www", "api", "app", "admin", "portal", "dev", "staging", "test", "qa", "uat", "prod",
    "mail", "smtp", "imap", "pop", "webmail", "vpn", "remote", "gateway", "proxy", "cdn",
    "static", "assets", "media", "img", "files", "docs", "wiki", "git", "gitlab", "jenkins",
    "ci", "build", "status", "monitor", "grafana", "kibana", "logs", "db", "mysql", "postgres",
    "redis", "cache", "auth", "sso", "login", "id", "accounts", "billing", "pay", "shop",
    "store", "blog", "news", "support", "help", "internal", "intranet", "corp", "office",
];

pub struct DnsBruteForceSource {
    wordlist: Vec<String>,
    dns: DnsEngine,
}

impl Default for DnsBruteForceSource {
    fn default() -> Self {
        Self::new().expect("default DNS engine must initialize")
    }
}

impl DnsBruteForceSource {
    pub fn new() -> Result<Self, DiscoveryError> {
        let dns = DnsEngine::new(DnsConfig {
            max_concurrency: 20,
            timeout: std::time::Duration::from_secs(4),
            retries: 1,
            cache_ttl: std::time::Duration::from_secs(300),
            wildcard_detection: true,
        })
        .map_err(|e| DiscoveryError::SourceUnavailable(e.to_string()))?;
        Ok(Self {
            wordlist: DEFAULT_WORDLIST.iter().map(|s| s.to_string()).collect(),
            dns,
        })
    }

    pub fn with_wordlist(mut self, words: Vec<String>) -> Self {
        self.wordlist = words;
        self
    }

    /// Build candidate hostnames for a target. Pure and testable.
    pub fn candidates(&self, target: &Target) -> Vec<String> {
        self.wordlist
            .iter()
            .map(|w| format!("{}.{}", w, target.domain))
            .collect()
    }
}

#[async_trait]
impl DiscoverySource for DnsBruteForceSource {
    fn name(&self) -> &'static str {
        "dns-bruteforce"
    }

    fn asset_source(&self) -> AssetSource {
        AssetSource::DnsBruteForce
    }

    async fn discover(&self, target: &Target) -> Result<Vec<DiscoveredAsset>, DiscoveryError> {
        let candidates = self.candidates(target);
        let observations = self
            .dns
            .observe_many(&candidates, &[RecordType::A, RecordType::Aaaa, RecordType::Cname])
            .await;

        let mut assets = Vec::new();
        for obs in observations.into_iter().flatten() {
            // Only report hostnames that actually resolve to something.
            if !obs.resolves || obs.records.is_empty() {
                continue;
            }
            let addresses: Vec<String> = obs
                .records
                .iter()
                .filter(|r| matches!(r.record_type, RecordType::A | RecordType::Aaaa | RecordType::Cname))
                .map(|r| r.value.clone())
                .collect();
            assets.push(DiscoveredAsset {
                hostname: obs.hostname,
                source: AssetSource::DnsBruteForce,
                detail: if addresses.is_empty() {
                    None
                } else {
                    Some(addresses.join(","))
                },
            });
        }
        Ok(assets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_wordlist_is_bounded() {
        assert!(DEFAULT_WORDLIST.len() < 200, "wordlist must stay a seed, not a dictionary");
        assert!(DEFAULT_WORDLIST.len() > 20);
    }

    #[test]
    fn candidates_are_built_per_wordlist_entry() {
        let source = DnsBruteForceSource::new().unwrap();
        let target = Target {
            domain: "example.com".into(),
            seeds: vec![],
        };
        let candidates = source.candidates(&target);
        assert_eq!(candidates.len(), source.wordlist.len());
        assert!(candidates.contains(&"api.example.com".to_string()));
    }

    #[test]
    fn custom_wordlist_replaces_default() {
        let source = DnsBruteForceSource::new()
            .unwrap()
            .with_wordlist(vec!["only".into()]);
        let target = Target {
            domain: "example.com".into(),
            seeds: vec![],
        };
        assert_eq!(source.candidates(&target), vec!["only.example.com".to_string()]);
    }

    #[test]
    fn asset_source_is_dns() {
        let source = DnsBruteForceSource::new().unwrap();
        assert_eq!(source.asset_source(), AssetSource::DnsBruteForce);
        assert_eq!(source.name(), "dns-bruteforce");
    }
}
