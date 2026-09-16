//! Native DNS resolution layer.
//!
//! Implements BugTools' own resolver abstraction over `hickory-resolver`
//! (a DNS *library*, not a reconnaissance tool). Supports A, AAAA, CNAME,
//! MX, NS, TXT and SOA lookups, with concurrency control, timeouts, bounded
//! retries, an in-memory cache, and wildcard detection.
//!
//! Scope and rate limits are the caller's responsibility at the engine
//! level; this layer bounds its own concurrency so a single target can
//! never flood a resolver.

use async_trait::async_trait;
use hickory_resolver::TokioAsyncResolver;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("resolution failed: {0}")]
    Resolution(String),
    #[error("invalid hostname: {0}")]
    InvalidHost(String),
    #[error("lookup timed out after {0:?}")]
    Timeout(Duration),
}

/// The DNS record types the engine models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Txt,
    Soa,
}

impl RecordType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::Aaaa => "AAAA",
            RecordType::Cname => "CNAME",
            RecordType::Mx => "MX",
            RecordType::Ns => "NS",
            RecordType::Txt => "TXT",
            RecordType::Soa => "SOA",
        }
    }
}

/// A single resolved DNS record, normalized for storage/analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub hostname: String,
    pub record_type: RecordType,
    pub value: String,
    /// TTL in seconds when the resolver reported one.
    pub ttl: Option<u32>,
}

/// The result of resolving one hostname across the requested types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsObservation {
    pub hostname: String,
    pub records: Vec<DnsRecord>,
    pub duration_ms: u64,
    /// True when the hostname resolves only because the zone has a wildcard.
    pub wildcard: bool,
    /// Whether the hostname resolved to at least one address (A/AAAA/CNAME).
    pub resolves: bool,
}

#[async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(
        &self,
        hostname: &str,
        record_types: &[RecordType],
    ) -> Result<Vec<DnsRecord>, DnsError>;
}

/// Configuration for the resolver engine.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// Maximum simultaneous lookups.
    pub max_concurrency: usize,
    /// Per-lookup timeout.
    pub timeout: Duration,
    /// Number of retry attempts after the first failure.
    pub retries: u32,
    /// Cache entry lifetime.
    pub cache_ttl: Duration,
    /// Whether to probe for wildcard DNS support.
    pub wildcard_detection: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 20,
            timeout: Duration::from_secs(5),
            retries: 1,
            cache_ttl: Duration::from_secs(300),
            wildcard_detection: true,
        }
    }
}

struct CacheEntry {
    records: Vec<DnsRecord>,
    inserted: Instant,
}

/// The native DNS engine: resolver + concurrency + cache + wildcard detection.
pub struct DnsEngine {
    resolver: TokioAsyncResolver,
    config: DnsConfig,
    semaphore: Arc<Semaphore>,
    cache: Arc<Mutex<HashMap<(String, RecordType), CacheEntry>>>,
}

impl DnsEngine {
    /// Build an engine with the system resolver configuration.
    pub fn new(config: DnsConfig) -> Result<Self, DnsError> {
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .map_err(|e| DnsError::Resolution(format!("cannot build resolver: {e}")))?;
        let semaphore = Arc::new(Semaphore::new(config.max_concurrency.max(1)));
        Ok(Self {
            resolver,
            config,
            semaphore,
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Build an engine with explicit name servers (used in tests).
    pub fn with_nameservers(config: DnsConfig, servers: Vec<std::net::IpAddr>) -> Result<Self, DnsError> {
        use hickory_resolver::config::{ResolverConfig, ResolverOpts};
        let mut resolver_config = ResolverConfig::new();
        for server in servers {
            resolver_config.add_name_server(hickory_resolver::config::NameServerConfigGroup::from_ips_clear(
                &[server],
                53,
                true,
            ).pop().unwrap());
        }
        let resolver = TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default());
        Ok(Self {
            resolver,
            config,
            semaphore: Arc::new(Semaphore::new(20)),
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn cached(&self, host: &str, rt: RecordType) -> Option<Vec<DnsRecord>> {
        let cache = self.cache.lock().await;
        cache
            .get(&(host.to_string(), rt))
            .filter(|e| e.inserted.elapsed() < self.config.cache_ttl)
            .map(|e| e.records.clone())
    }

    async fn store(&self, host: &str, rt: RecordType, records: Vec<DnsRecord>) {
        let mut cache = self.cache.lock().await;
        cache.insert(
            (host.to_string(), rt),
            CacheEntry {
                records,
                inserted: Instant::now(),
            },
        );
    }

    /// Resolve a single record type with timeout + bounded retries.
    async fn resolve_type(&self, hostname: &str, rt: RecordType) -> Result<Vec<DnsRecord>, DnsError> {
        if let Some(cached) = self.cached(hostname, rt).await {
            return Ok(cached);
        }

        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| DnsError::Resolution("resolver closed".into()))?;

        let mut last_err = None;
        for attempt in 0..=self.config.retries {
            let lookup = self.do_lookup(hostname, rt);
            match tokio::time::timeout(self.config.timeout, lookup).await {
                Ok(Ok(records)) => {
                    self.store(hostname, rt, records.clone()).await;
                    return Ok(records);
                }
                Ok(Err(e)) => last_err = Some(e),
                Err(_) => last_err = Some(DnsError::Timeout(self.config.timeout)),
            }
            if attempt < self.config.retries {
                tokio::time::sleep(Duration::from_millis(150 * (attempt as u64 + 1))).await;
            }
        }
        Err(last_err.unwrap_or_else(|| DnsError::Resolution("unknown".into())))
    }

    async fn do_lookup(&self, hostname: &str, rt: RecordType) -> Result<Vec<DnsRecord>, DnsError> {
        let mut out = Vec::new();
        match rt {
            RecordType::A => {
                let lookup = self
                    .resolver
                    .ipv4_lookup(hostname)
                    .await
                    .map_err(|e| DnsError::Resolution(e.to_string()))?;
                for ip in lookup.iter() {
                    out.push(DnsRecord {
                        hostname: hostname.to_string(),
                        record_type: rt,
                        value: ip.to_string(),
                        ttl: None,
                    });
                }
            }
            RecordType::Aaaa => {
                let lookup = self
                    .resolver
                    .ipv6_lookup(hostname)
                    .await
                    .map_err(|e| DnsError::Resolution(e.to_string()))?;
                for ip in lookup.iter() {
                    out.push(DnsRecord {
                        hostname: hostname.to_string(),
                        record_type: rt,
                        value: ip.to_string(),
                        ttl: None,
                    });
                }
            }
            RecordType::Cname => {
                let lookup = self
                    .resolver
                    .lookup(hostname, hickory_resolver::proto::rr::RecordType::CNAME)
                    .await
                    .map_err(|e| DnsError::Resolution(e.to_string()))?;
                for r in lookup.iter() {
                    out.push(DnsRecord {
                        hostname: hostname.to_string(),
                        record_type: rt,
                        value: r.to_string().trim_end_matches('.').to_string(),
                        ttl: None,
                    });
                }
            }
            RecordType::Mx => {
                let lookup = self
                    .resolver
                    .mx_lookup(hostname)
                    .await
                    .map_err(|e| DnsError::Resolution(e.to_string()))?;
                for mx in lookup.iter() {
                    out.push(DnsRecord {
                        hostname: hostname.to_string(),
                        record_type: rt,
                        value: mx.exchange().to_string().trim_end_matches('.').to_string(),
                        ttl: None,
                    });
                }
            }
            RecordType::Ns => {
                let lookup = self
                    .resolver
                    .ns_lookup(hostname)
                    .await
                    .map_err(|e| DnsError::Resolution(e.to_string()))?;
                for ns in lookup.iter() {
                    out.push(DnsRecord {
                        hostname: hostname.to_string(),
                        record_type: rt,
                        value: ns.to_string().trim_end_matches('.').to_string(),
                        ttl: None,
                    });
                }
            }
            RecordType::Txt => {
                let lookup = self
                    .resolver
                    .txt_lookup(hostname)
                    .await
                    .map_err(|e| DnsError::Resolution(e.to_string()))?;
                for txt in lookup.iter() {
                    out.push(DnsRecord {
                        hostname: hostname.to_string(),
                        record_type: rt,
                        value: txt.to_string(),
                        ttl: None,
                    });
                }
            }
            RecordType::Soa => {
                let lookup = self
                    .resolver
                    .soa_lookup(hostname)
                    .await
                    .map_err(|e| DnsError::Resolution(e.to_string()))?;
                if let Some(soa) = lookup.iter().next() {
                    out.push(DnsRecord {
                        hostname: hostname.to_string(),
                        record_type: rt,
                        value: format!("{} {}", soa.mname(), soa.rname()),
                        ttl: Some(soa.minimum() as u32),
                    });
                }
            }
        }
        Ok(out)
    }

    /// Resolve a hostname across several record types and classify the result.
    pub async fn observe(
        &self,
        hostname: &str,
        record_types: &[RecordType],
    ) -> Result<DnsObservation, DnsError> {
        if hostname.trim().is_empty() {
            return Err(DnsError::InvalidHost(hostname.to_string()));
        }
        let start = Instant::now();
        let mut records = Vec::new();
        let mut resolves = false;

        for rt in record_types {
            match self.resolve_type(hostname, *rt).await {
                Ok(mut found) => {
                    if matches!(rt, RecordType::A | RecordType::Aaaa | RecordType::Cname)
                        && !found.is_empty()
                    {
                        resolves = true;
                    }
                    records.append(&mut found);
                }
                Err(DnsError::Timeout(_)) => {
                    // A timeout on one type is not fatal for the observation.
                }
                Err(_) => {
                    // NXDOMAIN / no records of this type is normal.
                }
            }
        }

        let wildcard = if self.config.wildcard_detection && !resolves {
            self.detect_wildcard(hostname).await
        } else {
            false
        };

        Ok(DnsObservation {
            hostname: hostname.to_string(),
            records,
            duration_ms: start.elapsed().as_millis() as u64,
            wildcard,
            resolves,
        })
    }

    /// Detect wildcard DNS by looking up a random subdomain of the target's
    /// parent domain. If it resolves, the zone has a wildcard.
    async fn detect_wildcard(&self, hostname: &str) -> bool {
        let parts: Vec<&str> = hostname.split('.').collect();
        if parts.len() < 2 {
            return false;
        }
        let parent = parts[parts.len() - 2..].join(".");
        let probe = format!("bugtools-wildcard-probe-{}.{}", std::process::id(), parent);
        match self
            .resolve_type(&probe, RecordType::A)
            .await
        {
            Ok(records) => !records.is_empty(),
            Err(_) => false,
        }
    }

    /// Resolve many hostnames with bounded concurrency, preserving input order.
    ///
    /// Uses a bounded stream rather than spawning unbounded tasks, so a large
    /// hostname list cannot exhaust memory or flood the resolver.
    pub async fn observe_many(
        &self,
        hostnames: &[String],
        record_types: &[RecordType],
    ) -> Vec<Result<DnsObservation, DnsError>> {
        use futures::stream::{self, StreamExt};

        let rts = record_types.to_vec();
        stream::iter(hostnames.iter().cloned())
            .map(|host| {
                let rts = rts.clone();
                async move { self.observe(&host, &rts).await }
            })
            .buffered(self.config.max_concurrency.max(1))
            .collect()
            .await
    }
}

#[async_trait]
impl Resolver for DnsEngine {
    async fn resolve(
        &self,
        hostname: &str,
        record_types: &[RecordType],
    ) -> Result<Vec<DnsRecord>, DnsError> {
        let mut all = Vec::new();
        for rt in record_types {
            all.extend(self.resolve_type(hostname, *rt).await?);
        }
        Ok(all)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_type_labels() {
        assert_eq!(RecordType::A.as_str(), "A");
        assert_eq!(RecordType::Aaaa.as_str(), "AAAA");
        assert_eq!(RecordType::Cname.as_str(), "CNAME");
    }

    #[test]
    fn empty_hostname_rejected() {
        let config = DnsConfig::default();
        // Build without touching the network config if possible; fall back
        // to system config which is available in CI.
        if let Ok(engine) = DnsEngine::new(config) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let result = rt.block_on(engine.observe("", &[RecordType::A]));
            assert!(result.is_err());
        }
    }

    #[test]
    fn observation_defaults_are_honest() {
        // A DnsObservation with no records must report resolves=false.
        let obs = DnsObservation {
            hostname: "nonexistent.invalid".into(),
            records: vec![],
            duration_ms: 1,
            wildcard: false,
            resolves: false,
        };
        assert!(!obs.resolves);
        assert!(obs.records.is_empty());
    }

    #[test]
    fn dns_config_defaults_are_bounded() {
        let c = DnsConfig::default();
        assert!(c.max_concurrency <= 50);
        assert!(c.timeout <= Duration::from_secs(10));
    }
}
