//! The BugTools pipeline runtime.
//!
//! Orchestrates: Target → Scope → Discovery → DNS → HTTP probe → Crawl →
//! Normalization → Output. Every stage communicates through typed Rust
//! structures and emits `PipelineEvent`s, so the CLI and GUI share one core.

use bugtools_core::http::{HttpRequest, HttpResponse};
use bugtools_crawler::{extraction, CrawlConfig};
use bugtools_dns::{DnsConfig, DnsEngine, RecordType};
use bugtools_discovery::{DiscoveryEngine, Target};
use bugtools_http::SafeHttpClient;
use bugtools_output::{
    AssetEvent, CollectingSink, DnsEvent, EventSink, HttpEvent, PipelineEvent, PipelineSummary,
    UrlEvent,
};
use bugtools_scope::ScopeEngine;
use std::sync::Arc;
use std::time::Instant;

/// Configuration for a full pipeline run.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub dns: DnsConfig,
    pub crawl: CrawlConfig,
    /// HTTP probe path used when testing a host root.
    pub probe_path: String,
    /// Maximum hosts to probe concurrently.
    pub http_concurrency: usize,
    /// Request rate limit for probing.
    pub requests_per_second: f64,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            dns: DnsConfig::default(),
            crawl: CrawlConfig::default(),
            probe_path: "/".to_string(),
            http_concurrency: 8,
            requests_per_second: 5.0,
        }
    }
}

/// The orchestrating engine. Holds the shared scope and HTTP client so
/// every outbound request is scope-checked and rate-limited centrally.
pub struct Pipeline {
    config: PipelineConfig,
    scope: Arc<ScopeEngine>,
    http: Arc<SafeHttpClient>,
    dns: Arc<DnsEngine>,
}

impl Pipeline {
    /// Build a pipeline. The scope starts empty; `add_target_to_scope` must
    /// be called before a run or every request will be denied (default deny).
    pub fn new(config: PipelineConfig) -> Result<Self, String> {
        let scope = Arc::new(ScopeEngine::new());
        let dns = Arc::new(DnsEngine::new(config.dns.clone()).map_err(|e| e.to_string())?);
        let http = Arc::new(SafeHttpClient::new(
            scope.clone(),
            bugtools_http::HttpClientConfig {
                max_concurrency: config.http_concurrency,
                rate_limit_rps: config.requests_per_second,
                max_budget: 100_000,
                ..Default::default()
            },
        ));
        Ok(Self {
            config,
            scope,
            http,
            dns,
        })
    }

    pub fn scope(&self) -> Arc<ScopeEngine> {
        self.scope.clone()
    }

    /// Add the target and its subdomain wildcard to scope. This is the
    /// explicit authorization step — nothing is scanned before it.
    pub fn authorize_target(&self, target: &Target) {
        use bugtools_core::scope::{ScopeRule, ScopeRuleType};
        let project = uuid::Uuid::nil();
        self.scope
            .add_rule(ScopeRule::new(project, ScopeRuleType::IncludeDomain, target.domain.clone()));
        self.scope.add_rule(ScopeRule::new(
            project,
            ScopeRuleType::IncludeDomain,
            format!("*.{}", target.domain),
        ));
    }

    /// Run the full pipeline for a target, streaming events to `sink`.
    pub async fn run(&self, target: &Target, sink: &dyn EventSink) -> PipelineSummary {
        let start = Instant::now();
        let mut summary = PipelineSummary {
            target: target.domain.clone(),
            ..Default::default()
        };

        sink.emit(PipelineEvent::Started {
            target: target.domain.clone(),
            stages: vec![
                "scope".into(),
                "discovery".into(),
                "dns".into(),
                "http".into(),
                "crawl".into(),
            ],
        });

        // ── Stage 1: scope ──────────────────────────────────────────────
        self.authorize_target(target);

        // ── Stage 2: discovery ──────────────────────────────────────────
        let engine = DiscoveryEngine::new()
            .with_source(Arc::new(
                bugtools_discovery::sources::CertificateTransparencySource::new(),
            ))
            .with_source(Arc::new(
                match bugtools_discovery::sources::DnsBruteForceSource::new() {
                    Ok(s) => s,
                    Err(e) => {
                        sink.emit(PipelineEvent::Warning(format!("DNS source unavailable: {e}")));
                        return self.finish(summary, start, sink);
                    }
                },
            ));

        let (assets, stats) = engine.run(target).await;
        for asset in &assets {
            sink.emit(PipelineEvent::DiscoveryFound(AssetEvent {
                hostname: asset.hostname.clone(),
                source: format!("{:?}", asset.source).to_lowercase(),
            }));
        }
        summary.subdomains = assets.len();
        sink.emit(PipelineEvent::DiscoveryComplete {
            total: assets.len(),
            per_source: stats.per_source.into_iter().collect(),
        });

        if assets.is_empty() {
            sink.emit(PipelineEvent::Warning(
                "No subdomains discovered; probing the seed host only.".into(),
            ));
        }

        // ── Stage 3: DNS resolution (hosts already resolved by discovery,
        //    but we re-observe the seed set to stream DnsEvents) ──────────
        let mut hostnames: Vec<String> = assets.iter().map(|a| a.hostname.clone()).collect();
        hostnames.extend(target.seeds.iter().cloned());
        hostnames.sort();
        hostnames.dedup();

        let dns_results = self
            .dns
            .observe_many(&hostnames, &[RecordType::A, RecordType::Aaaa, RecordType::Cname])
            .await;

        let mut live_hosts = Vec::new();
        for (host, result) in hostnames.iter().zip(dns_results) {
            let (addresses, resolves, wildcard) = match result {
                Ok(obs) => (
                    obs.records
                        .iter()
                        .filter(|r| {
                            matches!(
                                r.record_type,
                                RecordType::A | RecordType::Aaaa | RecordType::Cname
                            )
                        })
                        .map(|r| r.value.clone())
                        .collect::<Vec<_>>(),
                    obs.resolves,
                    obs.wildcard,
                ),
                Err(_) => (Vec::new(), false, false),
            };
            if resolves {
                summary.resolved_hosts += 1;
                live_hosts.push(host.clone());
            }
            sink.emit(PipelineEvent::DnsResolved(DnsEvent {
                hostname: host.clone(),
                addresses,
                resolves,
                wildcard,
            }));
        }

        // ── Stage 4: HTTP probe ─────────────────────────────────────────
        for host in &live_hosts {
            let url = format!("https://{}{}", host, self.config.probe_path);
            let req = HttpRequest {
                id: uuid::Uuid::new_v4(),
                job_id: None,
                url: url.clone(),
                method: "GET".to_string(),
                headers: Default::default(),
                body: None,
                timestamp: chrono::Utc::now(),
            };
            match self.http.execute(req).await {
                Ok(resp) => {
                    summary.http_probed += 1;
                    if (200..400).contains(&resp.status_code) {
                        summary.live_hosts += 1;
                    }
                    sink.emit(PipelineEvent::HttpObserved(http_event(&url, &resp)));
                }
                Err(e) => {
                    sink.emit(PipelineEvent::Warning(format!("probe {url} failed: {e}")));
                }
            }
        }

        // ── Stage 5: crawl the seed host ────────────────────────────────
        if let Some(seed) = target.seeds.first() {
            let seed_url = format!("https://{}/", seed);
            let (urls, pages) = self.crawl(&seed_url, sink).await;
            summary.urls_crawled = urls;
            summary.pages_fetched = pages;
            sink.emit(PipelineEvent::CrawlComplete {
                urls,
                pages,
            });
        }

        self.finish(summary, start, sink)
    }

    /// Crawl from a seed URL, emitting URL discovery events.
    async fn crawl(&self, seed_url: &str, sink: &dyn EventSink) -> (usize, usize) {
        use bugtools_crawler::{CrawlFrontier, FrontierConfig};

        let mut frontier = CrawlFrontier::new(FrontierConfig {
            max_depth: self.config.crawl.max_depth,
            max_urls: self.config.crawl.max_urls,
        });
        frontier.seed(seed_url);

        let mut pages_fetched = 0;
        while let Some(item) = frontier.next() {
            let req = HttpRequest {
                id: uuid::Uuid::new_v4(),
                job_id: None,
                url: item.url.clone(),
                method: "GET".to_string(),
                headers: Default::default(),
                body: None,
                timestamp: chrono::Utc::now(),
            };
            match self.http.execute(req).await {
                Ok(resp) => {
                    pages_fetched += 1;
                    let ct = resp
                        .headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                        .map(|(_, v)| v.clone());
                    let is_html = ct
                        .as_deref()
                        .map(|c| c.contains("html"))
                        .unwrap_or(true);

                    sink.emit(PipelineEvent::HttpObserved(http_event(&item.url, &resp)));

                    if is_html && !resp.body.is_empty() {
                        let links = extraction::extract_endpoints(&resp.body);
                        let next_depth = item.depth + 1;
                        let discovered: Vec<String> = links
                            .iter()
                            .filter_map(|l| resolve_link(&item.url, l))
                            .collect();
                        for url in &discovered {
                            sink.emit(PipelineEvent::UrlDiscovered(UrlEvent {
                                url: url.clone(),
                                depth: next_depth,
                            }));
                        }
                        frontier.add_links(discovered.iter().map(|s| s.as_str()), next_depth);
                    }
                }
                Err(e) => {
                    sink.emit(PipelineEvent::Warning(format!("crawl {} failed: {e}", item.url)));
                }
            }

            // Cancellation/time budget guard.
            if pages_fetched >= self.config.crawl.max_urls {
                break;
            }
        }

        (frontier.visited_len(), pages_fetched)
    }

    fn finish(
        &self,
        mut summary: PipelineSummary,
        start: Instant,
        sink: &dyn EventSink,
    ) -> PipelineSummary {
        summary.duration_ms = start.elapsed().as_millis() as u64;
        sink.emit(PipelineEvent::Complete {
            summary: summary.clone(),
        });
        summary
    }
}

fn http_event(url: &str, resp: &HttpResponse) -> HttpEvent {
    let content_type = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone());
    let title = extract_title(&resp.body);
    HttpEvent {
        url: url.to_string(),
        status: resp.status_code,
        content_type,
        content_length: Some(resp.size_bytes as u64),
        duration_ms: resp.duration_ms,
        title,
    }
}

/// Extract the `<title>` text from an HTML body, if present.
fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    let start = lower.find("<title")?;
    let open_end = lower[start..].find('>')? + start + 1;
    let end = lower[open_end..].find("</title>")? + open_end;
    let title = body[open_end..end].trim();
    if title.is_empty() {
        None
    } else {
        Some(title.chars().take(120).collect())
    }
}

/// Resolve a discovered link against its page base URL.
fn resolve_link(base: &str, link: &extraction::ExtractedLink) -> Option<String> {
    let raw: String = match link {
        extraction::ExtractedLink::Anchor(h)
        | extraction::ExtractedLink::Script(h)
        | extraction::ExtractedLink::Image(h)
        | extraction::ExtractedLink::Stylesheet(h)
        | extraction::ExtractedLink::PathLike(h) => h.clone(),
        extraction::ExtractedLink::Form { action, .. } => action.clone(),
    };
    if raw.is_empty() || raw.starts_with("javascript:") || raw.starts_with("mailto:") {
        return None;
    }
    url::Url::parse(base)
        .ok()?
        .join(&raw)
        .ok()
        .map(|u| u.to_string())
}

/// Convenience: run a pipeline and collect all events (used by tests/GUI).
pub async fn run_collecting(
    config: PipelineConfig,
    target: &Target,
) -> Result<(PipelineSummary, Vec<PipelineEvent>), String> {
    let pipeline = Pipeline::new(config)?;
    let sink = CollectingSink::new();
    let summary = pipeline.run(target, &sink).await;
    Ok((summary, sink.events()))
}
