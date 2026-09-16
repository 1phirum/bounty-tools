//! Pipeline event stream. The CLI renders these; the GUI consumes the same
//! events. Typed Rust structures — no temporary text files between stages.

use serde::{Deserialize, Serialize};

/// A hostname discovered during the discovery stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetEvent {
    pub hostname: String,
    pub source: String,
}

/// A DNS observation for one hostname.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEvent {
    pub hostname: String,
    pub addresses: Vec<String>,
    pub resolves: bool,
    pub wildcard: bool,
}

/// An HTTP probe result for one URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpEvent {
    pub url: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub duration_ms: u64,
    pub title: Option<String>,
}

/// A URL discovered during crawling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlEvent {
    pub url: String,
    pub depth: u32,
}

/// The result of an XSS assessment for one endpoint. Deliberately compact
/// and self-contained: `bugtools-output` must not depend on the XSS engine,
/// so this carries only what a consumer needs to render or store the result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssAssessmentEvent {
    pub target: String,
    pub endpoint: String,
    pub parameter: Option<String>,
    /// The exploitability stage label, e.g. `EXECUTION_CONFIRMED`.
    pub stage: String,
    /// True only when execution was confirmed by browser evidence.
    pub confirmed: bool,
    /// The confidence level label.
    pub confidence: String,
    /// Stated weaknesses of the assessment, if any.
    pub limitations: Vec<String>,
}

/// Everything the pipeline emits, in order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum PipelineEvent {
    Started { target: String, stages: Vec<String> },
    DiscoveryFound(AssetEvent),
    DiscoveryComplete { total: usize, per_source: Vec<(String, usize)> },
    DnsResolved(DnsEvent),
    HttpObserved(HttpEvent),
    UrlDiscovered(UrlEvent),
    XssAssessed(XssAssessmentEvent),
    CrawlComplete { urls: usize, pages: usize },
    Warning(String),
    Error(String),
    Complete { summary: PipelineSummary },
}

/// Aggregate result of a pipeline run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PipelineSummary {
    pub target: String,
    pub subdomains: usize,
    pub resolved_hosts: usize,
    pub http_probed: usize,
    pub urls_crawled: usize,
    pub pages_fetched: usize,
    pub live_hosts: usize,
    pub duration_ms: u64,
}

/// A sink for pipeline events. Implemented by the CLI renderer and by the
/// GUI bridge, so both consume identical data.
pub trait EventSink: Send + Sync {
    fn emit(&self, event: PipelineEvent);
}

/// A sink that collects events into a vector (useful for tests and for the
/// GUI, which reads them afterwards).
#[derive(Default)]
pub struct CollectingSink {
    events: std::sync::Mutex<Vec<PipelineEvent>>,
}

impl CollectingSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn events(&self) -> Vec<PipelineEvent> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.events.lock().map(|e| e.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl EventSink for CollectingSink {
    fn emit(&self, event: PipelineEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }
}
