//! Endpoint discovery data models.
//!
//! An extractor emits [`RawEndpoint`]s — exactly what it saw in the document,
//! unresolved and unmerged. The engine resolves each against an optional base
//! URL, templatizes the path, and merges them into classified [`Endpoint`]s.
//! Keeping the two types distinct is what lets extractors stay pure and the
//! merge/normalization logic stay in one place.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EndpointError {
    #[error("invalid base url: {0}")]
    InvalidBase(String),
}

/// What kind of resource an endpoint points at. Classification is a precision
/// signal: an API route is far more interesting to a researcher than a static
/// asset, so the engine never lumps them together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    /// A navigable HTML page.
    Page,
    /// A likely application/API route (JSON/RPC/GraphQL).
    ApiRoute,
    /// A static asset (script, stylesheet, image, font).
    StaticAsset,
    /// A form submission target.
    FormAction,
    /// A websocket endpoint (`ws://` / `wss://`).
    WebSocket,
    /// Could not be classified.
    Unknown,
}

impl EndpointKind {
    /// Sort/merge precedence — lower is "more interesting" and wins when two
    /// findings for the same route disagree on kind.
    pub fn precedence(&self) -> u8 {
        match self {
            EndpointKind::ApiRoute => 0,
            EndpointKind::FormAction => 1,
            EndpointKind::WebSocket => 2,
            EndpointKind::Page => 3,
            EndpointKind::StaticAsset => 4,
            EndpointKind::Unknown => 5,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            EndpointKind::Page => "page",
            EndpointKind::ApiRoute => "api",
            EndpointKind::StaticAsset => "asset",
            EndpointKind::FormAction => "form",
            EndpointKind::WebSocket => "websocket",
            EndpointKind::Unknown => "unknown",
        }
    }
}

/// The HTTP method an endpoint is reached with, when observable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum MethodHint {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Options,
    Head,
    /// Method could not be determined from the source (e.g. a bare URL string).
    Unknown,
}

impl MethodHint {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_uppercase().as_str() {
            "GET" => MethodHint::Get,
            "POST" => MethodHint::Post,
            "PUT" => MethodHint::Put,
            "PATCH" => MethodHint::Patch,
            "DELETE" => MethodHint::Delete,
            "OPTIONS" => MethodHint::Options,
            "HEAD" => MethodHint::Head,
            _ => MethodHint::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MethodHint::Get => "GET",
            MethodHint::Post => "POST",
            MethodHint::Put => "PUT",
            MethodHint::Patch => "PATCH",
            MethodHint::Delete => "DELETE",
            MethodHint::Options => "OPTIONS",
            MethodHint::Head => "HEAD",
            MethodHint::Unknown => "?",
        }
    }

    pub fn is_known(&self) -> bool {
        !matches!(self, MethodHint::Unknown)
    }
}

/// Where a parameter is carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamLocation {
    Query,
    Form,
    Path,
    Body,
}

/// A single parameter observed on an endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EndpointParam {
    pub name: String,
    pub location: ParamLocation,
}

/// Which extractor produced a finding. Provenance drives confidence: a form
/// action parsed from the DOM is near-certain, a bare path matched by the
/// text heuristic is a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractorKind {
    HtmlAnchor,
    HtmlForm,
    HtmlResource,
    HtmlScript,
    JsFetch,
    JsXhr,
    JsAxios,
    JsStringLiteral,
    PathHeuristic,
}

impl ExtractorKind {
    /// How much a single finding from this source is worth on its own,
    /// before any corroboration bonus.
    pub fn base_confidence(&self) -> u8 {
        match self {
            // Structured DOM facts — the reference is unambiguous.
            ExtractorKind::HtmlForm => 90,
            ExtractorKind::HtmlAnchor => 80,
            ExtractorKind::HtmlScript => 75,
            ExtractorKind::HtmlResource => 70,
            // An explicit request call names both a method and a URL.
            ExtractorKind::JsFetch => 78,
            ExtractorKind::JsXhr => 78,
            ExtractorKind::JsAxios => 78,
            // A URL-shaped string literal: probably a route, but unproven.
            ExtractorKind::JsStringLiteral => 45,
            // A path-shaped run of text anywhere in the document: weakest.
            ExtractorKind::PathHeuristic => 30,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ExtractorKind::HtmlAnchor => "html-anchor",
            ExtractorKind::HtmlForm => "html-form",
            ExtractorKind::HtmlResource => "html-resource",
            ExtractorKind::HtmlScript => "html-script",
            ExtractorKind::JsFetch => "js-fetch",
            ExtractorKind::JsXhr => "js-xhr",
            ExtractorKind::JsAxios => "js-axios",
            ExtractorKind::JsStringLiteral => "js-string",
            ExtractorKind::PathHeuristic => "path-heuristic",
        }
    }
}

/// A raw finding from one extractor, before resolution or merging. `raw` is
/// the reference exactly as it appeared in the document (possibly relative).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEndpoint {
    pub raw: String,
    pub method: MethodHint,
    pub kind: EndpointKind,
    pub params: Vec<EndpointParam>,
    pub source: ExtractorKind,
}

impl RawEndpoint {
    pub fn new(raw: impl Into<String>, source: ExtractorKind) -> Self {
        Self {
            raw: raw.into(),
            method: MethodHint::Unknown,
            kind: EndpointKind::Unknown,
            params: Vec::new(),
            source,
        }
    }

    pub fn with_method(mut self, method: MethodHint) -> Self {
        self.method = method;
        self
    }

    pub fn with_kind(mut self, kind: EndpointKind) -> Self {
        self.kind = kind;
        self
    }

    pub fn with_params(mut self, params: Vec<EndpointParam>) -> Self {
        self.params = params;
        self
    }
}

/// A merged, classified, templated endpoint — the engine's output unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// Templated route key, e.g. `/api/users/{id}`.
    pub path: String,
    /// A concrete representative reference, e.g. `/api/users/42?full=1`.
    pub display: String,
    pub method: MethodHint,
    pub kind: EndpointKind,
    pub params: Vec<EndpointParam>,
    /// Distinct extractors that corroborate this endpoint.
    pub sources: Vec<ExtractorKind>,
    /// How many raw findings collapsed into this endpoint.
    pub occurrences: usize,
    /// 0–100. Driven by source precision and cross-source corroboration.
    pub confidence: u8,
}

/// The trait every extractor implements. Extractors are pure over the document
/// text so they compose and unit-test cleanly; resolution and merging are the
/// engine's job.
pub trait EndpointExtractor: Send + Sync {
    fn name(&self) -> &'static str;

    /// The provenance tag every finding from this extractor carries.
    fn kind(&self) -> ExtractorKind;

    /// Emit every reference this extractor can see in `content`.
    fn extract(&self, content: &str) -> Vec<RawEndpoint>;
}

/// Per-extractor and aggregate counts, surfaced in the CLI summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtractionStats {
    pub per_extractor: std::collections::BTreeMap<String, usize>,
    pub total_raw: usize,
    pub total_after_merge: usize,
    /// References dropped because they resolved to a host outside the base.
    pub external_skipped: usize,
}

/// An analysis result: the classified endpoints plus the run's statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointReport {
    pub endpoints: Vec<Endpoint>,
    pub stats: ExtractionStats,
}
