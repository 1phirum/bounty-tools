//! The endpoint engine: runs extractors, resolves and templatizes references,
//! and merges the overlap into classified [`Endpoint`]s with a confidence that
//! reflects how many independent sources agree.

use std::collections::HashMap;

use url::Url;

use crate::classify;
use crate::models::{
    Endpoint, EndpointExtractor, EndpointKind, EndpointParam, EndpointReport, ExtractionStats,
    ExtractorKind, MethodHint, ParamLocation,
};
use crate::normalization::{self, NormalizedRef};

/// A single resolved finding, pre-merge.
struct Entry {
    path: String,
    display: String,
    method: MethodHint,
    source: ExtractorKind,
    params: Vec<EndpointParam>,
    is_form: bool,
}

pub struct EndpointEngine {
    extractors: Vec<Box<dyn EndpointExtractor>>,
    base: Option<Url>,
    include_external: bool,
    include_assets: bool,
}

impl EndpointEngine {
    pub fn new() -> Self {
        Self {
            extractors: Vec::new(),
            base: None,
            include_external: false,
            include_assets: true,
        }
    }

    /// The standard extractor set: HTML DOM, JavaScript, and the path heuristic.
    pub fn default_set() -> Self {
        use crate::extractors::{HtmlExtractor, JavaScriptExtractor, PathHeuristicExtractor};
        Self::new()
            .with_extractor(Box::new(HtmlExtractor))
            .with_extractor(Box::new(JavaScriptExtractor))
            .with_extractor(Box::new(PathHeuristicExtractor))
    }

    pub fn with_extractor(mut self, e: Box<dyn EndpointExtractor>) -> Self {
        self.extractors.push(e);
        self
    }

    /// Resolve relative references against this base and drop off-host refs.
    pub fn with_base(mut self, base: Url) -> Self {
        self.base = Some(base);
        self
    }

    /// Keep references that resolve to a host other than the base's.
    pub fn include_external(mut self, yes: bool) -> Self {
        self.include_external = yes;
        self
    }

    /// Keep static-asset endpoints in the output.
    pub fn include_assets(mut self, yes: bool) -> Self {
        self.include_assets = yes;
        self
    }

    pub fn extractor_names(&self) -> Vec<&'static str> {
        self.extractors.iter().map(|e| e.name()).collect()
    }

    /// Analyze one document and return classified endpoints plus statistics.
    pub fn analyze(&self, content: &str) -> EndpointReport {
        let mut stats = ExtractionStats::default();
        let mut entries: Vec<Entry> = Vec::new();

        for extractor in &self.extractors {
            let raws = extractor.extract(content);
            *stats.per_extractor.entry(extractor.name().to_string()).or_insert(0) += raws.len();
            stats.total_raw += raws.len();

            for raw in raws {
                let Some(NormalizedRef { path, query_params, display, external }) =
                    normalization::normalize(self.base.as_ref(), &raw.raw)
                else {
                    continue;
                };
                if external && self.base.is_some() && !self.include_external {
                    stats.external_skipped += 1;
                    continue;
                }
                let mut params = raw.params.clone();
                for name in query_params {
                    if !params.iter().any(|p| p.name == name && p.location == ParamLocation::Query) {
                        params.push(EndpointParam { name, location: ParamLocation::Query });
                    }
                }
                entries.push(Entry {
                    path: normalization::templatize(&path),
                    display,
                    method: raw.method,
                    source: raw.source,
                    params,
                    is_form: raw.kind == EndpointKind::FormAction,
                });
            }
        }

        let endpoints = self.merge(entries);
        stats.total_after_merge = endpoints.len();
        EndpointReport { endpoints, stats }
    }

    /// Group by templated path, split concrete methods apart, fold ambiguous
    /// (`Unknown`-method) findings into each concrete method they share a path
    /// with, and compute classification + confidence.
    fn merge(&self, entries: Vec<Entry>) -> Vec<Endpoint> {
        // Preserve first-seen path order for stable output before the final sort.
        let mut order: Vec<String> = Vec::new();
        let mut groups: HashMap<String, Vec<Entry>> = HashMap::new();
        for e in entries {
            if !groups.contains_key(&e.path) {
                order.push(e.path.clone());
            }
            groups.entry(e.path.clone()).or_default().push(e);
        }

        let mut out = Vec::new();
        for path in order {
            let group = groups.remove(&path).unwrap();
            let concrete: Vec<MethodHint> = {
                let mut ms: Vec<MethodHint> =
                    group.iter().filter(|e| e.method.is_known()).map(|e| e.method).collect();
                ms.sort_by_key(|m| m.as_str());
                ms.dedup();
                ms
            };

            if concrete.is_empty() {
                out.push(self.build(&path, MethodHint::Unknown, group.iter().collect()));
            } else {
                for m in concrete {
                    let contributing: Vec<&Entry> = group
                        .iter()
                        .filter(|e| e.method == m || !e.method.is_known())
                        .collect();
                    out.push(self.build(&path, m, contributing));
                }
            }
        }

        out.sort_by(|a, b| {
            a.kind
                .precedence()
                .cmp(&b.kind.precedence())
                .then_with(|| b.confidence.cmp(&a.confidence))
                .then_with(|| a.path.cmp(&b.path))
                .then_with(|| a.method.as_str().cmp(b.method.as_str()))
        });
        out.retain(|e| self.include_assets || e.kind != EndpointKind::StaticAsset);
        out
    }

    fn build(&self, path: &str, method: MethodHint, entries: Vec<&Entry>) -> Endpoint {
        let is_form = entries.iter().any(|e| e.is_form);
        let kind = classify::classify(path, is_form);

        let mut params: Vec<EndpointParam> = Vec::new();
        for e in &entries {
            for p in &e.params {
                if !params.contains(p) {
                    params.push(p.clone());
                }
            }
        }

        let mut sources: Vec<ExtractorKind> = Vec::new();
        for e in &entries {
            if !sources.contains(&e.source) {
                sources.push(e.source);
            }
        }

        // Representative display: prefer a concrete-method finding, richest source.
        let display = entries
            .iter()
            .filter(|e| e.method == method)
            .max_by_key(|e| e.source.base_confidence())
            .or_else(|| entries.iter().max_by_key(|e| e.source.base_confidence()))
            .map(|e| e.display.clone())
            .unwrap_or_else(|| path.to_string());

        let confidence = confidence(&sources, kind, method);

        // Count distinct concrete references, not raw extractor hits: several
        // extractors legitimately see the same URL in one document (an anchor
        // href is also a quoted string and a path-shaped run), and that
        // corroboration already lives in `sources`. `occurrences` answers "how
        // many concrete instances collapsed into this templated route".
        let occurrences = {
            let mut displays: Vec<&str> = entries.iter().map(|e| e.display.as_str()).collect();
            displays.sort_unstable();
            displays.dedup();
            displays.len()
        };

        Endpoint {
            path: path.to_string(),
            display,
            method,
            kind,
            params,
            sources,
            occurrences,
            confidence,
        }
    }
}

impl Default for EndpointEngine {
    fn default() -> Self {
        Self::default_set()
    }
}

/// Confidence = strongest source, plus a corroboration bonus for each extra
/// independent source, plus a small bump when both kind and method are known.
fn confidence(sources: &[ExtractorKind], kind: EndpointKind, method: MethodHint) -> u8 {
    let base = sources.iter().map(|s| s.base_confidence()).max().unwrap_or(0) as u16;
    let distinct = sources.len() as u16;
    let bonus = (8 * distinct.saturating_sub(1)).min(30);
    let mut c = base + bonus;
    if kind != EndpointKind::Unknown && method.is_known() {
        c += 5;
    }
    c.min(100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(html: &str) -> EndpointReport {
        EndpointEngine::default_set().analyze(html)
    }

    fn find<'a>(r: &'a EndpointReport, path: &str, method: MethodHint) -> Option<&'a Endpoint> {
        r.endpoints.iter().find(|e| e.path == path && e.method == method)
    }

    #[test]
    fn templates_collapse_concrete_instances() {
        let html = r#"<a href="/user/1">a</a><a href="/user/2">b</a><a href="/user/3">c</a>"#;
        let r = analyze(html);
        let e = find(&r, "/user/{id}", MethodHint::Get).unwrap();
        assert_eq!(e.occurrences, 3, "three anchors, one route");
        assert_eq!(r.endpoints.iter().filter(|e| e.path == "/user/{id}").count(), 1);
    }

    #[test]
    fn get_and_post_to_same_path_stay_distinct() {
        let content = r#"<script>fetch('/api/x'); axios.post('/api/x', d);</script>"#;
        let r = analyze(content);
        assert!(find(&r, "/api/x", MethodHint::Get).is_some());
        assert!(find(&r, "/api/x", MethodHint::Post).is_some());
    }

    #[test]
    fn corroboration_raises_confidence() {
        // Same route seen by fetch AND a bare string literal AND the heuristic.
        let one = EndpointEngine::default_set().analyze(r#"<script>fetch('/api/solo')</script>"#);
        let solo = find(&one, "/api/solo", MethodHint::Get).unwrap().confidence;
        // A form action is a single very-strong source; compare corroboration.
        let many = EndpointEngine::default_set()
            .analyze(r#"<script>fetch('/api/dup'); var u = "/api/dup";</script> /api/dup"#);
        let dup = find(&many, "/api/dup", MethodHint::Get).unwrap();
        assert!(dup.sources.len() >= 2, "fetch + literal/heuristic");
        assert!(dup.confidence >= solo, "more sources, no less confidence");
    }

    #[test]
    fn classification_flows_through() {
        let html = r#"<a href="/about">x</a><script src="/app.js"></script>
            <form action="/api/login" method="post"><input name="u"></form>"#;
        let r = analyze(html);
        assert_eq!(find(&r, "/about", MethodHint::Get).unwrap().kind, EndpointKind::Page);
        assert_eq!(find(&r, "/app.js", MethodHint::Get).unwrap().kind, EndpointKind::StaticAsset);
        // /api/login is a form action but the API marker wins.
        assert_eq!(find(&r, "/api/login", MethodHint::Post).unwrap().kind, EndpointKind::ApiRoute);
    }

    #[test]
    fn base_resolves_relative_and_drops_external() {
        let base = Url::parse("https://target.test/app/").unwrap();
        let content = r#"<a href="items?id=1">x</a><script src="https://cdn.other/lib.js"></script>"#;
        let r = EndpointEngine::default_set().with_base(base).analyze(content);
        assert!(find(&r, "/app/items", MethodHint::Get).is_some());
        assert!(r.stats.external_skipped >= 1);
        assert!(!r.endpoints.iter().any(|e| e.display.contains("cdn.other")));
    }

    #[test]
    fn form_params_and_query_params_are_captured() {
        let html = r#"<form action="/search?lang=en" method="get"><input name="q"></form>"#;
        let r = analyze(html);
        let e = find(&r, "/search", MethodHint::Get).unwrap();
        assert!(e.params.iter().any(|p| p.name == "q" && p.location == ParamLocation::Form));
        assert!(e.params.iter().any(|p| p.name == "lang" && p.location == ParamLocation::Query));
    }

    #[test]
    fn assets_can_be_excluded() {
        let html = r#"<script src="/a.js"></script><a href="/page">p</a>"#;
        let r = EndpointEngine::default_set().include_assets(false).analyze(html);
        assert!(!r.endpoints.iter().any(|e| e.kind == EndpointKind::StaticAsset));
        assert!(find(&r, "/page", MethodHint::Get).is_some());
    }

    #[test]
    fn empty_input_is_clean() {
        let r = analyze("");
        assert!(r.endpoints.is_empty());
        assert_eq!(r.stats.total_after_merge, 0);
    }
}
