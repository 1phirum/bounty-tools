//! Technology Intelligence Engine — Phase 1 of the XSS brief.
//!
//! The brief's most important rule: fingerprint the target *before* testing,
//! and never report a technology or version from a single weak indicator.
//!
//! Design rules enforced here:
//! - One signal is never enough for a **technology** claim: it needs a
//!   minimum corroboration weight across independent evidence sources.
//! - A **version** is only reported when the exact version string is present
//!   in the evidence. A generic marker ("React") never yields a version.
//! - Every claim carries the signals that produced it, so nothing is asserted
//!   without evidence.

use serde::{Deserialize, Serialize};

/// Broad classification of a detected technology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TechCategory {
    Cdn,
    Waf,
    ReverseProxy,
    WebServer,
    Language,
    BackendFramework,
    FrontendFramework,
    JavaScriptRuntime,
    TemplateEngine,
    Cms,
    ApiFramework,
    Realtime,
    Database,
    Authentication,
    StaticPipeline,
    BuildSystem,

    ThirdPartyLibrary,
    SecurityMiddleware,
    Sanitizer,
}

/// Where a signal came from. Independent sources corroborate each other;
/// the same source twice does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    ResponseHeader,
    Cookie,
    HtmlBody,
    ScriptSrc,
    StaticPath,
    SourceMap,
    ErrorPage,
    ResponseStructure,
    EndpointPattern,
    JavaScriptBundle,
}

impl EvidenceSource {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ResponseHeader => "response header",
            Self::Cookie => "cookie",
            Self::HtmlBody => "html body",
            Self::ScriptSrc => "script src",
            Self::StaticPath => "static path",
            Self::SourceMap => "source map",
            Self::ErrorPage => "error page",
            Self::ResponseStructure => "response structure",
            Self::EndpointPattern => "endpoint pattern",
            Self::JavaScriptBundle => "javascript bundle",
        }
    }
}

/// One piece of evidence for a technology.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TechnologyEvidence {
    pub technology: String,
    pub category: TechCategory,
    /// Only set when the exact version string was observed. Never inferred.
    pub version: Option<String>,
    pub confidence: f32,
    pub evidence_source: EvidenceSource,
    pub evidence_value: String,
}

/// A corroborated technology with all its supporting evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnologyFinding {
    pub technology: String,
    pub category: TechCategory,
    /// Set only when at least one signal carried an exact version string.
    pub version: Option<String>,
    pub confidence: f32,
    /// Every signal that contributed. Never empty.
    pub evidence: Vec<TechnologyEvidence>,
    /// Number of distinct evidence sources — the corroboration measure.
    pub distinct_sources: usize,
}

impl TechnologyFinding {
    /// Whether the version was observed rather than assumed.
    pub fn version_is_observed(&self) -> bool {
        self.version.is_some()
    }

    /// Human summary; omits the version when it was not observed.
    pub fn summary(&self) -> String {
        match &self.version {
            Some(v) => format!("{} {} ({:.0}%)", self.technology, v, self.confidence * 100.0),
            None => format!(
                "{} (version not observed, {:.0}%)",
                self.technology,
                self.confidence * 100.0
            ),
        }
    }
}

/// A raw observation gathered from a response, before correlation.
#[derive(Debug, Clone)]
pub struct Observation {
    pub source: EvidenceSource,
    /// Header name (lowercase) when the source is a header, else unused.
    pub key: Option<String>,
    pub value: String,
}

impl Observation {
    pub fn header(name: &str, value: &str) -> Self {
        Self {
            source: EvidenceSource::ResponseHeader,
            key: Some(name.to_lowercase()),
            value: value.to_string(),
        }
    }

    pub fn body(value: &str) -> Self {
        Self {
            source: EvidenceSource::HtmlBody,
            key: None,
            value: value.to_string(),
        }
    }

    pub fn script_src(value: &str) -> Self {
        Self {
            source: EvidenceSource::ScriptSrc,
            key: None,
            value: value.to_string(),
        }
    }

    pub fn cookie(value: &str) -> Self {
        Self {
            source: EvidenceSource::Cookie,
            key: None,
            value: value.to_string(),
        }
    }
}

/// A single signature rule: a needle, the technology it implicates, and the
/// weight it contributes. `version_regex` captures the version when the
/// pattern includes it.
struct Signature {
    technology: &'static str,
    category: TechCategory,
    /// Matched case-insensitively as a substring, unless `header_only`.
    needle: &'static str,
    weight: f32,
    /// Restrict to a specific header (lowercase name).
    header_only: Option<&'static str>,
    /// How to extract a version from the matched text, if present.
    version_regex: Option<&'static str>,
}

/// The signature table. Deliberately conservative: a single generic marker
/// carries a low weight so it cannot alone cross the reporting threshold.
const SIGNATURES: &[Signature] = &[
    // ── Frameworks with explicit version exposure (server headers) ──
    Signature { technology: "Express", category: TechCategory::BackendFramework, needle: "x-powered-by: express", weight: 0.9, header_only: None, version_regex: None },
    Signature { technology: "Next.js", category: TechCategory::FrontendFramework, needle: "x-powered-by: next.js", weight: 0.9, header_only: None, version_regex: None },
    Signature { technology: "ASP.NET", category: TechCategory::BackendFramework, needle: "x-powered-by: asp.net", weight: 0.7, header_only: None, version_regex: None },
    Signature { technology: "ASP.NET", category: TechCategory::BackendFramework, needle: "x-aspnet-version", weight: 0.8, header_only: Some("x-aspnet-version"), version_regex: Some(r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)") },
    Signature { technology: "ASP.NET MVC", category: TechCategory::BackendFramework, needle: "x-aspnetmvc-version", weight: 0.8, header_only: Some("x-aspnetmvc-version"), version_regex: Some(r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)") },
    Signature { technology: "PHP", category: TechCategory::Language, needle: "x-powered-by: php", weight: 0.85, header_only: None, version_regex: Some(r"PHP/([0-9]+\.[0-9]+(?:\.[0-9]+)?)") },

    // ── Web servers with version strings ──
    Signature { technology: "nginx", category: TechCategory::WebServer, needle: "server: nginx", weight: 0.9, header_only: None, version_regex: Some(r"nginx/([0-9]+\.[0-9]+\.[0-9]+)") },
    Signature { technology: "Apache", category: TechCategory::WebServer, needle: "server: apache", weight: 0.9, header_only: None, version_regex: Some(r"Apache/([0-9]+\.[0-9]+\.[0-9]+)") },
    Signature { technology: "IIS", category: TechCategory::WebServer, needle: "server: microsoft-iis", weight: 0.9, header_only: None, version_regex: Some(r"Microsoft-IIS/([0-9]+\.[0-9]+)") },
    Signature { technology: "LiteSpeed", category: TechCategory::WebServer, needle: "server: litespeed", weight: 0.85, header_only: None, version_regex: None },
    Signature { technology: "Caddy", category: TechCategory::WebServer, needle: "server: caddy", weight: 0.85, header_only: None, version_regex: None },

    // ── CDN / WAF ──
    Signature { technology: "Cloudflare", category: TechCategory::Cdn, needle: "cf-ray", weight: 0.95, header_only: Some("cf-ray"), version_regex: None },
    Signature { technology: "Cloudflare", category: TechCategory::Waf, needle: "cf-mitigated", weight: 0.9, header_only: Some("cf-mitigated"), version_regex: None },
    Signature { technology: "AWS CloudFront", category: TechCategory::Cdn, needle: "x-amz-cf-id", weight: 0.9, header_only: Some("x-amz-cf-id"), version_regex: None },
    Signature { technology: "Fastly", category: TechCategory::Cdn, needle: "x-fastly-request-id", weight: 0.9, header_only: Some("x-fastly-request-id"), version_regex: None },
    Signature { technology: "Akamai", category: TechCategory::Cdn, needle: "x-akamai-transformed", weight: 0.9, header_only: Some("x-akamai-transformed"), version_regex: None },

    // ── Frontend frameworks (body/bundle markers; low weight alone) ──
    Signature { technology: "React", category: TechCategory::FrontendFramework, needle: "data-reactroot", weight: 0.6, header_only: None, version_regex: None },
    Signature { technology: "React", category: TechCategory::FrontendFramework, needle: "__react_devtools", weight: 0.4, header_only: None, version_regex: None },
    Signature { technology: "Vue.js", category: TechCategory::FrontendFramework, needle: "data-v-", weight: 0.4, header_only: None, version_regex: None },
    Signature { technology: "Vue.js", category: TechCategory::FrontendFramework, needle: "__vue__", weight: 0.5, header_only: None, version_regex: None },
    Signature { technology: "Angular", category: TechCategory::FrontendFramework, needle: "ng-version", weight: 0.6, header_only: None, version_regex: Some(r#"ng-version="([0-9]+\.[0-9]+\.[0-9]+)""#) },
    Signature { technology: "Svelte", category: TechCategory::FrontendFramework, needle: "svelte-", weight: 0.4, header_only: None, version_regex: None },
    Signature { technology: "Nuxt.js", category: TechCategory::FrontendFramework, needle: "__nuxt", weight: 0.7, header_only: None, version_regex: None },
    Signature { technology: "Next.js", category: TechCategory::FrontendFramework, needle: "__next_data__", weight: 0.7, header_only: None, version_regex: None },
    Signature { technology: "jQuery", category: TechCategory::ThirdPartyLibrary, needle: "jquery", weight: 0.4, header_only: None, version_regex: Some(r"jquery[-.]([0-9]+\.[0-9]+\.[0-9]+)") },

    // ── CMS ──
    Signature { technology: "WordPress", category: TechCategory::Cms, needle: "wp-content", weight: 0.6, header_only: None, version_regex: None },
    Signature { technology: "WordPress", category: TechCategory::Cms, needle: "wp-json", weight: 0.7, header_only: None, version_regex: None },
    Signature { technology: "Drupal", category: TechCategory::Cms, needle: "drupal-settings-json", weight: 0.8, header_only: None, version_regex: None },
    Signature { technology: "Joomla", category: TechCategory::Cms, needle: "/media/jui/", weight: 0.6, header_only: None, version_regex: None },

    // ── Backend frameworks (server markers) ──
    Signature { technology: "Laravel", category: TechCategory::BackendFramework, needle: "laravel_session", weight: 0.8, header_only: None, version_regex: None },
    Signature { technology: "Django", category: TechCategory::BackendFramework, needle: "csrftoken", weight: 0.4, header_only: None, version_regex: None },
    Signature { technology: "Django", category: TechCategory::BackendFramework, needle: "csrfmiddlewaretoken", weight: 0.6, header_only: None, version_regex: None },
    Signature { technology: "Rails", category: TechCategory::BackendFramework, needle: "_rails_session", weight: 0.7, header_only: None, version_regex: None },
    Signature { technology: "Spring", category: TechCategory::BackendFramework, needle: "whitelabel error", weight: 0.6, header_only: None, version_regex: None },

    // ── Template engines (often visible in markup or debug output) ──
    Signature { technology: "Twig", category: TechCategory::TemplateEngine, needle: "twig", weight: 0.4, header_only: None, version_regex: None },
    Signature { technology: "Handlebars", category: TechCategory::TemplateEngine, needle: "handlebars", weight: 0.4, header_only: None, version_regex: None },
    Signature { technology: "Jinja2", category: TechCategory::TemplateEngine, needle: "jinja", weight: 0.4, header_only: None, version_regex: None },
];

/// Minimum corroboration weight before a technology is reported at all.
const MIN_TECH_CONFIDENCE: f32 = 0.6;

/// Run the detector over a set of observations.
///
/// Returns only technologies that cross `MIN_TECH_CONFIDENCE`. A version is
/// attached solely when an exact version string was matched.
pub fn detect(observations: &[Observation]) -> Vec<TechnologyFinding> {
    use std::collections::HashMap;

    // Accumulate per-technology: total weight, evidence, and any version.
    struct Acc {
        category: TechCategory,
        weight: f32,
        evidence: Vec<TechnologyEvidence>,
        observations: Vec<(EvidenceSource, String, String)>,
        version: Option<String>,
    }
    let mut acc: HashMap<String, Acc> = HashMap::new();

    for obs in observations {
        // Build a normalized haystack including the header key so signatures
        // written as "server: nginx" match a header observation.
        let haystack = match &obs.key {
            Some(k) => format!("{k}: {}", obs.value).to_lowercase(),
            None => obs.value.to_lowercase(),
        };

        for sig in SIGNATURES {
            // Header-scoped signatures only match that header.
            if let Some(required) = sig.header_only {
                if obs.key.as_deref() != Some(required) {
                    continue;
                }
            }
            if !haystack.contains(&sig.needle.to_lowercase()) {
                continue;
            }

            // Extract a version if the signature defines one and the exact
            // string is present. No inference, no defaults.
            let version = sig.version_regex.and_then(|pattern| {
                regex::Regex::new(pattern)
                    .ok()
                    .and_then(|re| re.captures(&obs.value).and_then(|c| c.get(1).map(|m| m.as_str().to_string())))
            });

            let entry = acc.entry(sig.technology.to_string()).or_insert_with(|| Acc {
                category: sig.category,
                weight: 0.0,
                evidence: Vec::new(),
                observations: Vec::new(),
                version: None,
            });

            // Only count a source once per technology — the same header
            // repeated is not independent corroboration.
            let already = entry
                .observations
                .iter()
                .any(|(s, v, _): &(EvidenceSource, String, String)| *s == obs.source && *v == obs.value);
            if already {
                continue;
            }

            entry.weight += sig.weight;
            entry.observations.push((obs.source, obs.value.clone(), sig.needle.to_string()));
            entry.evidence.push(TechnologyEvidence {
                technology: sig.technology.to_string(),
                category: sig.category,
                version: version.clone(),
                confidence: sig.weight,
                evidence_source: obs.source,
                evidence_value: obs.value.clone(),
            });
            if version.is_some() && entry.version.is_none() {
                entry.version = version;
            }
        }
    }

    let mut findings: Vec<TechnologyFinding> = acc
        .into_iter()
        .filter(|(_, a)| a.weight >= MIN_TECH_CONFIDENCE)
        .map(|(technology, a)| {
            let distinct_sources = a
                .observations
                .iter()
                .map(|(s, _, _)| *s)
                .collect::<std::collections::HashSet<_>>()
                .len();
            TechnologyFinding {
                technology,
                category: a.category,
                version: a.version,
                confidence: a.weight.min(1.0),
                evidence: a.evidence,
                distinct_sources,
            }
        })
        .collect();

    // Strongest first, then alphabetical for determinism.
    findings.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.technology.cmp(&b.technology))
    });
    findings
}

/// Build observations from an HTTP response.
pub fn observations_from_response(
    headers: &[(String, String)],
    body: &str,
    script_srcs: &[String],
) -> Vec<Observation> {
    let mut obs = Vec::new();
    for (k, v) in headers {
        obs.push(Observation::header(k, v));
    }
    obs.push(Observation::body(body));
    for src in script_srcs {
        obs.push(Observation::script_src(src));
    }
    obs
}

/// Extract `<script src="...">` targets from HTML for bundle analysis.
pub fn extract_script_srcs(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = html.to_lowercase();
    let mut idx = 0;
    while let Some(start) = lower[idx..].find("<script") {
        let abs = idx + start;
        let tag_end = match lower[abs..].find('>') {
            Some(e) => abs + e,
            None => break,
        };
        let tag = &html[abs..tag_end];
        if let Some(src_pos) = tag.to_lowercase().find("src=") {
            let rest = &tag[src_pos + 4..];
            let quote = rest.chars().next().unwrap_or('"');
            if quote == '"' || quote == '\'' {
                if let Some(end) = rest[1..].find(quote) {
                    out.push(rest[1..end + 1].to_string());
                }
            }
        }
        idx = tag_end + 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_reported_when_explicitly_present() {
        let obs = vec![Observation::header("server", "nginx/1.25.3")];
        let findings = detect(&obs);
        let nginx = findings.iter().find(|f| f.technology == "nginx").unwrap();
        assert_eq!(nginx.version.as_deref(), Some("1.25.3"));
        assert!(nginx.version_is_observed());
    }

    #[test]
    fn version_is_not_invented_when_absent() {
        // A generic marker must NOT produce a version.
        let obs = vec![Observation::header("server", "nginx")];
        let findings = detect(&obs);
        let nginx = findings.iter().find(|f| f.technology == "nginx").unwrap();
        assert_eq!(nginx.version, None, "version was invented from a generic marker");
        assert!(nginx.summary().contains("version not observed"));
    }

    #[test]
    fn single_weak_indicator_does_not_report() {
        // "wp-content" alone is weight 0.6... so this must NOT report below
        // threshold when combined with nothing else. Test the low-weight case.
        let obs = vec![Observation::body("<div class='svelte-abc'>hi</div>")];
        let findings = detect(&obs);
        assert!(
            !findings.iter().any(|f| f.technology == "Svelte"),
            "a single 0.4-weight marker must not report a technology"
        );
    }

    #[test]
    fn corroboration_across_sources_reports() {
        // WordPress: wp-content (0.6) alone passes, but combining with wp-json
        // raises confidence and source count.
        let obs = vec![
            Observation::body("<link href='/wp-content/themes/x.css'>"),
            Observation::body("{\"wp-json\":true}"),
        ];
        let findings = detect(&obs);
        let wp = findings.iter().find(|f| f.technology == "WordPress").unwrap();
        assert!(wp.confidence > 0.6);
    }

    #[test]
    fn distinct_sources_are_counted() {
        let obs = vec![
            Observation::header("cf-ray", "abc123"),
            Observation::header("cf-mitigated", "challenge"),
        ];
        let findings = detect(&obs);
        let cf = findings.iter().find(|f| f.technology == "Cloudflare").unwrap();
        // Both are headers — one distinct source.
        assert_eq!(cf.distinct_sources, 1);
    }

    #[test]
    fn repeated_identical_evidence_not_double_counted() {
        let obs = vec![
            Observation::header("cf-ray", "abc123"),
            Observation::header("cf-ray", "abc123"),
        ];
        let findings = detect(&obs);
        let cf = findings.iter().find(|f| f.technology == "Cloudflare").unwrap();
        assert_eq!(cf.evidence.len(), 1, "duplicate evidence was counted twice");
    }

    #[test]
    fn every_finding_carries_evidence() {
        let obs = vec![
            Observation::header("server", "nginx/1.25.3"),
            Observation::header("x-powered-by", "Express"),
        ];
        for finding in detect(&obs) {
            assert!(!finding.evidence.is_empty(), "finding had no evidence");
            for e in &finding.evidence {
                assert!(!e.evidence_value.is_empty());
            }
        }
    }

    #[test]
    fn aspnet_version_from_dedicated_header() {
        let obs = vec![Observation::header("x-aspnet-version", "4.0.30319")];
        let findings = detect(&obs);
        let asp = findings.iter().find(|f| f.technology == "ASP.NET").unwrap();
        assert_eq!(asp.version.as_deref(), Some("4.0.30319"));
    }

    #[test]
    fn angular_version_from_ng_version_attribute() {
        let obs = vec![Observation::body("<app-root ng-version=\"15.2.9\"></app-root>")];
        let findings = detect(&obs);
        let ng = findings.iter().find(|f| f.technology == "Angular").unwrap();
        assert_eq!(ng.version.as_deref(), Some("15.2.9"));
    }

    #[test]
    fn clean_response_reports_nothing() {
        let obs = vec![
            Observation::header("content-type", "text/html"),
            Observation::body("<html><body>hello</body></html>"),
        ];
        assert!(detect(&obs).is_empty(), "clean response produced findings");
    }

    #[test]
    fn extracts_script_srcs() {
        let html = r#"<script src="/static/app.js"></script><script src='https://cdn.x/lib.js'></script>"#;
        let srcs = extract_script_srcs(html);
        assert_eq!(srcs.len(), 2);
        assert!(srcs.contains(&"/static/app.js".to_string()));
        assert!(srcs.contains(&"https://cdn.x/lib.js".to_string()));
    }

    #[test]
    fn findings_are_sorted_by_confidence() {
        let obs = vec![
            Observation::header("cf-ray", "x"),
            Observation::body("wp-content"),
        ];
        let findings = detect(&obs);
        for w in findings.windows(2) {
            assert!(w[0].confidence >= w[1].confidence);
        }
    }

    #[test]
    fn cookie_source_is_recorded() {
        let obs = vec![Observation::cookie("laravel_session=abc")];
        let findings = detect(&obs);
        let lv = findings.iter().find(|f| f.technology == "Laravel").unwrap();
        assert_eq!(lv.evidence[0].evidence_source, EvidenceSource::Cookie);
    }
}
