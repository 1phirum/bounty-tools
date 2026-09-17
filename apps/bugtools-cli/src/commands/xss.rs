//! `bugtools xss` — XSS reflection, context and taint analysis.
//!
//! One benign marker per parameter: the marker is submitted in the location
//! the parameter already occupies (query, or form body for a POST), the
//! response is analyzed for its reflection and the page's inline scripts are
//! traced for a source-to-sink flow. The marker contains no markup, so the
//! probe cannot itself constitute an attack, and no destructive payload is
//! ever sent.

use anyhow::{anyhow, Result};
use bugtools_core::scope::{ScopeRule, ScopeRuleType};
use bugtools_http::{HttpClientConfig, SafeHttpClient};
use bugtools_scope::ScopeEngine;
use std::sync::Arc;
use uuid::Uuid;

use crate::commands::http::fetch;
use crate::parsing::{apply_identity_header, resolve_cookies, resolve_headers};

/// Default UA, unless the caller supplies their own via `-H`.
const USER_AGENT: &str = "Mozilla/5.0 (compatible; BugTools/0.1)";

/// Options collected from the CLI flags.
pub struct XssOptions<'a> {
    pub params: &'a [String],
    pub method: &'a str,
    pub data: Option<&'a str>,
    pub cookies: &'a [String],
    pub headers: &'a [String],
    pub bearer: Option<&'a str>,
    pub json: bool,
    pub program: Option<&'a str>,
    pub handle: Option<&'a str>,
}

/// One probed parameter and the assessment of the response it produced.
struct ProbeResult {
    parameter: String,
    location: &'static str,
    assessment: bugtools_xss::XssAssessment,
}

pub async fn run(url: &str, authorize: bool, opts: XssOptions<'_>) -> Result<()> {
    if !authorize {
        anyhow::bail!(
            "refusing to probe without --i-authorize.\n\
             This flag is your explicit confirmation that you are authorized to test this target."
        );
    }
    let parsed = url::Url::parse(url).map_err(|e| anyhow!("invalid URL: {e}"))?;
    if parsed.host_str().is_none() {
        anyhow::bail!("URL has no host");
    }
    let method = opts.method.to_ascii_uppercase();
    if method != "GET" && method != "POST" {
        anyhow::bail!("unsupported method {method:?}: use GET or POST");
    }

    // Program policy: apply stated scope and constraints before any request.
    let policy = opts.program.and_then(|path| {
        match bugtools_sql::policy::ProgramPolicy::from_file(path) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("[!] could not load policy '{path}': {e}");
                None
            }
        }
    });
    if let Some(p) = &policy {
        let line = format!("[*] policy: {}", p.summary());
        if opts.json {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
        for note in &p.notes {
            eprintln!("[*]   note: {note}");
        }
        if !p.allows_host(parsed.host_str().unwrap_or("")) {
            anyhow::bail!(
                "target host '{}' is out of scope for the {} program",
                parsed.host_str().unwrap_or(""),
                p.name
            );
        }
    }

    let cookie_pairs = resolve_cookies(opts.cookies, None)?;
    let mut header_map = resolve_headers(opts.headers, opts.bearer)?;
    if let Some(h) = opts.handle {
        apply_identity_header(&mut header_map, h);
    }
    if !cookie_pairs.is_empty() {
        let cookie_header = cookie_pairs
            .iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        header_map.insert("Cookie".to_string(), cookie_header);
    }
    header_map
        .entry("User-Agent".to_string())
        .or_insert_with(|| USER_AGENT.to_string());

    // Every request goes through the shared safe client.
    let scope = Arc::new(ScopeEngine::new());
    scope.add_rule(ScopeRule::new(
        Uuid::nil(),
        ScopeRuleType::IncludeDomain,
        parsed.host_str().unwrap_or("").to_string(),
    ));
    let http = SafeHttpClient::new(
        scope,
        HttpClientConfig {
            timeout: std::time::Duration::from_secs(20),
            ..Default::default()
        },
    );

    // The parameters to probe and the request shape they live in.
    let targets = probe_targets(&parsed, &method, opts.data, opts.params);
    if targets.is_empty() {
        anyhow::bail!(
            "nothing to probe: a POST has no form parameters — pass them with --data, \
             or name one with --param"
        );
    }

    // Baseline request: the page as the caller configured it, used for the
    // technology/strategy context. A failure is reported, not fatal — the
    // per-parameter probes below are the analysis.
    let baseline_body = match fetch(
        &http,
        &parsed.to_string(),
        &method,
        opts.data,
        &header_map,
    )
    .await
    {
        Ok(f) => f.body,
        Err(e) => {
            eprintln!("[!] baseline request failed: {e}");
            String::new()
        }
    };
    let script_srcs = bugtools_xss::technology::extract_script_srcs(&baseline_body);
    let observations = bugtools_xss::observations_from_response(
        &[],
        &baseline_body,
        &script_srcs,
    );
    let findings = bugtools_xss::detect(&observations);
    let strategy = bugtools_xss::build_strategy(&findings);

    // One probe per parameter, each analyzed against its own response.
    let mut results: Vec<ProbeResult> = Vec::new();
    for target in &targets {
        let probe = marker();
        let (probe_url, probe_body_sent) =
            target.request_with(&parsed, &method, opts.data, &probe);
        let progress = format!(
            "[*] probing {} parameter '{}'",
            target.location, target.name
        );
        if opts.json {
            eprintln!("{progress}");
        } else {
            println!("{progress}");
        }

        let response = match fetch(
            &http,
            &probe_url,
            &method,
            probe_body_sent.as_deref(),
            &header_map,
        )
        .await
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[!] probe of '{}' failed: {e}", target.name);
                continue;
            }
        };

        let script_sources = bugtools_xss::technology::extract_inline_scripts(&response.body);
        let request = bugtools_xss::AnalyzeRequest {
            url: probe_url.clone(),
            parameter: target.name.clone(),
            submitted: probe.clone(),
            body: response.body,
            headers: response.headers,
            script_sources,
        };
        results.push(ProbeResult {
            parameter: target.name.clone(),
            location: target.location,
            assessment: bugtools_xss::analyze(&request),
        });
    }

    if results.is_empty() {
        anyhow::bail!("no probe produced an assessment");
    }

    // JSON mode: one clean document on stdout, progress already on stderr.
    if opts.json {
        let assessments: Vec<_> = results
            .iter()
            .map(|r| {
                let a = &r.assessment;
                serde_json::json!({
                    "parameter": r.parameter,
                    "location": r.location,
                    "endpoint": a.endpoint,
                    "stage": a.exploitability_stage.label(),
                    "confirmed": a.confirmed,
                    "confidence": a.confidence.level.label(),
                    "transitions": a.transitions.iter()
                        .map(|t| format!("{} -> {}", t.from.label(), t.to.label()))
                        .collect::<Vec<_>>(),
                    "reflection": a.reflection,
                    "uncertainty": a.remaining_uncertainty,
                    "limitations": a.limitations,
                    "finding": a.to_finding(Uuid::nil()),
                })
            })
            .collect();
        let payload = serde_json::json!({
            "url": url,
            "method": method,
            "strategy": {
                "rendering_model": strategy.rendering_model,
                "driven_by": strategy.driven_by,
                "items": strategy.items,
            },
            "assessments": assessments,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    println!("[*] {method} {url} — probing {} parameter(s)", results.len());
    for r in &results {
        print_assessment(r);
    }

    if strategy.is_generic() {
        println!();
        println!("STRATEGY: generic (no technology-specific guidance)");
    } else {
        println!();
        println!("XSS STRATEGY ({} item(s)):", strategy.items.len());
        for item in &strategy.items {
            println!("  [{:.2}] {}", item.priority, item.focus);
            println!("         {}", item.rationale);
        }
    }
    Ok(())
}

/// Render one parameter's assessment.
fn print_assessment(r: &ProbeResult) {
    let a = &r.assessment;
    println!();
    println!(
        "XSS ANALYSIS  param={} ({}) — {}",
        r.parameter,
        r.location,
        a.exploitability_stage.label()
    );
    if let Some(refl) = &a.reflection {
        println!("  reflection: offset {} ({})", refl.response_offset, refl.encoding);
        if let Some(h) = &refl.html_context {
            println!(
                "    html context: {} in <{:?}> attr={:?}",
                h.node_type.label(),
                h.element_name,
                h.attribute_name
            );
        }
        if let Some(j) = &refl.js_context {
            println!("    js context: {}", j.node_type.label());
        }
    } else {
        println!("  reflection: none (marker did not appear)");
    }
    if !a.remaining_uncertainty.is_empty() {
        println!("  uncertainty:");
        for u in &a.remaining_uncertainty {
            println!("    - {u}");
        }
    }
    println!("  confidence: {}", a.confidence.level.label());
    for t in &a.transitions {
        println!("    {} -> {}", t.from.label(), t.to.label());
    }
    if !a.limitations.is_empty() {
        println!("  limitations:");
        for l in &a.limitations {
            println!("    - {l}");
        }
    }
    if let Some(f) = a.to_finding(Uuid::nil()) {
        println!("  FINDING  {:?} / {:?}", f.severity, f.confidence);
        println!("    {}", f.title);
    }
}

/// A random, harmless marker. It carries no markup: the probe observes
/// reflection and flow, and never attacks.
fn marker() -> String {
    format!("btprobe{}", &Uuid::new_v4().simple().to_string()[..8])
}

/// One parameter to probe and where it lives.
struct ProbeTarget {
    name: String,
    location: &'static str,
}

impl ProbeTarget {
    /// The request that carries this parameter's marker. Returns the URL and,
    /// for a form body, the body to send.
    fn request_with(
        &self,
        base: &url::Url,
        method: &str,
        data: Option<&str>,
        marker: &str,
    ) -> (String, Option<String>) {
        let mut u = base.clone();
        if method == "GET" {
            let mut replaced = false;
            let pairs: Vec<(String, String)> = u
                .query_pairs()
                .map(|(k, v)| {
                    if k == self.name {
                        replaced = true;
                        (k.into_owned(), marker.to_string())
                    } else {
                        (k.into_owned(), v.into_owned())
                    }
                })
                .collect();
            u.query_pairs_mut().clear().extend_pairs(pairs);
            if !replaced {
                u.query_pairs_mut().append_pair(&self.name, marker);
            }
            (u.to_string(), None)
        } else {
            // POST: the query is untouched; the marker replaces the form value.
            let body = replace_form_value(data.unwrap_or(""), &self.name, marker);
            (u.to_string(), Some(body))
        }
    }
}

/// Determine which parameters to probe: those named with `--param`, or all
/// that the request already carries. A GET request with neither probes one
/// appended `bugtools_probe` parameter, so a plain URL is still useful.
fn probe_targets(
    parsed: &url::Url,
    method: &str,
    data: Option<&str>,
    params: &[String],
) -> Vec<ProbeTarget> {
    let location: &'static str = if method == "GET" { "query" } else { "form" };
    if !params.is_empty() {
        return params
            .iter()
            .map(|p| ProbeTarget { name: p.clone(), location })
            .collect();
    }
    let present: Vec<String> = if method == "GET" {
        parsed.query_pairs().map(|(k, _)| k.into_owned()).collect()
    } else {
        form_keys(data.unwrap_or(""))
    };
    if present.is_empty() {
        if method == "GET" {
            return vec![ProbeTarget { name: "bugtools_probe".into(), location: "query" }];
        }
        return Vec::new();
    }
    present.into_iter().map(|name| ProbeTarget { name, location }).collect()
}

/// The keys of an `application/x-www-form-urlencoded` body.
fn form_keys(body: &str) -> Vec<String> {
    body.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').map(|(k, _)| k).unwrap_or(p).to_string())
        .collect()
}

/// An `application/x-www-form-urlencoded` body with one parameter's value
/// replaced by the marker. The parameter is appended when the body does not
/// already carry it; every other pair keeps its original text.
fn replace_form_value(body: &str, name: &str, marker: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut replaced = false;
    for pair in body.split('&').filter(|p| !p.is_empty()) {
        let key = pair.split_once('=').map(|(k, _)| k).unwrap_or(pair);
        if key == name {
            out.push(format!("{name}={marker}"));
            replaced = true;
        } else {
            out.push(pair.to_string());
        }
    }
    if !replaced {
        out.push(format!("{name}={marker}"));
    }
    out.join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_has_no_markup() {
        let m = marker();
        assert!(m.starts_with("btprobe"));
        assert!(!m.contains('<') && !m.contains('>') && !m.contains('"'));
    }

    #[test]
    fn get_targets_are_the_query_parameters() {
        let u = url::Url::parse("https://t/p?a=1&b=2").unwrap();
        let names: Vec<String> = probe_targets(&u, "GET", None, &[])
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn get_without_parameters_probes_a_default() {
        let u = url::Url::parse("https://t/p").unwrap();
        let targets = probe_targets(&u, "GET", None, &[]);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "bugtools_probe");
    }

    #[test]
    fn named_parameters_win() {
        let u = url::Url::parse("https://t/p?a=1&b=2").unwrap();
        let targets = probe_targets(&u, "GET", None, &["b".into()]);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "b");
    }

    #[test]
    fn post_targets_come_from_the_form() {
        let u = url::Url::parse("https://t/p").unwrap();
        let names: Vec<String> = probe_targets(&u, "POST", Some("user=x&msg=y"), &[])
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert_eq!(names, vec!["user", "msg"]);
    }

    #[test]
    fn post_without_a_form_probes_nothing() {
        let u = url::Url::parse("https://t/p").unwrap();
        assert!(probe_targets(&u, "POST", Some(""), &[]).is_empty());
    }

    #[test]
    fn get_request_replaces_the_value_in_place() {
        let u = url::Url::parse("https://t/p?a=1&b=2").unwrap();
        let target = ProbeTarget { name: "a".into(), location: "query" };
        let (url, body) = target.request_with(&u, "GET", None, "MARK");
        assert!(body.is_none());
        assert!(url.contains("a=MARK"), "{url}");
        assert!(url.contains("b=2"), "{url}");
    }

    #[test]
    fn get_request_appends_a_missing_parameter() {
        let u = url::Url::parse("https://t/p?a=1").unwrap();
        let target = ProbeTarget { name: "q".into(), location: "query" };
        let (url, _) = target.request_with(&u, "GET", None, "MARK");
        assert!(url.contains("q=MARK"), "{url}");
        assert!(url.contains("a=1"), "{url}");
    }

    #[test]
    fn form_value_is_replaced_in_place() {
        assert_eq!(replace_form_value("user=x&msg=y", "msg", "MARK"), "user=x&msg=MARK");
    }

    #[test]
    fn form_value_is_appended_when_absent() {
        assert_eq!(replace_form_value("user=x", "msg", "MARK"), "user=x&msg=MARK");
    }

    #[test]
    fn post_request_replaces_the_form_value() {
        let u = url::Url::parse("https://t/p?keep=1").unwrap();
        let target = ProbeTarget { name: "msg".into(), location: "form" };
        let (url, body) = target.request_with(&u, "POST", Some("msg=y"), "MARK");
        assert_eq!(body.as_deref(), Some("msg=MARK"));
        assert!(url.contains("keep=1"), "the query must be untouched: {url}");
    }

    #[test]
    fn form_keys_split_on_ampersand() {
        assert_eq!(form_keys("a=1&b=2"), vec!["a", "b"]);
        assert!(form_keys("").is_empty());
    }
}
