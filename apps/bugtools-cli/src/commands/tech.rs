//! `bugtools tech` — technology fingerprint + XSS analysis pipeline.

use anyhow::Result;
use bugtools_core::scope::{ScopeRule, ScopeRuleType};
use bugtools_http::{HttpClientConfig, SafeHttpClient};
use bugtools_scope::ScopeEngine;
use std::sync::Arc;
use uuid::Uuid;

use crate::commands::http::fetch;
use crate::parsing::{apply_identity_header, resolve_cookies, resolve_headers};

/// Default UA, unless the caller supplies their own via `-H`.
const USER_AGENT: &str = "Mozilla/5.0 (compatible; BugTools/0.1)";

pub async fn run(
    url: &str,
    authorize: bool,
    cookies: &[String],
    header_flags: &[String],
    bearer: Option<&str>,
    json: bool,
    program: Option<&str>,
    handle: Option<&str>,
) -> Result<()> {
    if !authorize {
        anyhow::bail!(
            "refusing to request without --i-authorize.\n\
             This flag is your explicit confirmation that you are authorized to test this target."
        );
    }
    let parsed = url::Url::parse(url).map_err(|e| anyhow::anyhow!("invalid URL: {e}"))?;
    if parsed.host_str().is_none() {
        anyhow::bail!("URL has no host");
    }

    // Resolve the program policy before touching the target.
    let policy = program.and_then(|path| {
        match bugtools_sql::policy::ProgramPolicy::from_file(path) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("[!] could not load policy '{path}': {e}");
                None
            }
        }
    });
    if let Some(p) = &policy {
        if json {
            eprintln!("[*] policy: {}", p.summary());
        } else {
            println!("[*] policy: {}", p.summary());
        }
        for note in &p.notes {
            if json {
                eprintln!("[*]   note: {note}");
            } else {
                println!("[*]   note: {note}");
            }
        }
        let host = parsed.host_str().unwrap_or("").to_string();
        if !p.allows_host(&host) {
            anyhow::bail!(
                "target host '{host}' is out of scope for the {} program",
                p.name
            );
        }
    }

    let cookie_pairs = resolve_cookies(cookies, None)?;
    let mut header_map = resolve_headers(header_flags, bearer)?;
    if let Some(h) = handle {
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

    // Default UA unless the caller overrode it.
    header_map
        .entry("User-Agent".to_string())
        .or_insert_with(|| USER_AGENT.to_string());

    // Every request goes through the shared safe client: scope-checked,
    // rate-limited, budget-capped and size-bounded. No ad-hoc transport.
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

    let fetched = fetch(&http, url, "GET", None, &header_map).await?;
    let status = fetched.status;
    let mut header_vec = fetched.headers;
    header_vec.sort();
    let body = fetched.body;

    let script_srcs = bugtools_xss::technology::extract_script_srcs(&body);
    let observations =
        bugtools_xss::observations_from_response(&header_vec, &body, &script_srcs);
    let findings = bugtools_xss::detect(&observations);
    let strategy = bugtools_xss::build_strategy(&findings);

    // Full XSS analysis: submit a benign marker as a query parameter in ONE
    // additional request, then analyze the reflection of that marker. The
    // marker contains no markup, so this cannot itself constitute an attack.
    let probe = format!("btprobe{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let probe_url = {
        let mut u = parsed.clone();
        u.query_pairs_mut().append_pair("bugtools_probe", &probe);
        u.to_string()
    };
    let probe_body = match fetch(&http, &probe_url, "GET", None, &header_map).await {
        Ok(f) => f.body,
        Err(e) => {
            eprintln!("[!] probe request failed: {e}");
            body.clone()
        }
    };
    // Taint analysis runs on INLINE scripts — that is where DOM flows live.
    let script_sources = bugtools_xss::technology::extract_inline_scripts(&probe_body);
    let request = bugtools_xss::AnalyzeRequest {
        url: url.to_string(),
        parameter: "bugtools_probe".into(),
        submitted: probe.clone(),
        body: probe_body,
        headers: header_vec.clone(),
        script_sources,
    };
    let assessment = bugtools_xss::analyze(&request);

    // The assessment as a pipeline event (the shape the runtime's XSS stage
    // will emit) and, when execution is confirmed, a persistable finding.
    let xss_event = bugtools_output::XssAssessmentEvent {
        target: url.to_string(),
        endpoint: assessment.endpoint.clone(),
        parameter: assessment.parameter.clone(),
        stage: assessment.exploitability_stage.label().to_string(),
        confirmed: assessment.confirmed,
        confidence: assessment.confidence.level.label().to_string(),
        limitations: assessment.limitations.clone(),
    };
    // A finding exists only when execution was confirmed in a browser; the
    // mapping enforces that, so this stays None until a verifier is wired.
    let finding = assessment.to_finding(Uuid::nil());

    // JSON mode: all analysis is complete. Emit the single document and stop;
    // no human output may precede it or stdout is not valid JSON.
    if json {
        let payload = serde_json::json!({
            "url": url,
            "technologies": findings,
            "strategy": {
                "rendering_model": strategy.rendering_model,
                "driven_by": strategy.driven_by,
                "items": strategy.items,
            },
            "xss": xss_event,
            "finding": finding,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    println!("[*] fingerprinting {url} (HTTP {status})");
    println!();
    if findings.is_empty() {
        println!("No technology crossed the reporting threshold.");
        println!("note: this is absence of evidence, not evidence of absence —");
        println!("      most markers require multiple corroborating signals.");
    } else {
        println!("TECHNOLOGIES ({}):", findings.len());
        for f in &findings {
            println!(
                "  {:<24} {:<22} {}",
                f.technology,
                format!("{:?}", f.category),
                match &f.version {
                    Some(v) => format!("v{v} (observed)"),
                    None => "version not observed".to_string(),
                }
            );
            for e in &f.evidence {
                println!(
                    "      · {} = {:?}",
                    e.evidence_source.label(),
                    e.evidence_value
                );
            }
        }
    }

    println!();
    println!("RENDERING MODEL: {:?}", strategy.rendering_model);

    println!();
    println!(
        "XSS ANALYSIS (marker probe, {}):",
        assessment.exploitability_stage.label()
    );
    if let Some(r) = &assessment.reflection {
        println!("  reflection: offset {} ({})", r.response_offset, r.encoding);
        if let Some(h) = &r.html_context {
            println!(
                "    html context: {} in <{:?}> attr={:?}",
                h.node_type.label(),
                h.element_name,
                h.attribute_name
            );
        }
        if let Some(j) = &r.js_context {
            println!("    js context: {}", j.node_type.label());
        }
    } else {
        println!("  reflection: none (marker did not appear)");
    }
    if !assessment.remaining_uncertainty.is_empty() {
        println!("  uncertainty:");
        for u in &assessment.remaining_uncertainty {
            println!("    - {u}");
        }
    }
    println!("  confidence: {}", assessment.confidence.level.label());
    for t in &assessment.transitions {
        println!("    {} -> {}", t.from.label(), t.to.label());
    }
    if !assessment.limitations.is_empty() {
        println!("  limitations:");
        for l in &assessment.limitations {
            println!("    - {l}");
        }
    }
    if let Some(f) = &finding {
        println!();
        println!("FINDING  {:?} / {:?}", f.severity, f.confidence);
        println!("  {}", f.title);
        println!("  module: {}  technique: {}", f.module, f.technique);
        if let Some(notes) = &f.notes {
            println!("  {notes}");
        }
    }

    if strategy.is_generic() {
        println!("STRATEGY: generic (no technology-specific guidance)");
    } else {
        println!("XSS STRATEGY ({} item(s)):", strategy.items.len());
        for item in &strategy.items {
            println!("  [{:.2}] {}", item.priority, item.focus);
            println!("         {}", item.rationale);
        }
    }
    Ok(())
}
