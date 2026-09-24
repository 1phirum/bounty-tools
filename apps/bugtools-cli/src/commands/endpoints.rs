//! `bugtools endpoints` — endpoint discovery, offline or live.
//!
//! Offline: read a saved page/bundle and run the extractor engine over it.
//! Live (`--i-authorize`): fetch the URL through the shared [`SafeHttpClient`]
//! — scope-checked, rate-limited, budget-capped — then dynamically follow the
//! page's same-host scripts up to a depth and extract from those too.
//!
//! The `--profile` flag applies a realistic, static browser header set as
//! *defaults* so an authorized scan presents as an ordinary client. That is
//! ordinary client hygiene, not evasion: it does not spoof origin IPs, rotate
//! headers per request, or attempt to defeat WAF/bot-management challenges.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use bugtools_core::scope::{ScopeRule, ScopeRuleType};
use bugtools_endpoints::{Endpoint, EndpointEngine, EndpointKind, EndpointReport, ParamLocation};
use bugtools_http::profile::RequestProfile;
use bugtools_http::{HttpClientConfig, SafeHttpClient};
use bugtools_scope::ScopeEngine;
use uuid::Uuid;

use crate::commands::http::fetch;
use crate::parsing::{apply_identity_header, resolve_cookies, resolve_headers};

/// Everything the endpoints command needs beyond its positional input.
pub struct EndpointsOptions<'a> {
    pub i_authorize: bool,
    pub base: Option<&'a str>,
    pub profile: &'a str,
    pub depth: u32,
    pub include_external: bool,
    pub include_assets: bool,
    pub kind: Option<&'a str>,
    pub cookies: &'a [String],
    pub headers: &'a [String],
    pub bearer: Option<&'a str>,
    pub rate_limit: f64,
    pub max_requests: u64,
    pub program: Option<&'a str>,
    pub handle: Option<&'a str>,
    pub json: bool,
}

pub async fn run(input: &str, opts: EndpointsOptions<'_>) -> Result<()> {
    let report = if opts.i_authorize {
        live(input, &opts).await?
    } else {
        offline(input, &opts)?
    };
    print_report(&report, &opts, input);
    Ok(())
}

/// Offline: read `input` (file or `-` for stdin) and analyze it.
fn offline(input: &str, opts: &EndpointsOptions) -> Result<EndpointReport> {
    let content = if input == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        std::fs::read_to_string(input)
            .map_err(|e| anyhow!("cannot read '{input}': {e}"))?
    };

    let mut engine = EndpointEngine::default_set()
        .include_external(opts.include_external)
        .include_assets(opts.include_assets);
    if let Some(base) = opts.base {
        let url = url::Url::parse(base).map_err(|e| anyhow!("invalid --base '{base}': {e}"))?;
        engine = engine.with_base(url);
    }
    Ok(engine.analyze(&content))
}

/// Live: fetch the URL and its same-host scripts, then analyze the collected
/// content resolved against the page URL.
async fn live(input: &str, opts: &EndpointsOptions<'_>) -> Result<EndpointReport> {
    let parsed = url::Url::parse(input)
        .map_err(|e| anyhow!("invalid URL '{input}': {e} (omit --i-authorize to read a file)"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("URL has no host"))?
        .to_string();

    // Program policy gates the host before any request is sent.
    if let Some(path) = opts.program {
        match bugtools_sql::policy::ProgramPolicy::from_file(path) {
            Ok(p) => {
                eprintln!("[*] policy: {}", p.summary());
                if !p.allows_host(&host) {
                    anyhow::bail!("target host '{host}' is out of scope for the {} program", p.name);
                }
            }
            Err(e) => eprintln!("[!] could not load policy '{path}': {e}"),
        }
    }

    // Build headers: a realistic browser profile as defaults, then the
    // caller's own -H/-b/-c/--handle on top (they win over the profile).
    let mut header_map = profile_headers(opts.profile)?;
    for (k, v) in resolve_headers(opts.headers, opts.bearer)? {
        header_map.insert(k, v);
    }
    let cookie_pairs = resolve_cookies(opts.cookies, None)?;
    if !cookie_pairs.is_empty() {
        let cookie = cookie_pairs
            .iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        header_map.insert("Cookie".to_string(), cookie);
    }
    if let Some(h) = opts.handle {
        apply_identity_header(&mut header_map, h);
    }

    // Only the target host is in scope; the safe client blocks everything else.
    let scope = Arc::new(ScopeEngine::new());
    scope.add_rule(ScopeRule::new(Uuid::nil(), ScopeRuleType::IncludeDomain, host.clone()));
    let http = SafeHttpClient::new(
        scope,
        HttpClientConfig {
            rate_limit_rps: opts.rate_limit,
            max_budget: opts.max_requests,
            timeout: std::time::Duration::from_secs(20),
            ..Default::default()
        },
    );
    eprintln!("[*] authorized host: {host}");

    // Fetch the page, then follow same-host scripts breadth-first to --depth.
    let mut buffer = String::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut to_fetch = vec![parsed.to_string()];
    let mut level = 0u32;
    while !to_fetch.is_empty() {
        let mut next: Vec<String> = Vec::new();
        for u in std::mem::take(&mut to_fetch) {
            if !visited.insert(u.clone()) {
                continue;
            }
            match fetch(&http, &u, "GET", None, &header_map).await {
                Ok(f) => {
                    eprintln!("[*] fetched {u} (HTTP {}, {} bytes)", f.status, f.body.len());
                    for src in bugtools_xss::technology::extract_script_srcs(&f.body) {
                        if let Ok(abs) = url::Url::parse(&u).and_then(|b| b.join(&src)) {
                            if abs.host_str() == Some(host.as_str())
                                && !visited.contains(abs.as_str())
                            {
                                next.push(abs.to_string());
                            }
                        }
                    }
                    buffer.push_str(&f.body);
                    buffer.push('\n');
                }
                Err(e) => eprintln!("[!] skip {u}: {e}"),
            }
        }
        if level >= opts.depth {
            break;
        }
        to_fetch = next;
        level += 1;
    }

    let engine = EndpointEngine::default_set()
        .with_base(parsed)
        .include_external(opts.include_external)
        .include_assets(opts.include_assets);
    Ok(engine.analyze(&buffer))
}

/// Realistic browser header defaults for the named profile.
fn profile_headers(profile: &str) -> Result<HashMap<String, String>> {
    let p = match profile.to_ascii_lowercase().as_str() {
        "chrome" => Some(RequestProfile::PROFILE_STABLE_CHROME),
        "safari" | "ios" => Some(RequestProfile::PROFILE_STABLE_SAFARI_IOS),
        "api" => Some(RequestProfile::PROFILE_STABLE_API),
        "none" | "off" => None,
        other => return Err(anyhow!("unknown --profile '{other}' (chrome|safari|api|none)")),
    };
    Ok(p.map(|p| p.generate_headers()).unwrap_or_default())
}

/// Map a `--kind` filter string to its [`EndpointKind`].
fn parse_kind(kind: &str) -> Result<EndpointKind> {
    match kind.to_ascii_lowercase().as_str() {
        "page" => Ok(EndpointKind::Page),
        "api" | "apiroute" | "api_route" => Ok(EndpointKind::ApiRoute),
        "asset" | "static" | "staticasset" => Ok(EndpointKind::StaticAsset),
        "form" | "formaction" => Ok(EndpointKind::FormAction),
        "websocket" | "ws" => Ok(EndpointKind::WebSocket),
        "unknown" => Ok(EndpointKind::Unknown),
        other => Err(anyhow!(
            "unknown --kind '{other}' (page|api|asset|form|websocket|unknown)"
        )),
    }
}

/// Render the report to stdout, honoring `--kind` and `--json`.
fn print_report(report: &EndpointReport, opts: &EndpointsOptions, input: &str) {
    // Apply the optional kind filter without mutating the report.
    let filter = opts.kind.map(parse_kind);
    let filter = match filter {
        Some(Ok(k)) => Some(k),
        Some(Err(e)) => {
            eprintln!("[!] {e}");
            return;
        }
        None => None,
    };
    let selected: Vec<&Endpoint> = report
        .endpoints
        .iter()
        .filter(|e| filter.map_or(true, |k| e.kind == k))
        .collect();

    if opts.json {
        let value = serde_json::json!({
            "input": input,
            "stats": {
                "per_extractor": report.stats.per_extractor,
                "total_raw": report.stats.total_raw,
                "total_after_merge": report.stats.total_after_merge,
                "external_skipped": report.stats.external_skipped,
            },
            "endpoints": selected,
        });
        match serde_json::to_string_pretty(&value) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("[!] could not serialize report: {e}"),
        }
        return;
    }

    if selected.is_empty() {
        println!("No endpoints found.");
        print_stats(report);
        return;
    }

    println!("{:<7} {:>4}  {:<6} {}", "KIND", "CONF", "METHOD", "ENDPOINT");
    for e in &selected {
        let method = if e.method.is_known() {
            e.method.as_str()
        } else {
            "-"
        };
        println!(
            "{:<7} {:>3}%  {:<6} {}",
            e.kind.label(),
            e.confidence,
            method,
            e.display
        );
        if !e.params.is_empty() {
            let params = e
                .params
                .iter()
                .map(|p| format!("{}({})", p.name, param_loc(&p.location)))
                .collect::<Vec<_>>()
                .join(", ");
            println!("          params: {params}");
        }
    }
    print_stats(report);
}

fn print_stats(report: &EndpointReport) {
    let s = &report.stats;
    eprintln!(
        "[*] {} endpoints from {} raw references ({} external skipped)",
        s.total_after_merge, s.total_raw, s.external_skipped
    );
    for (name, count) in &s.per_extractor {
        eprintln!("    - {name}: {count}");
    }
}

fn param_loc(loc: &ParamLocation) -> &'static str {
    match loc {
        ParamLocation::Query => "query",
        ParamLocation::Form => "form",
        ParamLocation::Path => "path",
        ParamLocation::Body => "body",
    }
}
