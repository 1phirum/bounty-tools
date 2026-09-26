//! `bugtools recon` — DNS / TLS / HTTP reconnaissance via the embedded engine.
//!
//! Resolves the target's DNS records, inspects its TLS certificate (surfacing
//! in-scope SAN hostnames as newly discovered subdomains), and probes HTTP(S).
//! The work runs in the out-of-process Go engine that is baked into this binary
//! and extracted on demand, so `bugtools` ships as one self-contained file.

use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::Value;

use crate::embed;
use crate::engine_host::{self, Finding};

/// Parsed options for a recon run.
pub struct ReconOptions<'a> {
    /// Emit JSON instead of grouped, human-readable lines.
    pub json: bool,
    /// Suppress the live progress indicator (human mode only).
    pub quiet: bool,
    /// Explicit engine binary path, overriding the embedded copy.
    pub engine: Option<&'a str>,
    /// Skip TLS certificate inspection.
    pub no_tls: bool,
    /// Skip HTTP(S) probing.
    pub no_http: bool,
    /// Per-connection dial/handshake timeout, seconds.
    pub timeout: u64,
    /// Overall wall-clock budget for the whole job, seconds.
    pub overall_timeout: u64,
}

pub async fn run(target: &str, opts: ReconOptions<'_>) -> Result<()> {
    // Prefer an explicitly configured engine; otherwise extract the embedded one.
    let binary = match engine_host::locate_explicit("dns", opts.engine)? {
        Some(p) => p,
        None => embed::extract_dns_engine().context("stage embedded dns engine")?,
    };

    let mut config: HashMap<String, Value> = HashMap::new();
    config.insert("enable_tls".into(), Value::Bool(!opts.no_tls));
    config.insert("enable_http".into(), Value::Bool(!opts.no_http));
    config.insert("timeout_secs".into(), Value::from(opts.timeout));
    config.insert("overall_timeout_secs".into(), Value::from(opts.overall_timeout));

    // Progress goes to stderr so it never contaminates `--json` stdout. On a
    // TTY it is a single spinner line rewritten in place; piped (or with
    // `--quiet`), it degrades to one line per step so logs stay clean.
    let show_progress = !opts.json && !opts.quiet;
    let interactive = show_progress && std::io::stderr().is_terminal();
    let spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let mut frame = 0usize;
    let on_progress = |pct: f64, step: &str| {
        if !show_progress {
            return;
        }
        if interactive {
            let s = spinner[frame % spinner.len()];
            frame += 1;
            eprint!("\r\x1b[2K{s} {pct:3.0}%  {step}");
            let _ = std::io::stderr().flush();
        } else {
            eprintln!("[{pct:3.0}%] {step}");
        }
    };

    let started = Instant::now();
    let findings = engine_host::run_job(&binary, "dns", target, config, on_progress)
        .await
        .with_context(|| format!("recon engine failed for {target}"))?;
    let elapsed = started.elapsed();

    if interactive {
        // Wipe the spinner line before the results land.
        eprint!("\r\x1b[2K");
        let _ = std::io::stderr().flush();
    }

    if opts.json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
        return Ok(());
    }

    print_human(target, &findings, elapsed);
    Ok(())
}

/// TTY-gated ANSI styling. When stdout is not a terminal (piped/redirected) or
/// `NO_COLOR` is set, every method is the identity function, so redirected
/// output stays plain and grep-friendly.
struct Style {
    on: bool,
}

impl Style {
    fn detect() -> Self {
        let on = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
        Self { on }
    }
    fn wrap(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    fn cyan(&self, s: &str) -> String {
        self.wrap("36", s)
    }
    fn green(&self, s: &str) -> String {
        self.wrap("32", s)
    }
    fn yellow(&self, s: &str) -> String {
        self.wrap("33", s)
    }
    fn red(&self, s: &str) -> String {
        self.wrap("31", s)
    }
    /// A bracketed, colour-coded severity tag, or empty for info/unset.
    fn severity_tag(&self, sev: &str) -> String {
        match sev {
            "critical" | "high" => format!("  {}", self.red(&format!("[{}]", sev.to_uppercase()))),
            "medium" => format!("  {}", self.yellow(&format!("[{}]", sev.to_uppercase()))),
            "low" => format!("  {}", self.wrap("34", &format!("[{}]", sev.to_uppercase()))),
            _ => String::new(),
        }
    }
    /// Colour an HTTP status by class: 2xx green, 3xx cyan, 4xx/5xx red.
    fn http_status(&self, status: &str) -> String {
        match status.chars().next() {
            Some('2') => self.green(status),
            Some('3') => self.cyan(status),
            Some('4') | Some('5') => self.red(status),
            _ => status.to_string(),
        }
    }
}

/// Bucket a record type into an ordered, friendly section.
/// Returns `(order, label)`; the order groups related records so the report
/// reads addresses → DNS → TLS → subdomains → HTTP rather than raw alpha sort.
fn bucket(record_type: &str) -> (u8, &'static str) {
    match record_type {
        "A" | "AAAA" | "PTR" => (0, "Addresses"),
        "CNAME" => (1, "Aliases (CNAME)"),
        "MX" => (2, "Mail (MX)"),
        "NS" => (3, "Nameservers (NS)"),
        "TXT" | "SOA" | "SRV" => (4, "DNS records"),
        "TLS" => (5, "TLS certificate"),
        "SAN" => (6, "Discovered subdomains"),
        "HTTP" => (7, "HTTP"),
        _ => (8, "Other"),
    }
}

fn print_human(target: &str, findings: &[Finding], elapsed: Duration) {
    let st = Style::detect();

    if findings.is_empty() {
        println!(
            "{} {}   {}",
            st.bold("▸ recon"),
            st.cyan(target),
            st.dim("— no findings")
        );
        return;
    }

    // Headline: target, timing, total.
    println!(
        "{} {}   {}",
        st.bold("▸ recon"),
        st.cyan(target),
        st.dim(&format!("{:.1}s · {} findings", elapsed.as_secs_f64(), findings.len()))
    );

    // At-a-glance highlights line: resolved IPs, subdomains, TLS expiry, HTTP.
    print_highlights(&st, findings);
    println!();

    // Ordered sections with per-section counts.
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for f in findings {
        *counts.entry(bucket(&f.record_type).1).or_insert(0) += 1;
    }

    let mut idx: Vec<usize> = (0..findings.len()).collect();
    idx.sort_by_key(|&i| (bucket(&findings[i].record_type).0, i));

    let mut current = "";
    for &i in &idx {
        let f = &findings[i];
        let (_, label) = bucket(&f.record_type);
        if label != current {
            current = label;
            println!(
                "{}",
                st.dim(&format!("── {label} ({}) ──", counts.get(label).copied().unwrap_or(0)))
            );
        }
        print_finding(&st, f);
    }
}

/// Render the compact summary line under the headline.
fn print_highlights(st: &Style, findings: &[Finding]) {
    let mut parts: Vec<String> = Vec::new();

    let ips: Vec<&str> = findings
        .iter()
        .filter(|f| f.record_type == "A" || f.record_type == "AAAA")
        .map(|f| f.value.as_str())
        .collect();
    if !ips.is_empty() {
        parts.push(st.cyan(&format!("{} IP{}", ips.len(), plural(ips.len()))));
    }

    let subs = findings.iter().filter(|f| f.record_type == "SAN").count();
    if subs > 0 {
        parts.push(st.green(&format!("+{subs} subdomain{}", plural(subs))));
    }

    if let Some(tls) = findings.iter().find(|f| f.record_type == "TLS") {
        if tls.title.contains("failed") {
            parts.push(st.red("TLS failed"));
        } else if let Some(days) = tls.metadata.get("days_until_expiry") {
            let tag = format!("TLS {days}d");
            parts.push(match tls.severity.as_str() {
                "high" => st.red(&tag),
                "medium" => st.yellow(&tag),
                _ => st.dim(&tag),
            });
        }
    }

    if let Some(http) = findings.iter().find(|f| f.record_type == "HTTP") {
        let status = http.metadata.get("status").cloned().unwrap_or_else(|| http.value.clone());
        parts.push(format!("HTTP {}", st.http_status(&status)));
    }

    if !parts.is_empty() {
        println!("  {}", parts.join(st.dim(" · ").as_str()));
    }
}

/// Render one finding line (plus its description, indented and dimmed).
fn print_finding(st: &Style, f: &Finding) {
    // HTTP's title already carries method+status+page title; the bare status
    // `value` is redundant there, so prefer the title.
    let head = match f.record_type.as_str() {
        "HTTP" => f.title.clone(),
        _ if !f.value.is_empty() => f.value.clone(),
        _ => f.title.clone(),
    };
    let head = match f.record_type.as_str() {
        "SAN" => st.green(&head),
        "A" | "AAAA" => st.cyan(&head),
        _ => head,
    };
    println!("  {head}{}", st.severity_tag(&f.severity));
    if !f.description.is_empty() {
        println!("      {}", st.dim(&f.description));
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

