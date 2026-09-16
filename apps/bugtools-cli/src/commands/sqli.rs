//! `bugtools sqli` — adaptive assessment of SQLi candidates from a JSON file.

use anyhow::Result;
use serde::Deserialize;

use crate::parsing::{apply_identity_header, render_hypotheses, resolve_cookies, resolve_headers};

/// A candidate endpoint from the input file.
#[derive(Deserialize)]
pub struct SqliCandidate {
    pub url: String,
    pub method: String,
    pub parameter: String,
    pub location: String,
}

/// Options collected from the CLI flags.
#[derive(Clone)]
pub struct SqliOptions<'a> {
    pub cookies: &'a [String],
    pub cookie_file: Option<&'a str>,
    pub headers: &'a [String],
    pub bearer: Option<&'a str>,
    pub output: Option<&'a str>,
    pub format: &'a str,
    pub depth: &'a str,
    pub max_requests: u64,
    pub program: Option<&'a str>,
    pub handle: Option<&'a str>,
}

pub async fn run(input_path: &str, authorize: bool, opts: SqliOptions<'_>) -> Result<()> {
    // Program policy: apply stated scope and constraints when provided.
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
        println!("[*] policy: {}", p.summary());
        for note in &p.notes {
            println!("[*]   note: {note}");
        }
    }
    if !authorize {
        anyhow::bail!(
            "refusing to probe without --i-authorize.\n\
             This flag is your explicit confirmation that you are authorized to test every target in the input file."
        );
    }

    let cookie_pairs = resolve_cookies(opts.cookies, opts.cookie_file)?;
    let mut header_map = resolve_headers(opts.headers, opts.bearer)?;
    if let Some(handle) = opts.handle {
        apply_identity_header(&mut header_map, handle);
    }

    // Progress goes to stderr in JSON mode so stdout stays parseable.
    let json_mode = opts.format == "json";
    let progress = |msg: String| {
        if json_mode {
            eprintln!("{msg}");
        } else {
            println!("{msg}");
        }
    };
    if !cookie_pairs.is_empty() {
        progress(format!(
            "[*] session: {} cookie(s) — {}",
            cookie_pairs.len(),
            cookie_pairs
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !header_map.is_empty() {
        progress(format!(
            "[*] session: {} header(s) — {}",
            header_map.len(),
            header_map.keys().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    let _budget = bugtools_sql::scheduler::RequestBudget::new(opts.max_requests);
    progress(format!("[*] request budget: {}", opts.max_requests));

    let raw = std::fs::read_to_string(input_path)
        .map_err(|e| anyhow::anyhow!("cannot read {input_path}: {e}"))?;
    let candidates: Vec<SqliCandidate> =
        serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("invalid candidate JSON: {e}"))?;

    // A program policy refuses out-of-scope targets outright.
    let candidates: Vec<SqliCandidate> = if let Some(p) = &policy {
        let (kept, rejected): (Vec<_>, Vec<_>) = candidates.into_iter().partition(|c| {
            url::Url::parse(&c.url)
                .ok()
                .and_then(|u| u.host_str().map(String::from))
                .map(|h| p.allows_host(&h))
                .unwrap_or(false)
        });
        for c in &rejected {
            eprintln!("[!] REFUSED (out of program scope): {}", c.url);
        }
        if !rejected.is_empty() {
            eprintln!(
                "[*] {} of {} candidate(s) dropped as out of scope",
                rejected.len(),
                rejected.len() + kept.len()
            );
        }
        kept
    } else {
        candidates
    };

    if candidates.is_empty() {
        println!("No in-scope candidates in {input_path}.");
        return Ok(());
    }

    // Authorize every distinct host named in the file.
    let scope = std::sync::Arc::new(bugtools_scope::ScopeEngine::new());
    {
        use bugtools_core::scope::{ScopeRule, ScopeRuleType};
        let mut hosts = std::collections::BTreeSet::new();
        for c in &candidates {
            if let Some(h) = url::Url::parse(&c.url)
                .ok()
                .and_then(|u| u.host_str().map(String::from))
            {
                hosts.insert(h);
            }
        }
        for host in &hosts {
            scope.add_rule(ScopeRule::new(
                uuid::Uuid::nil(),
                ScopeRuleType::IncludeDomain,
                host.clone(),
            ));
        }
        progress(format!(
            "[*] authorized {} host(s): {}",
            hosts.len(),
            hosts.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }

    let mut assessments: Vec<bugtools_sql::AdaptiveResult> = Vec::new();
    for candidate in &candidates {
        let parsed = match url::Url::parse(&candidate.url) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("[!] skipping {} — invalid URL: {e}", candidate.url);
                continue;
            }
        };
        let param_value = parsed
            .query_pairs()
            .find(|(k, _)| *k == candidate.parameter)
            .map(|(_, v)| v.to_string())
            .unwrap_or_default();

        progress(format!(
            "[*] {} {} param={} ({}) depth={}",
            candidate.method, candidate.url, candidate.parameter, candidate.location, opts.depth
        ));

        // The scan runs authenticated exactly as configured.
        let mut headers = header_map.clone();
        if !cookie_pairs.is_empty() {
            let cookie_header = cookie_pairs
                .iter()
                .map(|(n, v)| format!("{n}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            headers.insert("Cookie".to_string(), cookie_header);
        }

        let base = bugtools_core::http::HttpRequest {
            id: uuid::Uuid::new_v4(),
            job_id: None,
            url: candidate.url.clone(),
            method: candidate.method.clone(),
            headers,
            body: None,
            timestamp: chrono::Utc::now(),
        };

        // Adaptive, evidence-driven run (no blind probe execution).
        let adaptive = bugtools_sql::run_adaptive(
            &base,
            &candidate.parameter,
            &param_value,
            scope.clone(),
            bugtools_sql::AdaptiveConfig {
                baseline_samples: 3,
                max_experiments: 8,
                delay_seconds: 5,
                dbms_hint: None,
                application_hint: None,
            },
        )
        .await;

        match adaptive {
            Ok(a) => {
                if !json_mode {
                    print_assessment(&a);
                }
                assessments.push(a);
            }
            Err(e) => eprintln!("[!] adaptive run failed for {}: {e}", candidate.url),
        }
    }

    if json_mode {
        // A single clean document on stdout.
        println!("{}", serde_json::to_string_pretty(&assessments)?);
    }
    if let Some(path) = opts.output {
        std::fs::write(path, serde_json::to_string_pretty(&assessments)?)?;
        if !json_mode {
            println!("\n[+] wrote {} assessments to {path}", assessments.len());
        }
    } else if !json_mode {
        println!("\n[+] {} candidate(s) assessed", assessments.len());
    }

    Ok(())
}

/// Render one adaptive assessment in the text format.
fn print_assessment(a: &bugtools_sql::AdaptiveResult) {
    println!("    baseline:   {}", a.baseline_summary);
    println!("    context:    {}", render_hypotheses(&a.context_hypotheses));
    println!(
        "    position:   {}",
        render_hypotheses(&a.query_position_hypotheses)
    );
    println!("    dbms:       {}", render_hypotheses(&a.dbms_hypotheses));
    println!(
        "    coverage:   {}   confidence {:.2}",
        a.coverage, a.confidence
    );
    println!(
        "    tests:      {} distinct experiment(s), {} duplicate(s) avoided",
        a.experiments_executed, a.duplicates_avoided
    );
    println!(
        "    reliability: {} test(s) reproduced under repetition, {} discarded as flaky",
        a.repetitions_verified, a.flaky_tests
    );
    if !a.signals.is_empty() {
        let sig: Vec<String> = a
            .signals
            .iter()
            .map(|(k, s)| format!("{k}({s:.2})"))
            .collect();
        println!("    signals:    {}", sig.join(", "));
    }
    if !a.tested_families.is_empty() {
        println!("    families:");
        for f in &a.tested_families {
            println!(
                "      {:<22} tested {} executed {} equivalent {} strength {:.2}",
                f.family, f.tested, f.executed, f.equivalent_result, f.evidence_strength
            );
        }
    }
    if !a.confirmed {
        println!();
        println!("    Diagnostic result (no confirmation):");
        for line in &a.diagnostic_report {
            println!("      - {line}");
        }
    }
    if !a.remaining_uncertainty.is_empty() {
        println!("    Remaining uncertainty:");
        for line in &a.remaining_uncertainty {
            println!("      - {line}");
        }
    }
    if !a.limitations.is_empty() {
        println!("    Limitations:");
        for line in &a.limitations {
            println!("      - {line}");
        }
    }
}
