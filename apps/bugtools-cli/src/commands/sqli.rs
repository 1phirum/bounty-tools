//! `bugtools sqli` — adaptive assessment of SQLi candidates from a JSON file.

use anyhow::Result;
use serde::Deserialize;

use bugtools_sql::payload::{tampers, EscalationTier};
use bugtools_sql::{DbmsProbeEngine, SweepSummary};

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
    /// Known backend engine, so the engine-specific catalogue is used.
    pub dbms: Option<&'a str>,
    /// Named tamper chain applied to every payload.
    pub tamper: Option<&'a str>,
    /// Technique labels to restrict the sweep to (empty = tier default).
    pub techniques: &'a [String],
    /// Recover a read-only proof set once a positive result is reached
    /// (default on; `--no-prove` clears it).
    pub prove: bool,
    /// Additionally dump a table's rows read-only (opt-in `--dump`).
    pub dump: bool,
    /// The table `--dump` targets.
    pub dump_table: Option<&'a str>,
    /// Row cap for `--dump`.
    pub max_rows: usize,
    /// Enable the out-of-band confirmation stage.
    pub oob: bool,
    /// OOB collector backend: `interactsh` or `byoc`.
    pub oob_provider: &'a str,
    /// BYOC callback domain the operator controls.
    pub oob_domain: Option<&'a str>,
    /// BYOC poll source — an HTTP(S) URL or a local file path.
    pub oob_poll: Option<&'a str>,
    /// interactsh server host (self-hosted or public).
    pub oob_interactsh_server: Option<&'a str>,
    /// interactsh authorization token, when the server requires one.
    pub oob_token: Option<&'a str>,
    /// Seconds to wait after sending OOB payloads before polling.
    pub oob_wait: u64,
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
    let candidates: Vec<SqliCandidate> = serde_json::from_str(crate::parsing::strip_bom(&raw))
        .map_err(|e| anyhow::anyhow!("invalid candidate JSON: {e}"))?;

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

    // ── Out-of-band collector (opt-in) ──────────────────────────────────────
    // Registered once and shared across every candidate: one collector serves
    // the whole run. The provider is polled with its own plain client (it is
    // operator-owned, deliberately off-target), while OOB payloads to the target
    // still go through the scoped, rate-limited safe client. OOB induces the
    // target database to make an outbound DNS/HTTP lookup to the collector — so
    // it is gated behind --oob and --i-authorize and prints a one-time ROE note.
    let oob_run = if opts.oob {
        use std::sync::Arc;
        use tokio::sync::Mutex;
        let provider: Arc<Mutex<dyn bugtools_sql::OobProvider>> = match opts
            .oob_provider
            .to_ascii_lowercase()
            .as_str()
        {
            "byoc" => {
                let domain = opts.oob_domain.ok_or_else(|| {
                    anyhow::anyhow!("--oob-provider byoc requires --oob-domain <DOMAIN>")
                })?;
                let poll_raw = opts.oob_poll.ok_or_else(|| {
                    anyhow::anyhow!("--oob-provider byoc requires --oob-poll <URL|FILE>")
                })?;
                let source = if poll_raw.starts_with("http://") || poll_raw.starts_with("https://")
                {
                    bugtools_sql::PollSource::Url(poll_raw.to_string())
                } else {
                    bugtools_sql::PollSource::File(std::path::PathBuf::from(poll_raw))
                };
                Arc::new(Mutex::new(bugtools_sql::ByocProvider::new(domain, source)))
            }
            "interactsh" => Arc::new(Mutex::new(
                bugtools_sql::InteractshProvider::new(
                    opts.oob_interactsh_server.map(|s| s.to_string()),
                    opts.oob_token.map(|s| s.to_string()),
                )
                .map_err(|e| anyhow::anyhow!("interactsh setup failed: {e}"))?,
            )),
            other => {
                anyhow::bail!("unknown --oob-provider '{other}' (expected 'interactsh' or 'byoc')")
            }
        };
        let callback_domain = provider
            .lock()
            .await
            .register()
            .await
            .map_err(|e| anyhow::anyhow!("OOB collector registration failed: {e}"))?;
        eprintln!(
            "[!] OOB enabled: the target database will be induced to make outbound DNS/HTTP \
             lookups to your collector at '{callback_domain}'. This is more intrusive than an \
             in-band read (it originates traffic from the DB host) but remains read-only — no \
             data or schema is modified. Ensure this is within your authorization and the \
             program's rules of engagement."
        );
        progress(format!(
            "[*] OOB collector ({}) registered; callback domain: {callback_domain} (waiting {}s per candidate before polling)",
            opts.oob_provider.to_ascii_lowercase(),
            opts.oob_wait,
        ));
        Some(bugtools_sql::OobRun {
            callback_domain,
            provider,
            wait_secs: opts.oob_wait,
        })
    } else {
        None
    };

    // Depth selects the escalation tier, and the tier selects both the sweep
    // breadth and the adaptive budget. This is the port that mattered: `depth`
    // used to be printed and ignored while the run stayed capped at 8
    // experiments over two families, so the batch scanner tested a small
    // fraction of what the single-URL analyze path tested.
    let tier = match opts.depth.to_ascii_lowercase().as_str() {
        "recon" => EscalationTier::Recon,
        "confirm" => EscalationTier::Confirm,
        "explore" => EscalationTier::Explore,
        other => anyhow::bail!("unknown depth '{other}' (expected recon, confirm or explore)"),
    };
    // (baseline samples, adaptive experiment cap, nominal delay seconds)
    let (baseline_samples, adaptive_cap, delay_seconds) = match tier {
        EscalationTier::Recon => (3usize, 24usize, 5u32),
        EscalationTier::Confirm => (4usize, 64usize, 5u32),
        EscalationTier::Explore => (5usize, 180usize, 5u32),
    };

    let chain = tampers::resolve_chain(opts.tamper.unwrap_or(""))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let technique_filter: Vec<String> = opts.techniques.to_vec();
    let hinted_dbms = opts.dbms.and_then(crate::parsing::parse_dbms_arg);

    // The sweep is the expensive stage, so its size is derived from the
    // remaining request allowance rather than being fixed: a large input file
    // must not turn a deep scan into an unbounded run.
    let available = bugtools_sql::generators::catalog_selected(tier, &technique_filter, &chain).len();
    let per_candidate = (opts.max_requests / (candidates.len() as u64).max(1)).max(8) as usize;
    let sweep_cap = per_candidate.min(available);
    progress(format!(
        "[*] depth {} → tier {}: {} of {} catalogue payload(s) per candidate",
        opts.depth,
        tier.label(),
        sweep_cap,
        available
    ));
    progress(format!(
        "[*] tampers: {}{}",
        chain.summary(),
        if chain.changes_semantics() {
            " (semantics-changing: results require a differential)"
        } else {
            ""
        }
    ));
    if !technique_filter.is_empty() {
        progress(format!("[*] techniques: {}", technique_filter.join(", ")));
    }

    let mut assessments: Vec<bugtools_sql::AdaptiveResult> = Vec::new();
    // Build the dump spec once, and print the rules-of-engagement / PII warning
    // a single time before the run — bulk extraction is opt-in and dangerous to
    // a program's rules of engagement, so the operator sees the caveat up front.
    let dump_spec = if opts.dump {
        if opts.dump_table.is_none() {
            eprintln!(
                "[!] --dump requires --dump-table <TABLE>; no table named, so no rows will be dumped"
            );
        }
        eprintln!(
            "[!] --dump enabled (read-only SELECT, capped at {} row(s)). Bulk data extraction \
             can breach a program's rules of engagement and expose PII — most programs want \
             proof-of-access, not mass exfiltration. Only the named table is read; use the \
             smallest row cap that proves impact.",
            opts.max_rows
        );
        Some(bugtools_sql::DumpSpec {
            table: opts.dump_table.map(|t| t.to_string()),
            max_rows: opts.max_rows,
        })
    } else {
        None
    };
    // One engine, reused for every candidate: it owns the HTTP client, so
    // connection reuse and the response fingerprinter stay warm across the run.
    let engine = DbmsProbeEngine::new(scope.clone());

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

        // ── Stage 1: the wide catalogue sweep ────────────────────────────────
        // Exactly the engine `analyze` runs (`DbmsProbeEngine::sweep`), with the
        // payload set gated by depth, optionally filtered by technique, and
        // optionally tampered. This is what closes the gap between the two live
        // paths: the batch scanner no longer tests a two-family stub.
        let sweep_payloads: Vec<_> = {
            let mut c = bugtools_sql::generators::catalog_selected(tier, &technique_filter, &chain);
            c.truncate(sweep_cap);
            c
        };
        let mut summary = SweepSummary {
            payloads_available: available,
            tamper_chain: chain.summary(),
            technique_filter: technique_filter.clone(),
            ..Default::default()
        };
        let mut sweep_dbms: Option<bugtools_sql::DbmsFamily> = None;
        match engine
            .sweep(&base, &candidate.parameter, sweep_payloads)
            .await
        {
            Ok(results) => {
                use std::collections::{BTreeMap, HashMap};
                let mut counts: BTreeMap<String, usize> = BTreeMap::new();
                let mut dbms_votes: HashMap<bugtools_sql::DbmsFamily, usize> = HashMap::new();
                for r in results
                    .iter()
                    .filter(|r| r.probe_type != bugtools_sql::ProbeType::Baseline)
                {
                    *counts
                        .entry(bugtools_sql::generators::technique_label(r.probe_type).to_string())
                        .or_default() += 1;
                    if !r.dialects_confirmed.is_empty() {
                        summary.with_signal += 1;
                    }
                    if let Some(d) = r.detection.detected_dbms {
                        *dbms_votes.entry(d).or_default() += 1;
                    }
                }
                summary.payloads_attempted = results.len().saturating_sub(1);
                summary.by_technique = counts.into_iter().collect();
                let best = dbms_votes.into_iter().max_by_key(|(_, n)| *n).map(|(d, _)| d);
                summary.detected_dbms = best.map(|d| d.label().to_string());
                sweep_dbms = best;
            }
            Err(e) => progress(format!("[!] sweep failed for {}: {e}", candidate.url)),
        }

        // ── Stage 2: evidence-gated adaptive escalation ──────────────────────
        // Now that the sweep has (usually) named the engine, the adaptive phase
        // can compose that engine's own primitives — the catalogue vectors —
        // instead of only the portable forms. A `--dbms` hint wins over the
        // sweep's inference.
        let adaptive = bugtools_sql::run_adaptive(
            &base,
            &candidate.parameter,
            &param_value,
            scope.clone(),
            bugtools_sql::AdaptiveConfig {
                baseline_samples,
                max_experiments: adaptive_cap,
                delay_seconds,
                dbms_hint: hinted_dbms.or(sweep_dbms),
                application_hint: None,
                extract: opts.prove,
                dump: dump_spec.clone(),
                techniques: technique_filter.clone(),
                oob: oob_run.clone(),
            },
        )
        .await;

        match adaptive {
            Ok(mut a) => {
                a.sweep = Some(summary);
                if !json_mode {
                    print_sweep(&a.sweep, tier);
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

/// Render the catalogue sweep summary.
///
/// This is the evidence that the batch path ran the deep engine rather than a
/// shallow stub: how many payloads of how many there were, per technique, under
/// which tamper chain, and what the sweep's error text revealed.
fn print_sweep(sweep: &Option<bugtools_sql::SweepSummary>, tier: EscalationTier) {
    let Some(s) = sweep else {
        return;
    };
    println!(
        "    sweep:      {} of {} catalogue payload(s) at tier {} — {} with a signal",
        s.payloads_attempted, s.payloads_available, tier.label(), s.with_signal
    );
    if !s.by_technique.is_empty() {
        let dist: Vec<String> = s
            .by_technique
            .iter()
            .map(|(k, n)| format!("{k} {n}"))
            .collect();
        println!("                {}", dist.join(", "));
    }
    println!("    tampers:    {}", s.tamper_chain);
    if let Some(d) = &s.detected_dbms {
        println!("    sweep dbms: {d}");
    }
    if s.payloads_attempted < s.payloads_available {
        println!(
            "                ({} payload(s) skipped by the request budget or depth gate)",
            s.payloads_available - s.payloads_attempted
        );
    }
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
    // Recovered values are the proof of impact — the difference between an
    // "informative" theory finding and a demonstrated read. Schema/note rows
    // (channel schema/none) are shown too so an empty or partial recovery is
    // reported honestly rather than hidden.
    if !a.extracted.is_empty() {
        println!("    Extracted (read-only proof of impact):");
        for fact in &a.extracted {
            if matches!(fact.channel.as_str(), "none" | "schema") {
                println!("      {:<18} {}", fact.label, fact.value);
            } else {
                println!(
                    "      {:<18} {}   [{}, {} request(s)]",
                    fact.label, fact.value, fact.channel, fact.requests
                );
            }
        }
    }
    // Out-of-band confirmation: a planted token that came back through the
    // operator's collector is dispositive proof of a blind injection. Only
    // correlated, in-window tokens appear here — stray traffic is never listed.
    if a.oob_attempted {
        if a.oob_correlations.is_empty() {
            println!(
                "    OOB:        attempted — no planted token was observed at the collector \
                 (absence of a callback is not proof of absence of injection)"
            );
        } else {
            println!(
                "    OOB:        CONFIRMED — {} correlated callback(s) carrying a planted token:",
                a.oob_correlations.len()
            );
            for c in &a.oob_correlations {
                println!(
                    "      {:<5} from {}   token {}   (+{} confidence)",
                    format!("{:?}", c.interaction_type),
                    c.source,
                    c.token,
                    c.confidence_delta
                );
            }
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
