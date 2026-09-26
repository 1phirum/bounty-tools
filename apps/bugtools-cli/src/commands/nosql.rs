//! `bugtools nosql` — offline NoSQL datastore fingerprinting and live,
//! scope-checked, read-only operator-injection detection.

use anyhow::Result;

use crate::cli::NosqlCommands;
use crate::parsing::{apply_identity_header, resolve_cookies, resolve_headers};

/// Options for the live `analyze` probe path.
struct AnalyzeOptions<'a> {
    param: Option<&'a str>,
    cookies: &'a [String],
    cookie_file: Option<&'a str>,
    headers: &'a [String],
    bearer: Option<&'a str>,
    handle: Option<&'a str>,
    extract_field: Option<String>,
    where_delay_ms: u64,
    max_experiments: usize,
    json: bool,
}

pub async fn run(command: NosqlCommands) -> Result<()> {
    match command {
        NosqlCommands::Detect { text } => detect(&text).await,
        NosqlCommands::Analyze {
            url,
            param,
            i_authorize,
            cookies,
            cookie_file,
            headers,
            bearer,
            handle,
            extract_field,
            where_delay_ms,
            max_experiments,
            json,
        } => {
            let opts = AnalyzeOptions {
                param: param.as_deref(),
                cookies: &cookies,
                cookie_file: cookie_file.as_deref(),
                headers: &headers,
                bearer: bearer.as_deref(),
                handle: handle.as_deref(),
                extract_field,
                where_delay_ms,
                max_experiments,
                json,
            };
            analyze(&url, i_authorize, opts).await
        }
    }
}

/// Fingerprint a NoSQL datastore from pasted error text. Sends nothing.
async fn detect(text: &str) -> Result<()> {
    let input = if text == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        text.to_string()
    };

    let result = bugtools_nosql::analyze_error_body(crate::parsing::strip_bom(&input));
    match result.detected {
        Some(family) => {
            println!("Datastore:  {}", family.display_name());
            println!("Confidence: {}%", result.confidence);
            println!("Verdict:    {:?}", result.verdict);
            if !result.signals.is_empty() {
                println!("\nMatched signals:");
                for signal in &result.signals {
                    println!(
                        "  [{:>3}] {} — {} ({:?})",
                        signal.weight,
                        signal.family.display_name(),
                        signal.label,
                        signal.category
                    );
                }
            }
            println!(
                "\nNote: no signature match does NOT mean the datastore is absent — many drivers \
                 swallow errors or return a generic 500."
            );
        }
        None => {
            println!("Datastore:  undetermined");
            println!("Confidence: {}%", result.confidence);
            println!(
                "No NoSQL-specific signature matched. Absence of a signature is not evidence of \
                 absence."
            );
        }
    }
    Ok(())
}

/// Live scope-checked NoSQL operator-injection detection against a URL.
async fn analyze(url: &str, authorize: bool, opts: AnalyzeOptions<'_>) -> Result<()> {
    if !authorize {
        anyhow::bail!(
            "refusing to send probes without --i-authorize.\n\
             This flag is your explicit confirmation that you are authorized to test this target."
        );
    }
    let parsed = url::Url::parse(url)?;
    if parsed.host_str().is_none() {
        anyhow::bail!("URL has no host");
    }

    // Only the URL's host is added to scope; every other host stays blocked.
    let scope = std::sync::Arc::new(bugtools_scope::ScopeEngine::new());
    if let Some(host) = parsed.host_str() {
        use bugtools_core::scope::{ScopeRule, ScopeRuleType};
        scope.add_rule(ScopeRule::new(
            uuid::Uuid::nil(),
            ScopeRuleType::IncludeDomain,
            host.to_string(),
        ));
    }

    // Resolve the request identity: headers + bearer, cookies, and an optional
    // researcher handle folded into X-Bug-Bounty.
    let mut header_map = resolve_headers(opts.headers, opts.bearer)?;
    let cookies = resolve_cookies(opts.cookies, opts.cookie_file)?;
    if !cookies.is_empty() {
        let cookie_value = cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        header_map.insert("Cookie".to_string(), cookie_value);
    }
    if let Some(handle) = opts.handle {
        apply_identity_header(&mut header_map, handle);
    }

    // Default parameter: the first query key.
    let param_name = match opts.param {
        Some(p) => p.to_string(),
        None => match parsed.query_pairs().next() {
            Some((k, _)) => k.to_string(),
            None => anyhow::bail!("URL has no query parameter to probe"),
        },
    };

    if !opts.json {
        println!("[*] authorized host: {}", parsed.host_str().unwrap_or(""));
        if !header_map.is_empty() {
            let mut names: Vec<&str> = header_map.keys().map(String::as_str).collect();
            names.sort_unstable();
            println!("[*] request headers: {}", names.join(", "));
        }
        println!("[*] probing parameter: {param_name}");
        if opts.extract_field.is_some() {
            println!("[*] read-only $regex extraction armed (only fires after a differential)");
        }
    }

    use bugtools_core::http::HttpRequest;
    use chrono::Utc;
    let base = HttpRequest {
        id: uuid::Uuid::new_v4(),
        job_id: None,
        url: url.to_string(),
        method: "GET".into(),
        headers: header_map,
        body: None,
        timestamp: Utc::now(),
    };

    let config = bugtools_nosql::NoSqlConfig {
        where_delay_ms: opts.where_delay_ms,
        max_experiments: opts.max_experiments,
        extract_field: opts.extract_field,
        ..Default::default()
    };

    let result = bugtools_nosql::run_nosql(&base, &param_name, scope, config)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    if opts.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }

    println!("\nTarget:     {}", result.target);
    println!("Parameter:  {}", result.parameter);
    println!("Baseline:   {}", result.baseline_summary);
    println!("Coverage:   {}", result.coverage);
    println!("Confidence: {:.0}%", result.confidence * 100.0);
    println!(
        "Experiments: {} run, {} deduplicated, {} repetition-verified, {} flaky",
        result.experiments_executed,
        result.duplicates_avoided,
        result.repetitions_verified,
        result.flaky_tests
    );

    if !result.datastore_hypotheses.is_empty() {
        println!("\nDatastore hypotheses:");
        for (name, weight) in &result.datastore_hypotheses {
            println!("  {name} (weight {weight})");
        }
    }
    if let Some(prefix) = &result.extracted_prefix {
        println!("\nRead-only $regex extraction recovered prefix: {prefix:?}");
    }
    if !result.signals.is_empty() {
        println!("\nSignals:");
        for s in &result.signals {
            println!("  {s}");
        }
    }
    if !result.diagnostic_report.is_empty() {
        println!("\nDiagnosis:");
        for line in &result.diagnostic_report {
            println!("  - {line}");
        }
    }
    if !result.remaining_uncertainty.is_empty() {
        println!("\nRemaining uncertainty:");
        for line in &result.remaining_uncertainty {
            println!("  - {line}");
        }
    }
    if !result.limitations.is_empty() {
        println!("\nLimitations:");
        for line in &result.limitations {
            println!("  - {line}");
        }
    }
    Ok(())
}
