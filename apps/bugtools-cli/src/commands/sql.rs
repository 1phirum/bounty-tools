//! `bugtools sql` — offline DBMS detection and the clause reference.

use anyhow::Result;
use bugtools_sql::DbmsFamily;

use crate::cli::SqlCommands;
use crate::parsing::{apply_identity_header, parse_dbms_arg, resolve_cookies, resolve_headers};

/// Options for the live `analyze` probe path.
struct AnalyzeOptions<'a> {
    param: Option<&'a str>,
    cookies: &'a [String],
    cookie_file: Option<&'a str>,
    headers: &'a [String],
    bearer: Option<&'a str>,
    handle: Option<&'a str>,
    json: bool,
}

pub async fn run(command: SqlCommands) -> Result<()> {
    match command {
        SqlCommands::Detect { text } => detect(&text).await,
        SqlCommands::Clauses { dbms } => clauses(dbms.as_deref()),
        SqlCommands::Analyze {
            url,
            param,
            i_authorize,
            cookies,
            cookie_file,
            headers,
            bearer,
            handle,
            json,
        } => {
            let opts = AnalyzeOptions {
                param: param.as_deref(),
                cookies: &cookies,
                cookie_file: cookie_file.as_deref(),
                headers: &headers,
                bearer: bearer.as_deref(),
                handle: handle.as_deref(),
                json,
            };
            analyze(&url, i_authorize, opts).await
        }
    }
}

/// Identify a DBMS from pasted error text. Sends nothing.
async fn detect(text: &str) -> Result<()> {
    let input = if text == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        text.to_string()
    };

    let result = bugtools_sql::detection::analyze_error_body(crate::parsing::strip_bom(&input));
    match result.detected_dbms {
        Some(dbms) => {
            println!("DBMS:       {}", dbms.display_name());
            println!("Confidence: {}%", result.confidence);
            println!("Verdict:    {:?}", result.verdict);
            if !result.signals.is_empty() {
                println!("\nMatched signals:");
                for signal in &result.signals {
                    println!(
                        "  [{:>3}] {} — {} ({:?})",
                        signal.weight, signal.dbms.label(), signal.label, signal.category
                    );
                }
            }
            println!(
                "\nNote: no signature match does NOT mean the DBMS is absent — only that no \
                 DBMS-specific error text was present."
            );
        }
        None => {
            println!("DBMS:       undetermined");
            println!("Confidence: {}%", result.confidence);
            println!(
                "No DBMS-specific signature matched. Absence of a signature is not evidence of \
                 absence."
            );
        }
    }
    Ok(())
}

/// Print the clause/dialect reference.
fn clauses(dbms: Option<&str>) -> Result<()> {
    let family: Option<DbmsFamily> = dbms.map(|name| {
        parse_dbms_arg(name)
            .ok_or_else(|| anyhow::anyhow!("unknown DBMS '{name}'"))
            .unwrap()
    });

    let maps = bugtools_sql::clause_map::clause_map();
    let relevant: Vec<_> = maps
        .iter()
        .filter(|m| {
            family.map(|f| m.variants.iter().any(|v| v.accepted_by.contains(&f)))
                .unwrap_or(true)
        })
        .collect();

    for map in relevant {
        println!("{:?}", map.clause);
        for variant in &map.variants {
            let accepted: Vec<String> = variant
                .accepted_by
                .iter()
                .map(|d| d.label().to_string())
                .collect();
            println!("    {}  [{}]", variant.syntax, accepted.join(", "));
        }
    }
    Ok(())
}

/// Live scope-checked DBMS detection against a parameterized URL.
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
    // researcher handle folded into X-Bug-Bounty. These ride on every probe so
    // program-compliance headers actually reach the target.
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

    if !opts.json {
        println!("[*] authorized host: {}", parsed.host_str().unwrap_or(""));
        if !header_map.is_empty() {
            let mut names: Vec<&str> = header_map.keys().map(String::as_str).collect();
            names.sort_unstable();
            println!("[*] request headers: {}", names.join(", "));
        }
    }

    // Default parameter: the first query key.
    let (param_name, param_value) = match opts.param {
        Some(p) => {
            let v = parsed
                .query_pairs()
                .find(|(k, _)| *k == *p)
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();
            (p.to_string(), v)
        }
        None => match parsed.query_pairs().next() {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => anyhow::bail!("URL has no query parameter to probe"),
        },
    };
    if !opts.json {
        println!("[*] probing parameter: {param_name}");
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

    let engine = bugtools_sql::DbmsProbeEngine::new(scope.clone());
    let result = bugtools_sql::analyze_endpoint(&engine, &base, &param_name, &param_value).await?;

    if opts.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }

    println!("\nDBMS hypothesis: {}", match &result.dbms_hypothesis {
        Some(d) => d.display_name(),
        None => "undetermined".to_string(),
    });
    println!("Confidence:      {}%", result.confidence_score);
    println!("Techniques run:  {}", result.techniques_tested.len());
    if !result.signals.is_empty() {
        println!("\nSignals (unique):");
        let mut seen = std::collections::BTreeSet::new();
        for s in &result.signals {
            seen.insert(s.clone());
        }
        for s in seen {
            println!("  {s}");
        }
    }
    if let Some(dbms) = result.dbms_hypothesis {
        println!("\nClause coverage for {} (accepted):", dbms.display_name());
        for coverage in &result.clause_coverage {
            if coverage.dialects_accepting.contains(&dbms) {
                println!("  {:?}", coverage.clause);
            }
        }
    }
    Ok(())
}
