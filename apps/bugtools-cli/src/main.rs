//! BugTools CLI.
//!
//! Shares the entire native Rust core with the GUI. Renders the same
//! `PipelineEvent` stream the GUI consumes.

use anyhow::Result;
use bugtools_dns::{DnsConfig, DnsEngine, RecordType};
use bugtools_discovery::{DiscoveryEngine, Target};
use bugtools_output::{EventSink, PipelineEvent};
use bugtools_runtime::{Pipeline, PipelineConfig};
use clap::{Parser, Subcommand};
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "bugtools",
    about = "BugTools — Native Rust Security Research Platform",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Normalize and describe a target without scanning it.
    Target {
        /// Domain or URL, e.g. example.com
        input: String,
    },
    /// Discover subdomains for a target.
    Discover {
        /// Domain or URL, e.g. example.com
        input: String,
        /// Emit JSON instead of human-readable lines.
        #[arg(long)]
        json: bool,
    },
    /// Resolve DNS records for a hostname.
    Resolve {
        hostname: String,
        /// Record types to query (a, aaaa, cname, mx, ns, txt, soa).
        #[arg(long, value_delimiter = ',', default_value = "a,cname")]
        types: Vec<String>,
    },
    /// Run the full pipeline: discovery → DNS → HTTP → crawl → JSON.
    Pipeline {
        /// Domain or URL, e.g. example.com
        input: String,
        /// Write the result summary as JSON to this path.
        #[arg(long)]
        out: Option<String>,
        /// Maximum crawl depth.
        #[arg(long, default_value_t = 2)]
        depth: u32,
        /// Maximum URLs to fetch while crawling.
        #[arg(long, default_value_t = 200)]
        max_urls: usize,
        /// Requests per second for HTTP probing.
        #[arg(long, default_value_t = 5.0)]
        rps: f64,
    },
    /// SQL research engine: DBMS detection and clause mapping.
    Sql {
        #[command(subcommand)]
        command: SqlCommands,
    },
}

#[derive(Subcommand)]
enum SqlCommands {
    /// Identify a DBMS from pasted error text (offline, no network).
    Detect {
        /// Error text. Use "-" to read from stdin.
        text: String,
    },
    /// Print the clause/dialect reference, optionally filtered.
    Clauses {
        /// Show only clauses the given DBMS accepts.
        #[arg(long)]
        dbms: Option<String>,
    },
    /// Run scope-checked DBMS detection against a live parameterized URL.
    Analyze {
        /// Full URL including at least one query parameter, e.g.
        /// https://target/item?id=1
        url: String,
        /// Parameter to probe (defaults to the first query parameter).
        #[arg(long)]
        param: Option<String>,
        /// Authorize this host for the scan. Without it, nothing is sent.
        #[arg(long)]
        i_authorize: bool,
    },
}

/// CLI renderer for pipeline events.
struct CliSink {
    json: bool,
}

impl EventSink for CliSink {
    fn emit(&self, event: PipelineEvent) {
        if self.json {
            if let Ok(line) = serde_json::to_string(&event) {
                println!("{line}");
            }
            return;
        }
        match event {
            PipelineEvent::Started { target, stages } => {
                println!("[*] pipeline for {target}");
                println!("[*] stages: {}", stages.join(" → "));
            }
            PipelineEvent::DiscoveryFound(a) => {
                println!("[discovery] {} ({})", a.hostname, a.source);
            }
            PipelineEvent::DiscoveryComplete { total, per_source } => {
                println!("[+] discovery complete: {total} unique hostnames");
                for (source, count) in per_source {
                    println!("      {source}: {count}");
                }
            }
            PipelineEvent::DnsResolved(d) => {
                if d.resolves {
                    println!("[dns] {} → {}", d.hostname, d.addresses.join(", "));
                } else if d.wildcard {
                    println!("[dns] {} → no records (wildcard zone detected)", d.hostname);
                } else {
                    println!("[dns] {} → no records", d.hostname);
                }
            }
            PipelineEvent::HttpObserved(h) => {
                let title = h.title.as_deref().unwrap_or("");
                println!(
                    "[http] {} {} ({}ms){}",
                    h.status,
                    h.url,
                    h.duration_ms,
                    if title.is_empty() {
                        String::new()
                    } else {
                        format!(" — {title}")
                    }
                );
            }
            PipelineEvent::UrlDiscovered(u) => {
                println!("[url] depth {} {}", u.depth, u.url);
            }
            PipelineEvent::CrawlComplete { urls, pages } => {
                println!("[+] crawl complete: {pages} pages fetched, {urls} URLs seen");
            }
            PipelineEvent::Warning(w) => println!("[!] {w}"),
            PipelineEvent::Error(e) => eprintln!("[x] {e}"),
            PipelineEvent::Complete { summary } => {
                println!();
                println!("Summary");
                println!("  target          {}", summary.target);
                println!("  subdomains      {}", summary.subdomains);
                println!("  resolved hosts  {}", summary.resolved_hosts);
                println!("  live hosts      {}", summary.live_hosts);
                println!("  http probed     {}", summary.http_probed);
                println!("  pages fetched   {}", summary.pages_fetched);
                println!("  urls discovered {}", summary.urls_crawled);
                println!("  duration        {} ms", summary.duration_ms);
            }
        }
    }
}

fn parse_record_types(types: &[String]) -> Vec<RecordType> {
    types
        .iter()
        .filter_map(|t| match t.to_lowercase().as_str() {
            "a" => Some(RecordType::A),
            "aaaa" => Some(RecordType::Aaaa),
            "cname" => Some(RecordType::Cname),
            "mx" => Some(RecordType::Mx),
            "ns" => Some(RecordType::Ns),
            "txt" => Some(RecordType::Txt),
            "soa" => Some(RecordType::Soa),
            _ => None,
        })
        .collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Target { input } => {
            let target = Target::parse(&input)?;
            println!("domain: {}", target.domain);
            println!("seeds:  {}", target.seeds.join(", "));
        }

        Commands::Discover { input, json } => {
            let target = Target::parse(&input)?;
            let engine = DiscoveryEngine::new()
                .with_source(Arc::new(
                    bugtools_discovery::sources::CertificateTransparencySource::new(),
                ))
                .with_source(Arc::new(
                    bugtools_discovery::sources::DnsBruteForceSource::new()?,
                ));
            let (assets, stats) = engine.run(&target).await;
            if json {
                println!("{}", serde_json::to_string_pretty(&assets)?);
            } else {
                for asset in &assets {
                    println!("{}", asset.hostname);
                }
                eprintln!(
                    "[+] {} unique hostnames ({} before dedup)",
                    stats.total_after_dedup, stats.total_before_dedup
                );
            }
        }

        Commands::Resolve { hostname, types } => {
            let engine = DnsEngine::new(DnsConfig::default())?;
            let rts = parse_record_types(&types);
            let obs = engine.observe(&hostname, &rts).await?;
            for record in &obs.records {
                println!("{} {} {}", record.hostname, record.record_type.as_str(), record.value);
            }
            if obs.records.is_empty() {
                println!("no records for {hostname}");
            }
        }

        Commands::Pipeline {
            input,
            out,
            depth,
            max_urls,
            rps,
        } => {
            let target = Target::parse(&input)?;
            let config = PipelineConfig {
                crawl: bugtools_crawler::CrawlConfig {
                    max_depth: depth,
                    max_urls,
                    ..Default::default()
                },
                requests_per_second: rps,
                ..Default::default()
            };
            let pipeline = Pipeline::new(config).map_err(anyhow::Error::msg)?;
            let sink = CliSink { json: false };
            let summary = pipeline.run(&target, &sink).await;

            if let Some(path) = out {
                let json = serde_json::to_string_pretty(&summary)?;
                std::fs::write(&path, json)?;
                println!("\n[+] wrote summary to {path}");
            }
        }
        Commands::Sql { command } => {
            run_sql_command(command).await?;
        }
    }

    Ok(())
}

/// Handle the `sql` subcommands.
async fn run_sql_command(command: SqlCommands) -> Result<()> {
    match command {
        SqlCommands::Detect { text } => {
            let input = if text == "-" {
                use std::io::Read;
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf
            } else {
                text
            };
            let result = bugtools_sql::detection::analyze_error_body(&input);
            match result.detected_dbms {
                Some(dbms) => {
                    println!("DBMS:       {}", dbms.display_name());
                    println!("Confidence: {}%", result.confidence);
                    println!("Verdict:    {:?}", result.verdict);
                }
                None => {
                    println!("DBMS:       undetermined");
                    println!("Verdict:    {:?}", result.verdict);
                    println!(
                        "note: absence of a signature does not identify a DBMS — it only means\n      none of the curated error patterns matched this text."
                    );
                }
            }
            if !result.signals.is_empty() {
                println!("\nMatched signals:");
                for signal in &result.signals {
                    println!(
                        "  [{:>3}] {} — {} ({:?})",
                        signal.weight,
                        signal.dbms.display_name(),
                        signal.label,
                        signal.category
                    );
                }
            }
        }

        SqlCommands::Clauses { dbms } => {
            let filter = match &dbms {
                Some(name) => Some(parse_dbms_arg(name).ok_or_else(|| {
                    anyhow::anyhow!("unknown DBMS '{name}' (mysql|mariadb|postgresql|mssql|oracle|sqlite)")
                })?),
                None => None,
            };
            for entry in bugtools_sql::clause_map::clause_map() {
                if let Some(family) = filter {
                    let relevant = entry
                        .variants
                        .iter()
                        .any(|v| v.accepted_by.contains(&family) || v.rejected_by.contains(&family));
                    if !relevant {
                        continue;
                    }
                }
                println!("{:?}", entry.clause);
                for variant in &entry.variants {
                    let accepted = variant
                        .accepted_by
                        .iter()
                        .map(|d| d.display_name())
                        .collect::<Vec<_>>()
                        .join(", ");
                    println!("    {}  [{}]", variant.syntax, accepted);
                }
            }
        }

        SqlCommands::Analyze {
            url,
            param,
            i_authorize,
        } => {
            if !i_authorize {
                anyhow::bail!(
                    "refusing to send probes without --i-authorize.\n\
                     This flag is your explicit confirmation that you are authorized to test this target."
                );
            }
            let parsed = url::Url::parse(&url)
                .map_err(|e| anyhow::anyhow!("invalid URL: {e}"))?;
            let host = parsed
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("URL has no host"))?
                .to_string();
            let param_name = match param {
                Some(p) => p,
                None => parsed
                    .query_pairs()
                    .next()
                    .map(|(k, _)| k.to_string())
                    .ok_or_else(|| {
                        anyhow::anyhow!("URL has no query parameter; pass --param to name one")
                    })?,
            };
            let param_value = parsed
                .query_pairs()
                .find(|(k, _)| *k == param_name)
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();

            // Scope: authorize exactly this host, nothing else.
            let scope = std::sync::Arc::new(bugtools_scope::ScopeEngine::new());
            {
                use bugtools_core::scope::{ScopeRule, ScopeRuleType};
                scope.add_rule(ScopeRule::new(
                    uuid::Uuid::nil(),
                    ScopeRuleType::IncludeDomain,
                    host.clone(),
                ));
            }
            println!("[*] authorized host: {host}");
            println!("[*] probing parameter: {param_name}");

            let engine = bugtools_sql::DbmsProbeEngine::new(scope);
            let base = bugtools_core::http::HttpRequest {
                id: uuid::Uuid::new_v4(),
                job_id: None,
                url: url.clone(),
                method: "GET".to_string(),
                headers: Default::default(),
                body: None,
                timestamp: chrono::Utc::now(),
            };
            let result =
                bugtools_sql::analyze_endpoint(&engine, &base, &param_name, &param_value)
                    .await
                    .map_err(|e| anyhow::anyhow!("analysis failed: {e}"))?;

            println!();
            println!("DBMS hypothesis: {}", match result.dbms_hypothesis {
                Some(d) => d.display_name(),
                None => "undetermined".to_string(),
            });
            println!("Confidence:      {}%", result.confidence_score);
            println!("Techniques run:  {}", result.techniques_tested.len());
            if !result.signals.is_empty() {
                println!("\nSignals (unique):");
                let mut seen = std::collections::BTreeSet::new();
                for signal in &result.signals {
                    seen.insert(signal.clone());
                }
                for signal in seen {
                    println!("  {signal}");
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
        }
    }
    Ok(())
}

/// Parse a DBMS family from a CLI argument.
fn parse_dbms_arg(name: &str) -> Option<bugtools_sql::DbmsFamily> {
    use bugtools_sql::DbmsFamily;
    match name.to_lowercase().as_str() {
        "mysql" => Some(DbmsFamily::MySQL),
        "mariadb" => Some(DbmsFamily::MariaDB),
        "postgresql" | "postgres" | "pg" => Some(DbmsFamily::PostgreSQL),
        "mssql" | "sqlserver" | "sql_server" => Some(DbmsFamily::MSSQL),
        "oracle" => Some(DbmsFamily::Oracle),
        "sqlite" | "sqlite3" => Some(DbmsFamily::SQLite),
        _ => None,
    }
}
