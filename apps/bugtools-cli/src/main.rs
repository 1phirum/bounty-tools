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
    #[command(visible_alias = "t", long_about = "Normalize a domain or URL and show the apex domain and seed hosts. Performs no network activity.\n\nEXAMPLES:\n  bugtools t example.com\n  bugtools target https://api.example.com/v2/items?id=1")]
    Target {
        /// Domain or URL, e.g. example.com
        input: String,
    },
    /// Discover subdomains for a target (CT logs + DNS brute-force).
    #[command(visible_alias = "d", long_about = "Run the native discovery engine: certificate transparency plus DNS brute-force, deduplicated by normalized hostname.\n\nEXAMPLES:\n  bugtools d example.com\n  bugtools discover example.com --json")]
    Discover {
        /// Domain or URL, e.g. example.com
        input: String,
        /// Emit JSON instead of human-readable lines.
        #[arg(short = 'j', long)]
        json: bool,
    },
    /// Resolve DNS records for a hostname.
    #[command(visible_alias = "r", long_about = "Resolve A/AAAA/CNAME/MX/NS/TXT/SOA records using the native DNS engine.\n\nEXAMPLES:\n  bugtools r example.com\n  bugtools resolve example.com --types a,ns,mx")]
    Resolve {
        hostname: String,
        /// Record types to query (a, aaaa, cname, mx, ns, txt, soa).
        #[arg(long, value_delimiter = ',', default_value = "a,cname")]
        types: Vec<String>,
    },
    /// Run the full pipeline: discovery -> DNS -> HTTP -> crawl -> JSON.
    #[command(visible_alias = "p", long_about = "Full recon pipeline for a target: scope -> discovery -> DNS -> HTTP probe -> crawl -> summary.\n\nEXAMPLES:\n  bugtools p example.com\n  bugtools pipeline example.com --out result.json --depth 2 --max-urls 200")]
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
    #[command(visible_alias = "s", long_about = "SQL research engine. Offline detection from pasted error text, the clause/dialect reference, and live scope-checked DBMS probing.\n\nEXAMPLES:\n  bugtools s detect \"psycopg2.errors.SyntaxError: syntax error at or near\"\n  bugtools sql clauses --dbms postgresql\n  bugtools s analyze \"https://target/item?id=1\" --i-authorize\n  bugtools s analyze \"https://target/item?id=1\" -c session.txt --i-authorize")]
    Sql {
        #[command(subcommand)]
        command: SqlCommands,
    },
    /// Fingerprint a target's technology stack from a live response.
    #[command(visible_alias = "x", long_about = "Technology intelligence: fingerprint the stack from headers, cookies, HTML and script paths, then derive the XSS strategy. Versions are reported only when the exact string is observed.\n\nEXAMPLES:\n  bugtools x https://example.com --i-authorize\n  bugtools tech https://example.com --i-authorize --json\n  bugtools x https://app.example.com -c session.txt -H \"X-Account-ID: 99\" --i-authorize")]
    Tech {
        /// URL to fingerprint.
        url: String,
        /// Authorize this host for the request.
        #[arg(short = 'y', long)]
        i_authorize: bool,
        /// Cookies (inline list or file path).
        #[arg(short = 'c', long = "cookie", value_delimiter = ';')]
        cookies: Vec<String>,
        /// Extra headers as `Name: value`.
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Bearer token.
        #[arg(short = 'b', long)]
        bearer: Option<String>,
        /// Emit JSON.
        #[arg(short = 'j', long)]
        json: bool,
        /// Path to a program policy TOML file. Enforces its scope and limits.
        #[arg(long, value_name = "FILE")]
        program: Option<String>,
        /// Your researcher handle; sent as an identity header when the
        /// program requires one.
        #[arg(long)]
        handle: Option<String>,
    },
    /// Inspect adaptive payload generation (sends nothing).
    #[command(visible_alias = "gen", long_about = "Show the candidates the SQLi engine would use, with the rationale for each. Sends no traffic.\n\nEXAMPLES:\n  bugtools gen --clause where --quote single\n  bugtools payload --clause order_by --quote numeric --dbms postgresql --tier explore\n  bugtools gen --clause where --quote single --waf --json")]
    Payload {
        /// SQL clause/context: where, having, order_by, group_by, join, like,
        /// limit, insert, update, delete, select_expr, function_arg, generic.
        #[arg(long, default_value = "where")]
        clause: String,
        /// Quote mode: none, single, double, backtick, bracket.
        #[arg(long, default_value = "single")]
        quote: String,
        /// DBMS hypothesis: mysql, mariadb, postgresql, mssql, oracle,
        /// sqlite, db2, h2. Omit for unknown.
        #[arg(long)]
        dbms: Option<String>,
        /// Representation context: query, form, json, header, cookie, path.
        #[arg(long, default_value = "query")]
        representation: String,
        /// Escalation tier: recon, confirm, explore.
        #[arg(long, default_value = "recon")]
        tier: String,
        /// Technique: boolean, error, timing, union, clause.
        #[arg(long, default_value = "boolean")]
        technique: String,
        /// Simulate prior edge interference (widens representation breadth).
        #[arg(long)]
        waf: bool,
        /// Emit JSON instead of a human-readable table.
        #[arg(short = 'j', long)]
        json: bool,
    },
    /// Assess SQLi candidates from an endpoints/parameters JSON file.
    #[command(visible_alias = "q", long_about = "Assess SQLi candidates listed in a JSON file. Requires --i-authorize.\n\nEXAMPLES:\n  bugtools q --input endpoints.json --i-authorize\n  bugtools sqli --input endpoints.json -c cookies.txt --i-authorize --depth confirm\n  bugtools q --input endpoints.json -b \"eyJ...\" --i-authorize --json --format json")]
    Sqli {
        /// JSON file describing candidates: a list of objects with url,
        /// method, parameter and location fields.
        #[arg(short = 'i', long)]
        input: String,
        /// Authorize the hosts in the input file for probing.
        #[arg(short = 'y', long)]
        i_authorize: bool,
        /// Cookies to send. Accepts either an inline `name=value` list (use
        /// `;` to separate several) or a path to a cookie file — the file is
        /// read automatically when the argument names an existing file.
        #[arg(short = 'c', long = "cookie", value_delimiter = ';')]
        cookies: Vec<String>,
        /// Explicit cookie-file flag, equivalent to passing a path to
        /// `--cookie`. Kept for clarity.
        #[arg(long)]
        cookie_file: Option<String>,
        /// Extra headers as `Name: value` (repeatable).
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Bearer token, sent as `Authorization: Bearer <token>`.
        #[arg(short = 'b', long)]
        bearer: Option<String>,
        /// Maximum concurrent probes.
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
        /// Requests per second.
        #[arg(long, default_value_t = 5.0)]
        rate_limit: f64,
        /// Per-request timeout in seconds.
        #[arg(long, default_value_t = 15)]
        timeout: u64,
        /// Write the assessments as JSON to this path.
        #[arg(short = 'o', long)]
        output: Option<String>,
        /// Output format for stdout: text or json.
        #[arg(short = 'f', long, default_value = "text")]
        format: String,
        /// Test depth: recon, confirm, or explore.
        #[arg(short = 'd', long, default_value = "recon")]
        depth: String,
        /// Maximum requests to spend across the whole run.
        #[arg(long, default_value_t = 500)]
        max_requests: u64,
        /// Path to a program policy TOML file. Enforces its scope and limits.
        #[arg(long, value_name = "FILE")]
        program: Option<String>,
        /// Your researcher handle; sent as an identity header when the
        /// program requires one, and available as X-Bug-Bounty otherwise.
        #[arg(long)]
        handle: Option<String>,
    },
}

#[derive(Subcommand)]
enum SqlCommands {
    /// Identify a DBMS from pasted error text (offline, no network).
    #[command(visible_alias = "id", long_about = "Identify a DBMS from error text. Sends nothing. Use \"-\" to read from stdin.\n\nEXAMPLES:\n  bugtools s detect \"ORA-01756: quoted string not properly terminated\"\n  bugtools s detect - < error.txt")]
    Detect {
        /// Error text. Use "-" to read from stdin.
        text: String,
    },
    /// Print the clause/dialect reference, optionally filtered.
    #[command(visible_alias = "ref", long_about = "Print the SQL clause/dialect reference.\n\nEXAMPLES:\n  bugtools sql clauses\n  bugtools s ref --dbms postgresql")]
    Clauses {
        /// Show only clauses the given DBMS accepts.
        #[arg(long)]
        dbms: Option<String>,
    },
    /// Run scope-checked DBMS detection against a live parameterized URL.
    #[command(visible_alias = "a", long_about = "Live scope-checked DBMS detection. Requires --i-authorize.\n\nEXAMPLES:\n  bugtools s a \"https://target/item?id=1\" --i-authorize\n  bugtools sql analyze \"https://target/item?id=1\" -p id -c session.txt --i-authorize")]
    Analyze {
        /// Full URL including at least one query parameter, e.g.
        /// https://target/item?id=1
        url: String,
        /// Parameter to probe (defaults to the first query parameter).
        #[arg(short = 'p', long)]
        param: Option<String>,
        /// Authorize this host for the scan. Without it, nothing is sent.
        #[arg(short = 'y', long)]
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

        Commands::Tech {
            url,
            i_authorize,
            cookies,
            headers,
            bearer,
            json,
            program,
            handle,
        } => {
            run_tech_command(
                &url,
                i_authorize,
                &cookies,
                &headers,
                bearer.as_deref(),
                json,
                program.as_deref(),
                handle.as_deref(),
            )
            .await?;
        }

        Commands::Payload {
            clause,
            quote,
            dbms,
            representation,
            tier,
            technique,
            waf,
            json,
        } => {
            run_payload_command(
                &clause, &quote, dbms.as_deref(), &representation, &tier, &technique, waf, json,
            )?;
        }

        Commands::Sqli {
            input,
            i_authorize,
            cookies,
            cookie_file,
            headers,
            bearer,
            concurrency: _,
            rate_limit: _,
            timeout: _,
            output,
            format,
            depth,
            max_requests,
            program,
            handle,
        } => {
            run_sqli_command(
                &input,
                i_authorize,
                &cookies,
                cookie_file.as_deref(),
                &headers,
                bearer.as_deref(),
                output.as_deref(),
                &format,
                &depth,
                max_requests,
                program.as_deref(),
                handle.as_deref(),
            )
            .await?;
        }
    }

    Ok(())
}

/// Resolve the cookie set from CLI flags and an optional file.
///
/// Accepts `--cookie "name=value"` (repeatable), `--cookie "a=1; b=2"`,
/// and `--cookie-file` containing either a raw `Cookie:` header value or
/// one `name=value` per line. Returns name/value pairs.
fn resolve_cookies(cli_cookies: &[String], cookie_file: Option<&str>) -> Result<Vec<(String, String)>> {
    let mut jar = bugtools_sql::request::CookieJar::new("cli");

    // Ingest one cookie source. If it names an existing file, read it;
    // otherwise treat it as an inline `name=value` (or `;`-separated) list.
    // This lets `--cookie cookies.txt` work without a separate flag.
    fn ingest(source: &str, jar: &mut bugtools_sql::request::CookieJar) -> Result<()> {
        let trimmed = source.trim();
        if trimmed.is_empty() {
            return Ok(());
        }

        // File path? Only if it exists — an inline pair like "a=1" never
        // collides with a real path because of the '='.
        let path = std::path::Path::new(trimmed);
        if path.is_file() {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("cannot read cookie file {}: {e}", path.display()))?;
            return ingest_contents(&raw, jar);
        }

        // Inline value: may itself contain a `;`-separated cookie header.
        ingest_contents(trimmed, jar)
    }

    /// Parse cookie text: accepts a raw `Cookie:` header, `name=value`
    /// pairs separated by `;`, or one `name=value` per line. Lines starting
    /// with `#` are comments.
    fn ingest_contents(raw: &str, jar: &mut bugtools_sql::request::CookieJar) -> Result<()> {
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("Cookie:").unwrap_or(line).trim();
            for pair in line.split(';') {
                let pair = pair.trim();
                if pair.is_empty() {
                    continue;
                }
                if let Some((name, value)) = pair.split_once('=') {
                    jar.import_pairs(&[(name.trim().to_string(), value.trim().to_string())]);
                } else {
                    anyhow::bail!("invalid cookie '{pair}': expected name=value");
                }
            }
        }
        Ok(())
    }

    for entry in cli_cookies {
        ingest(entry, &mut jar)?;
    }

    if let Some(source) = cookie_file {
        ingest(source, &mut jar)?;
    }

    Ok(jar.export_pairs())
}

/// Parse `Name: value` header flags into a map.
fn resolve_headers(headers: &[String], bearer: Option<&str>) -> Result<std::collections::HashMap<String, String>> {
    let mut map = std::collections::HashMap::new();
    for header in headers {
        let (name, value) = header
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("invalid header '{header}': expected 'Name: value'"))?;
        map.insert(name.trim().to_string(), value.trim().to_string());
    }
    if let Some(token) = bearer {
        map.insert("Authorization".to_string(), format!("Bearer {token}"));
    }
    Ok(map)
}

/// A SQLi candidate as read from the input JSON.
#[derive(serde::Deserialize)]
struct SqliCandidate {
    url: String,
    #[serde(default = "default_method")]
    method: String,
    parameter: String,
    #[serde(default = "default_location")]
    location: String,
}

fn default_method() -> String {
    "GET".to_string()
}

fn default_location() -> String {
    "query".to_string()
}

/// Render a hypothesis list like `WHERE: 0.61 | LIKE: 0.24 | unknown: 0.15`.
fn render_hypotheses(hypotheses: &[(String, f32)]) -> String {
    if hypotheses.is_empty() {
        return "unknown (none considered)".to_string();
    }
    let present: Vec<String> = hypotheses
        .iter()
        .filter(|(_, p)| *p > 0.01)
        .map(|(label, p)| format!("{label}: {p:.2}"))
        .collect();
    let ruled_out: Vec<&String> = hypotheses
        .iter()
        .filter(|(_, p)| *p <= 0.01)
        .map(|(label, _)| label)
        .collect();
    let mut out = present.join(" | ");
    if out.is_empty() {
        out = "unknown".to_string();
    }
    if !ruled_out.is_empty() {
        let names: Vec<&str> = ruled_out.iter().map(|s| s.as_str()).collect();
        out.push_str(&format!("   (considered, no evidence: {})", names.join(", ")));
    }
    out
}

/// Run the `sqli` command: assess each candidate and emit assessments.
#[allow(clippy::too_many_arguments)]
async fn run_sqli_command(
    input_path: &str,
    authorize: bool,
    cli_cookies: &[String],
    cookie_file: Option<&str>,
    header_flags: &[String],
    bearer: Option<&str>,
    output_path: Option<&str>,
    format: &str,
    depth: &str,
    max_requests: u64,
    program: Option<&str>,
    handle: Option<&str>,
) -> Result<()> {
    // Program policy: apply stated scope and constraints when provided.
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

    let cookie_pairs = resolve_cookies(cli_cookies, cookie_file)?;
    let mut header_map = resolve_headers(header_flags, bearer)?;
    // Researcher identity header when supplied (e.g. X-Bug-Bounty).
    if let Some(h) = handle {
        header_map.entry("X-Bug-Bounty".to_string()).or_insert_with(|| h.to_string());
    }
    // Progress output goes to stderr when the caller asked for JSON, so
    // stdout stays a single parseable document.
    let progress = |msg: String| {
        if format == "json" {
            eprintln!("{msg}");
        } else {
            println!("{msg}");
        }
    };
    if !cookie_pairs.is_empty() {
        progress(format!(
            "[*] session: {} cookie(s) — {}",
            cookie_pairs.len(),
            cookie_pairs.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }
    if !header_map.is_empty() {
        progress(format!(
            "[*] session: {} header(s) — {}",
            header_map.len(),
            header_map.keys().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    let _budget = bugtools_sql::scheduler::RequestBudget::new(max_requests);
    progress(format!("[*] request budget: {max_requests}"));

    let raw = std::fs::read_to_string(input_path)
        .map_err(|e| anyhow::anyhow!("cannot read {input_path}: {e}"))?;
    let candidates: Vec<SqliCandidate> = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("invalid candidate JSON: {e}"))?;

    // When a program policy is active, refuse out-of-scope targets outright.
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
            eprintln!("[*] {} of {} candidate(s) dropped as out of scope", rejected.len(), rejected.len() + kept.len());
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
            if let Some(h) = url::Url::parse(&c.url).ok().and_then(|u| u.host_str().map(String::from)) {
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
            candidate.method, candidate.url, candidate.parameter, candidate.location, depth
        ));

        // Build the request with the researcher's session material so the
        // scan runs authenticated exactly as they configured it.
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

        // Adaptive, evidence-driven run (replaces blind probe execution).
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
                if format == "json" {
                    // Collected and emitted once at the end.
                } else {
                    println!("    baseline:   {}", a.baseline_summary);
                    println!("    context:    {}", render_hypotheses(&a.context_hypotheses));
                    println!("    position:   {}", render_hypotheses(&a.query_position_hypotheses));
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
                assessments.push(a);
            }
            Err(e) => eprintln!("[!] adaptive run failed for {}: {e}", candidate.url),
        }
    }

    if format == "json" {
        // A single clean document on stdout.
        println!("{}", serde_json::to_string_pretty(&assessments)?);
    }
    if let Some(path) = output_path {
        std::fs::write(path, serde_json::to_string_pretty(&assessments)?)?;
        if format != "json" {
            println!("\n[+] wrote {} assessments to {path}", assessments.len());
        }
    } else if format == "text" {
        println!("\n[+] {} candidate(s) assessed", assessments.len());
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

/// Fingerprint a target's technology stack and print the derived strategy.
async fn run_tech_command(
    url: &str,
    authorize: bool,
    cli_cookies: &[String],
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

    let cookie_pairs = resolve_cookies(cli_cookies, None)?;
    let mut header_map = resolve_headers(header_flags, bearer)?;
    // Researcher identity: an X-Bug-Bounty header identifying the handle.
    if let Some(h) = handle {
        header_map.entry("X-Bug-Bounty".to_string()).or_insert_with(|| h.to_string());
    }
    if !cookie_pairs.is_empty() {
        let cookie_header = cookie_pairs
            .iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        header_map.insert("Cookie".to_string(), cookie_header);
    }

    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (compatible; BugTools/0.1)")
        .timeout(std::time::Duration::from_secs(20))
        .build()?;

    let mut request = client.get(url);
    for (k, v) in &header_map {
        request = request.header(k, v);
    }
    let response = request.send().await?;
    let status = response.status();

    let mut header_vec: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    // Reqwest may fold multiple Set-Cookie values; keep them as observed.
    header_vec.sort();
    let body = response.text().await.unwrap_or_default();

    let script_srcs = bugtools_xss::technology::extract_script_srcs(&body);
    let observations = bugtools_xss::observations_from_response(&header_vec, &body, &script_srcs);
    let findings = bugtools_xss::detect(&observations);
    let strategy = bugtools_xss::build_strategy(&findings);

    if json {
        let payload = serde_json::json!({
            "url": url,
            "technologies": findings,
            "strategy": {
                "rendering_model": strategy.rendering_model,
                "driven_by": strategy.driven_by,
                "items": strategy.items,
            }
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    println!("[*] fingerprinting {} (HTTP {})", url, status);
    println!();
    if findings.is_empty() {
        println!("No technology crossed the reporting threshold.");
        println!("note: this is absence of evidence, not evidence of absence —");
        println!("      most markers require multiple corroborating signals.");
    } else {
        println!("TECHNOLOGIES ({}):", findings.len());
        for f in &findings {
            println!("  {:<24} {:<22} {}", f.technology, format!("{:?}", f.category), match &f.version {
                Some(v) => format!("v{v} (observed)"),
                None => "version not observed".to_string(),
            });
            for e in &f.evidence {
                println!("      · {} = {:?}", e.evidence_source.label(), e.evidence_value);
            }
        }
    }

    println!();
    println!("RENDERING MODEL: {:?}", strategy.rendering_model);
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

/// Generate payload candidates for inspection (sends nothing).
#[allow(clippy::too_many_arguments)]
fn run_payload_command(
    clause: &str,
    quote: &str,
    dbms: Option<&str>,
    representation: &str,
    tier: &str,
    technique: &str,
    waf: bool,
    json: bool,
) -> Result<()> {
    use bugtools_sql::payload::{
        compose_for, ClauseStrategy, ComposeContext, EscalationTier, QuoteMode,
        RepresentationContext,
    };

    let clause_strategy = match clause.to_lowercase().as_str() {
        "where" => ClauseStrategy::Where,
        "having" => ClauseStrategy::Having,
        "order_by" | "orderby" => ClauseStrategy::OrderBy,
        "group_by" | "groupby" => ClauseStrategy::GroupBy,
        "join" => ClauseStrategy::Join,
        "like" => ClauseStrategy::Like,
        "limit" | "offset" | "limit_offset" => ClauseStrategy::LimitOffset,
        "insert" | "values" => ClauseStrategy::InsertValues,
        "update" => ClauseStrategy::UpdateSet,
        "delete" => ClauseStrategy::DeleteWhere,
        "select_expr" | "select" => ClauseStrategy::SelectExpression,
        "function_arg" | "function" => ClauseStrategy::FunctionArgument,
        "generic" => ClauseStrategy::Generic,
        other => anyhow::bail!("unknown clause '{other}'"),
    };

    let quote_mode = match quote.to_lowercase().as_str() {
        "none" | "numeric" => QuoteMode::None,
        "single" => QuoteMode::Single,
        "double" => QuoteMode::Double,
        "backtick" => QuoteMode::Backtick,
        "bracket" => QuoteMode::Bracket,
        other => anyhow::bail!("unknown quote mode '{other}'"),
    };

    let rep = match representation.to_lowercase().as_str() {
        "query" => RepresentationContext::QueryValue,
        "form" => RepresentationContext::FormValue,
        "json" => RepresentationContext::JsonString,
        "header" => RepresentationContext::HeaderValue,
        "cookie" => RepresentationContext::CookieValue,
        "path" => RepresentationContext::PathSegment,
        other => anyhow::bail!("unknown representation '{other}'"),
    };

    let tier = match tier.to_lowercase().as_str() {
        "recon" => EscalationTier::Recon,
        "confirm" => EscalationTier::Confirm,
        "explore" => EscalationTier::Explore,
        other => anyhow::bail!("unknown tier '{other}'"),
    };

    let technique = match technique.to_lowercase().as_str() {
        "boolean" => bugtools_sql::types::ProbeType::BooleanBlind,
        "error" => bugtools_sql::types::ProbeType::ErrorInjection,
        "timing" => bugtools_sql::types::ProbeType::TimingProbe,
        "union" => bugtools_sql::types::ProbeType::UnionBased,
        "clause" => bugtools_sql::types::ProbeType::ClauseVariant,
        other => anyhow::bail!("unknown technique '{other}'"),
    };

    let dbms_family = dbms.and_then(parse_dbms_arg);

    let ctx = ComposeContext {
        clause: clause_strategy,
        quote_mode,
        dbms: dbms_family,
        representation: rep,
        original_value: "1".to_string(),
        waf_interference: waf,
    };

    let candidates = compose_for(technique, &ctx, tier, 5);

    if json {
        println!("{}", serde_json::to_string_pretty(&candidates)?);
        return Ok(());
    }

    println!(
        "[*] composed {} candidate(s) for {:?} / {} / {} / tier {}\n",
        candidates.len(),
        technique,
        clause_strategy.label(),
        match quote_mode {
            QuoteMode::None => "numeric",
            QuoteMode::Single => "single-quoted",
            QuoteMode::Double => "double-quoted",
            QuoteMode::Backtick => "backtick",
            QuoteMode::Bracket => "bracket",
        },
        tier.label()
    );
    for (i, c) in candidates.iter().enumerate() {
        println!("{:3}. {}", i + 1, c.rendered);
        println!("     rationale: {}", c.rationale);
        if !c.trace.steps.is_empty() {
            println!("     transform: {}", c.trace.summary());
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
