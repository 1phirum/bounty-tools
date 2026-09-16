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
    }

    Ok(())
}
