//! Renders `PipelineEvent`s for the terminal (or as JSONL when requested).

use bugtools_output::{EventSink, PipelineEvent};

/// CLI renderer for pipeline events.
pub struct CliSink {
    pub json: bool,
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
