//! `bugtools pipeline` — the full recon pipeline.

use anyhow::Result;
use bugtools_discovery::Target;
use bugtools_runtime::{Pipeline, PipelineConfig};

use crate::output::CliSink;

pub async fn run(
    input: &str,
    out: Option<&str>,
    depth: u32,
    max_urls: usize,
    rps: f64,
) -> Result<()> {
    let target = Target::parse(input)?;
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
        std::fs::write(path, json)?;
        println!("\n[+] wrote summary to {path}");
    }
    Ok(())
}
