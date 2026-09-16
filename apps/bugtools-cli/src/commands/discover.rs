//! `bugtools discover` — subdomain discovery (CT + DNS brute-force).

use anyhow::Result;
use bugtools_discovery::{sources, DiscoveryEngine, Target};
use std::sync::Arc;

pub async fn run(input: &str, json: bool) -> Result<()> {
    let target = Target::parse(input)?;
    let engine = DiscoveryEngine::new()
        .with_source(Arc::new(sources::CertificateTransparencySource::new()))
        .with_source(Arc::new(sources::DnsBruteForceSource::new()?));
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
    Ok(())
}
