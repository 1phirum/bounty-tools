//! `bugtools resolve` — DNS record resolution.

use anyhow::Result;
use bugtools_dns::{DnsConfig, DnsEngine};

use crate::parsing::parse_record_types;

pub async fn run(hostname: &str, types: &[String]) -> Result<()> {
    let engine = DnsEngine::new(DnsConfig::default())?;
    let rts = parse_record_types(types);
    let obs = engine.observe(hostname, &rts).await?;
    for record in &obs.records {
        println!(
            "{} {} {}",
            record.hostname,
            record.record_type.as_str(),
            record.value
        );
    }
    if obs.records.is_empty() {
        println!("no records for {hostname}");
    }
    Ok(())
}
