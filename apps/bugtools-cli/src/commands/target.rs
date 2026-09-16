//! `bugtools target` — normalize a target, no network activity.

use anyhow::Result;
use bugtools_discovery::Target;

pub async fn run(input: &str) -> Result<()> {
    let target = Target::parse(input)?;
    println!("domain: {}", target.domain);
    println!("seeds:  {}", target.seeds.join(", "));
    Ok(())
}
