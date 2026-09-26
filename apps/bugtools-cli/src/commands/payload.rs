//! `bugtools payload` — inspect adaptive payload generation (sends nothing).

use anyhow::Result;
use bugtools_sql::payload::{
    compose_for, tampers, ClauseStrategy, ComposeContext, EscalationTier, QuoteMode,
    RepresentationContext,
};

use crate::parsing::parse_dbms_arg;

#[allow(clippy::too_many_arguments)]
pub fn run(
    clause: &str,
    quote: &str,
    dbms: Option<&str>,
    representation: &str,
    tier: &str,
    technique: &str,
    waf: bool,
    tamper: Option<&str>,
    list_tampers: bool,
    catalogue: bool,
    json: bool,
) -> Result<()> {
    if list_tampers {
        return list_available_tampers();
    }
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

    if catalogue {
        return print_catalogue(dbms_family, tier);
    }

    let ctx = ComposeContext {
        clause: clause_strategy,
        quote_mode,
        dbms: dbms_family,
        representation: rep,
        original_value: "1".to_string(),
        waf_interference: waf,
    };

    // A named tamper chain (sqlmap's `--tamper`) is applied after composition
    // and before serialization, so both the printed payload and the JSON document
    // contain the exact bytes that would be sent. Every step lands in the
    // candidate's trace, which is what makes a finding replayable.
    //
    // `--tamper auto` is our own addition: instead of hand-picking scripts, we
    // recommend an engine-appropriate, priority-ordered chain from the `--dbms`
    // and `--waf` context — dropping tampers that would not parse on the target.
    let chain = if tamper.map(|t| t.trim().eq_ignore_ascii_case("auto")).unwrap_or(false) {
        let c = tampers::recommend_chain(dbms_family, waf);
        eprintln!("[*] auto-tamper: {}", c.summary());
        c
    } else {
        tampers::resolve_chain(tamper.unwrap_or(""))
            .map_err(|e| anyhow::anyhow!("{e}"))?
    };
    let candidates: Vec<_> = if chain.is_identity() {
        compose_for(technique, &ctx, tier, 5)
    } else {
        compose_for(technique, &ctx, tier, 5)
            .into_iter()
            .map(|mut c| {
                let mut trace = c.trace.clone();
                for step in &chain.steps {
                    trace = trace.apply(*step);
                }
                c.rendered = trace.final_representation.clone();
                c.trace = trace;
                c
            })
            .collect()
    };

    if !json && !chain.is_identity() {
        println!(
            "[*] tampers: {}{}",
            chain.summary(),
            if chain.changes_semantics() {
                " (semantics-changing steps: confirm with a differential)"
            } else {
                ""
            }
        );
    }

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

/// Print the shared payload catalogue: everything the live engine can run, per
/// technique, per depth tier, and per engine when one is named.
fn print_catalogue(dbms: Option<bugtools_sql::DbmsFamily>, tier: EscalationTier) -> Result<()> {
    use bugtools_sql::generators;

    let summary = generators::catalog_summary();
    let total: usize = summary.iter().map(|(_, n)| *n).sum();
    println!(
        "[*] catalogue: {total} payload(s) across {} technique(s)\n",
        summary.iter().filter(|(_, n)| *n > 0).count()
    );
    for (name, n) in &summary {
        println!("  {name:<14} {n:>3}");
    }

    println!("\n[*] depth gate:");
    for t in [
        EscalationTier::Recon,
        EscalationTier::Confirm,
        EscalationTier::Explore,
    ] {
        println!(
            "  tier {:<8} {:>3} payload(s){}",
            t.label(),
            generators::catalog_for_tier(t).len(),
            if t == tier { "   <- requested" } else { "" }
        );
    }

    println!("\n[*] tampers: {} available (`--list-tampers` for the list)", bugtools_sql::payload::tampers::TAMPERS.len());

    if let Some(fam) = dbms {
        let profile = bugtools_sql::dialects::profile(fam);
        let ctx = bugtools_sql::payload::VectorContext {
            query: bugtools_sql::payload::extraction_query(&profile),
            seconds: 5,
            columns: 3,
            host: String::new(),
            truth: true,
        };
        println!(
            "\n[*] {} engine catalogue: {} gated vector(s)",
            fam.label(),
            bugtools_sql::payload::catalog_size(fam, &ctx)
        );
        for channel in bugtools_sql::payload::vectors::ALL_CHANNELS {
            println!(
                "  {:<18} {:>3}",
                channel.label(),
                bugtools_sql::payload::vectors_for(fam, *channel, &ctx).len()
            );
        }
    }
    Ok(())
}

/// Print every named tamper and what it does (the `--list-tampers` surface).
fn list_available_tampers() -> Result<()> {
    use bugtools_sql::payload::tampers::DbmsTag;

    println!(
        "{} named tampers — sqlmap-compatible names where the semantics match.\n\
         Chains are applied in PRIORITY order (structural rewrites before encoders),\n\
         not the order typed, so a chain can never encode away the syntax a later\n\
         rewrite needs. [tier] shows when each runs; {{dbms}} marks engine-specific ones.\n",
        tampers::TAMPERS.len()
    );
    // Show highest-priority (earliest-applied) tampers first.
    let mut sorted: Vec<&tampers::Tamper> = tampers::TAMPERS.iter().collect();
    sorted.sort_by(|a, b| b.priority().cmp(&a.priority()));
    for t in sorted {
        let dbms = match t.dbms() {
            DbmsTag::Any => String::new(),
            DbmsTag::MySql => " {mysql}".to_string(),
            DbmsTag::MsSql => " {mssql}".to_string(),
            DbmsTag::PostgreSql => " {postgres}".to_string(),
            DbmsTag::Oracle => " {oracle}".to_string(),
            DbmsTag::SqLite => " {sqlite}".to_string(),
        };
        println!("  [{:>4}] {:<26}{} {}", t.priority(), t.name, dbms, t.note);
    }
    println!(
        "\nChains auto-order by priority, so these two are identical and both correct:\n  \
         bugtools payload --clause where --quote single --tamper charencode,between\n  \
         bugtools payload --clause where --quote single --tamper between,charencode\n  \
         bugtools sqli --input endpoints.json --i-authorize --depth explore \\\n      \
         --tamper versionedmorekeywords,charunicodeencode"
    );
    Ok(())
}
