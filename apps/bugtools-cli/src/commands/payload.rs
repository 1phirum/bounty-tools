//! `bugtools payload` — inspect adaptive payload generation (sends nothing).

use anyhow::Result;
use bugtools_sql::payload::{
    compose_for, ClauseStrategy, ComposeContext, EscalationTier, QuoteMode,
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
    json: bool,
) -> Result<()> {
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
