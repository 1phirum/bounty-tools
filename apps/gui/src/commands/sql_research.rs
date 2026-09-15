use crate::state::AppState;
use bugtools_core::http::HttpRequest;
use bugtools_sql::{analyze_endpoint, clause_map, DbmsProbeEngine, SqlAnalysisResult};

use uuid::Uuid;

pub async fn sql_analyze_endpoint(
    url: String,
    method: String,
    headers: Option<std::collections::HashMap<String, String>>,
    body: Option<String>,
    param_name: String,
    param_value: String,
    state: &AppState,
) -> Result<SqlAnalysisResult, String> {
    let base = HttpRequest {
        id: Uuid::new_v4(),
        job_id: None,
        url,
        method,
        headers: headers.unwrap_or_default(),
        body,
        timestamp: chrono::Utc::now(),
    };

    let engine = DbmsProbeEngine::new(state.scope.clone());
    let result = analyze_endpoint(&engine, &base, &param_name, &param_value)
        .await
        .map_err(|e| e.to_string())?;

    // Publish detection event
    if let Some(dbms) = &result.dbms_hypothesis {
        state.event_bus.publish(bugtools_core::events::BugToolsEvent::AuditLog {
            timestamp: chrono::Utc::now(),
            level: "info".to_string(),
            component: "sql-research".to_string(),
            message: format!(
                "DBMS detected: {} (confidence: {}%) for parameter '{}'",
                dbms.display_name(),
                result.confidence_score,
                param_name
            ),
        });
    }

    Ok(result)
}

pub async fn sql_get_clause_map(
    dbms: Option<String>,
    _state: &AppState,
) -> Result<serde_json::Value, String> {
    let maps = clause_map::clause_map();

    let filtered: Vec<&clause_map::SqlClauseMap> = if let Some(dbms_str) = &dbms {
        let family = parse_dbms(dbms_str).ok_or_else(|| format!("Unknown DBMS: {}", dbms_str))?;
        maps.iter()
            .filter(|m| {
                m.variants.iter().any(|v| v.accepted_by.contains(&family))
            })
            .collect()
    } else {
        maps.iter().collect()
    };

    Ok(serde_json::json!({
        "clauses": filtered,
        "total_clauses": filtered.len(),
        "coverage": clause_map::coverage_report(),
    }))
}

pub async fn sql_get_dialect_variants(
    clause: String,
    dbms: String,
    _state: &AppState,
) -> Result<serde_json::Value, String> {
    let clause_enum = parse_clause(&clause).ok_or_else(|| format!("Unknown clause: {}", clause))?;
    let family = parse_dbms(&dbms).ok_or_else(|| format!("Unknown DBMS: {}", dbms))?;

    let variants = clause_map::variants_accepted_by(family, clause_enum);

    Ok(serde_json::json!({
        "clause": clause,
        "dbms": dbms,
        "variants": variants.iter().map(|v| {
            serde_json::json!({
                "syntax": v.syntax,
                "accepted_by": v.accepted_by,
                "rejected_by": v.rejected_by,
                "notes": v.notes,
            })
        }).collect::<Vec<_>>(),
        "total": variants.len(),
    }))
}

fn parse_dbms(s: &str) -> Option<bugtools_sql::DbmsFamily> {
    match s.to_lowercase().as_str() {
        "mysql" => Some(bugtools_sql::DbmsFamily::MySQL),
        "mariadb" => Some(bugtools_sql::DbmsFamily::MariaDB),
        "postgresql" | "postgres" | "pg" => Some(bugtools_sql::DbmsFamily::PostgreSQL),
        "mssql" | "sqlserver" | "sql_server" => Some(bugtools_sql::DbmsFamily::MSSQL),
        "oracle" => Some(bugtools_sql::DbmsFamily::Oracle),
        "sqlite" | "sqlite3" => Some(bugtools_sql::DbmsFamily::SQLite),
        _ => None,
    }
}

fn parse_clause(s: &str) -> Option<clause_map::SqlClause> {
    match s.to_lowercase().as_str() {
        "select" => Some(clause_map::SqlClause::Select),
        "insert" => Some(clause_map::SqlClause::Insert),
        "update" => Some(clause_map::SqlClause::Update),
        "delete" => Some(clause_map::SqlClause::Delete),
        "where" => Some(clause_map::SqlClause::Where),
        "order_by" | "orderby" => Some(clause_map::SqlClause::OrderBy),
        "group_by" | "groupby" => Some(clause_map::SqlClause::GroupBy),
        "having" => Some(clause_map::SqlClause::Having),
        "limit_offset" | "limit" | "offset" => Some(clause_map::SqlClause::LimitOffset),
        "join_inner" | "inner_join" => Some(clause_map::SqlClause::JoinInner),
        "join_left" | "left_join" => Some(clause_map::SqlClause::JoinLeft),
        "join_right" | "right_join" => Some(clause_map::SqlClause::JoinRight),
        "join_full_outer" | "full_outer_join" => Some(clause_map::SqlClause::JoinFullOuter),
        "join_cross" | "cross_join" => Some(clause_map::SqlClause::JoinCross),
        "union" => Some(clause_map::SqlClause::Union),
        "union_all" | "unionall" => Some(clause_map::SqlClause::UnionAll),
        "subquery" => Some(clause_map::SqlClause::Subquery),
        "case_when" | "case" => Some(clause_map::SqlClause::CaseWhen),
        "string_concat" | "concat" => Some(clause_map::SqlClause::StringConcat),
        "substring" | "substr" => Some(clause_map::SqlClause::Substring),
        "length" | "len" => Some(clause_map::SqlClause::Length),
        "trim" => Some(clause_map::SqlClause::Trim),
        "upper_lower" | "upper" | "lower" => Some(clause_map::SqlClause::UpperLower),
        "coalesce" | "ifnull" | "isnull" | "nvl" => Some(clause_map::SqlClause::Coalesce),
        "cast" => Some(clause_map::SqlClause::Cast),
        "current_date" | "curdate" | "sysdate" => Some(clause_map::SqlClause::CurrentDate),
        "current_timestamp" | "now" => Some(clause_map::SqlClause::CurrentTimestamp),
        "date_add" | "dateadd" => Some(clause_map::SqlClause::DateAdd),
        "date_diff" | "datediff" => Some(clause_map::SqlClause::DateDiff),
        "create_table" => Some(clause_map::SqlClause::CreateTable),
        "alter_table" => Some(clause_map::SqlClause::AlterTable),
        "drop_table" => Some(clause_map::SqlClause::DropTable),
        "create_index" => Some(clause_map::SqlClause::CreateIndex),
        "if_exists" => Some(clause_map::SqlClause::IfExists),
        "auto_increment" => Some(clause_map::SqlClause::AutoIncrement),
        "boolean_literal" => Some(clause_map::SqlClause::BooleanLiteral),
        "comment" => Some(clause_map::SqlClause::Comment),
        _ => None,
    }
}
