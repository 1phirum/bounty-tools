use crate::state::AppState;
use bugtools_core::scope::{ScopeEvaluation, ScopeRule, ScopeRuleType};
use uuid::Uuid;

pub async fn get_scope_rules(project_id: String, state: &AppState) -> Result<Vec<ScopeRule>, String> {
    let proj_uuid = Uuid::parse_str(&project_id).map_err(|e| e.to_string())?;
    state.db.get_scope_rules(proj_uuid).map_err(|e| e.to_string())
}

pub async fn add_scope_rule(
    project_id: String,
    rule_type: String,
    pattern: String,
    state: &AppState,
) -> Result<ScopeRule, String> {
    let proj_uuid = Uuid::parse_str(&project_id).map_err(|e| e.to_string())?;
    let r_type = match rule_type.to_lowercase().as_str() {
        "include_domain" => ScopeRuleType::IncludeDomain,
        "exclude_domain" => ScopeRuleType::ExcludeDomain,
        "include_path" => ScopeRuleType::IncludePath,
        "exclude_path" => ScopeRuleType::ExcludePath,
        "include_port" => ScopeRuleType::IncludePort,
        "exclude_port" => ScopeRuleType::ExcludePort,
        _ => ScopeRuleType::Protocol,
    };

    let rule = ScopeRule::new(proj_uuid, r_type, pattern);
    state.db.insert_scope_rule(&rule).map_err(|e| e.to_string())?;
    state.scope.add_rule(rule.clone());

    Ok(rule)
}

pub async fn evaluate_target(target: String, state: &AppState) -> Result<ScopeEvaluation, String> {
    Ok(state.scope.evaluate(&target))
}
