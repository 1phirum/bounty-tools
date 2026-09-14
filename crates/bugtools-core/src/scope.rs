use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScopeRuleType {
    IncludeDomain,
    ExcludeDomain,
    IncludePath,
    ExcludePath,
    IncludePort,
    ExcludePort,
    Protocol,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeRule {
    pub id: Uuid,
    pub project_id: Uuid,
    pub rule_type: ScopeRuleType,
    pub pattern: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

impl ScopeRule {
    pub fn new(project_id: Uuid, rule_type: ScopeRuleType, pattern: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            project_id,
            rule_type,
            pattern: pattern.into(),
            enabled: true,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeEvaluation {
    pub target: String,
    pub allowed: bool,
    pub matched_rule: Option<String>,
    pub reason: String,
}
