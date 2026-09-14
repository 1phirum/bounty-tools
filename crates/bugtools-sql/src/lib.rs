use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum SqlEngineError {
    #[error("Rule parse error: {0}")]
    RuleParse(#[from] toml::de::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SqlContext {
    Unknown,
    Numeric,
    String,
    Boolean,
    Like,
    OrderBy,
    Limit,
    Offset,
    Identifier,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SqlDialect {
    Generic,
    MySQL,
    PostgreSQL,
    MSSQL,
    Oracle,
    SQLite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlDetectionRule {
    pub id: String,
    pub name: String,
    pub category: String,
    pub dbms: Option<String>,
    pub patterns: Vec<String>,
    pub confidence_delta: i32,
}

pub struct SqlRuleRegistry {
    rules: Vec<SqlDetectionRule>,
}

impl Default for SqlRuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SqlRuleRegistry {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn load_rule_from_str(&mut self, content: &str) -> Result<(), SqlEngineError> {
        let rule: SqlDetectionRule = toml::from_str(content)?;
        self.rules.push(rule);
        Ok(())
    }

    pub fn load_rule_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), SqlEngineError> {
        let content = std::fs::read_to_string(path)?;
        self.load_rule_from_str(&content)
    }

    pub fn scan_for_signatures(&self, body: &str) -> Vec<(&SqlDetectionRule, String)> {
        let mut matched = Vec::new();
        let body_lower = body.to_lowercase();
        for rule in &self.rules {
            for pattern in &rule.patterns {
                if body_lower.contains(&pattern.to_lowercase()) {
                    matched.push((rule, pattern.clone()));
                    break;
                }
            }
        }
        matched
    }

    pub fn rules(&self) -> &[SqlDetectionRule] {
        &self.rules
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlAnalysisResult {
    pub target: String,
    pub endpoint: String,
    pub parameter: String,
    pub context: SqlContext,
    pub dbms_hypothesis: Option<SqlDialect>,
    pub techniques_tested: Vec<String>,
    pub signals: Vec<String>,
    pub confidence_score: u32,
    pub evidence_id: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_rule_matching() {
        let mut registry = SqlRuleRegistry::new();
        let toml_rule = r#"
            id = "pg-001"
            name = "PostgreSQL syntax error"
            category = "error-analysis"
            dbms = "postgresql"
            patterns = ["syntax error at or near", "unterminated quoted string"]
            confidence_delta = 30
        "#;
        registry.load_rule_from_str(toml_rule).unwrap();

        let hits = registry.scan_for_signatures("Error: syntax error at or near 'SELECT'");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0.id, "pg-001");
    }
}
