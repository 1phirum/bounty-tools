use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SqlEngineError {
    #[error("Rule parse error: {0}")]
    RuleParse(#[from] toml::de::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// TOML rule format (backward-compatible with existing rules/sql/*.toml).
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
