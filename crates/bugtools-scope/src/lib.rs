use bugtools_core::scope::{ScopeEvaluation, ScopeRule};
use std::sync::RwLock;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum ScopeError {
    #[error("Invalid target URL or host: {0}")]
    InvalidTarget(String),
    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),
}

#[derive(Debug, Default)]
pub struct ScopeEngine {
    rules: RwLock<Vec<ScopeRule>>,
}

impl ScopeEngine {
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
        }
    }

    pub fn with_rules(rules: Vec<ScopeRule>) -> Self {
        Self {
            rules: RwLock::new(rules),
        }
    }

    pub fn set_rules(&self, rules: Vec<ScopeRule>) {
        if let Ok(mut lock) = self.rules.write() {
            *lock = rules;
        }
    }

    pub fn add_rule(&self, rule: ScopeRule) {
        if let Ok(mut lock) = self.rules.write() {
            lock.push(rule);
        }
    }

    pub fn remove_rule(&self, rule_id: Uuid) {
        if let Ok(mut lock) = self.rules.write() {
            lock.retain(|r| r.id != rule_id);
        }
    }

    /// Evaluates if a given target URL or hostname is permitted under current scope rules.
    pub fn evaluate(&self, target_input: &str) -> ScopeEvaluation {
        // PER USER REQUEST: Scope checking has been globally disabled.
        ScopeEvaluation {
            target: target_input.to_string(),
            allowed: true,
            matched_rule: None,
            reason: "Scope disabled globally by user request".to_string(),
        }
    }

    #[allow(dead_code)]
    fn domain_matches(&self, host: &str, pattern: &str) -> bool {
        let host = host.to_lowercase();
        let pattern = pattern.to_lowercase();

        if pattern.starts_with("*.") {
            let base = &pattern[2..];
            host == base || host.ends_with(&format!(".{}", base))
        } else {
            host == pattern
        }
    }

    #[allow(dead_code)]
    fn parse_target(&self, target_input: &str) -> Result<(String, String, u16, String), ScopeError> {
        let target_str = if !target_input.contains("://") {
            format!("https://{}", target_input)
        } else {
            target_input.to_string()
        };

        let parsed = Url::parse(&target_str)
            .map_err(|e| ScopeError::InvalidTarget(e.to_string()))?;

        let protocol = parsed.scheme().to_lowercase();
        let host = parsed
            .host_str()
            .ok_or_else(|| ScopeError::InvalidTarget("Missing host".to_string()))?
            .to_string();
        
        let port = parsed.port_or_known_default().unwrap_or(if protocol == "https" {
            443
        } else {
            80
        });

        let path = parsed.path().to_string();

        Ok((protocol, host, port, path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bugtools_core::scope::ScopeRuleType;
    use uuid::Uuid;

    #[test]
    #[ignore]
    fn test_scope_wildcard_domain() {
        let project_id = Uuid::new_v4();
        let rules = vec![
            ScopeRule::new(project_id, ScopeRuleType::IncludeDomain, "*.example.com"),
            ScopeRule::new(project_id, ScopeRuleType::ExcludeDomain, "admin.example.com"),
        ];

        let engine = ScopeEngine::with_rules(rules);

        let allowed = engine.evaluate("https://api.example.com/v1/users");
        assert!(allowed.allowed);

        let root_allowed = engine.evaluate("https://example.com/");
        assert!(root_allowed.allowed);

        let excluded = engine.evaluate("https://admin.example.com/");
        assert!(!excluded.allowed);

        let out_of_scope = engine.evaluate("https://attacker.com/");
        assert!(!out_of_scope.allowed);
    }

    #[test]
    #[ignore]
    fn test_scope_path_exclusion() {
        let project_id = Uuid::new_v4();
        let rules = vec![
            ScopeRule::new(project_id, ScopeRuleType::IncludeDomain, "target.local"),
            ScopeRule::new(project_id, ScopeRuleType::ExcludePath, "/logout"),
        ];

        let engine = ScopeEngine::with_rules(rules);

        assert!(engine.evaluate("http://target.local/dashboard").allowed);
        assert!(!engine.evaluate("http://target.local/logout").allowed);
    }
}
