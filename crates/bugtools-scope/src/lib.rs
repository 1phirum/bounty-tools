use bugtools_core::scope::{ScopeEvaluation, ScopeRule, ScopeRuleType};
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
        let (protocol, host, port, path) = match self.parse_target(target_input) {
            Ok(parsed) => parsed,
            Err(e) => {
                return ScopeEvaluation {
                    target: target_input.to_string(),
                    allowed: false,
                    matched_rule: None,
                    reason: format!("Failed to parse target: {}", e),
                }
            }
        };

        let rules = match self.rules.read() {
            Ok(r) => r.clone(),
            Err(_) => {
                return ScopeEvaluation {
                    target: target_input.to_string(),
                    allowed: false,
                    matched_rule: None,
                    reason: "Scope lock poisoned".to_string(),
                }
            }
        };

        let active_rules: Vec<&ScopeRule> = rules.iter().filter(|r| r.enabled).collect();
        if active_rules.is_empty() {
            return ScopeEvaluation {
                target: target_input.to_string(),
                allowed: false,
                matched_rule: None,
                reason: "No active scope rules configured (default deny)".to_string(),
            };
        }

        // 1. Check Explicit Exclusions first (Domain, Path, Port)
        for rule in &active_rules {
            match rule.rule_type {
                ScopeRuleType::ExcludeDomain => {
                    if self.domain_matches(&host, &rule.pattern) {
                        return ScopeEvaluation {
                            target: target_input.to_string(),
                            allowed: false,
                            matched_rule: Some(rule.pattern.clone()),
                            reason: format!("Explicitly excluded by domain rule: {}", rule.pattern),
                        };
                    }
                }
                ScopeRuleType::ExcludePath => {
                    if path.starts_with(&rule.pattern) {
                        return ScopeEvaluation {
                            target: target_input.to_string(),
                            allowed: false,
                            matched_rule: Some(rule.pattern.clone()),
                            reason: format!("Explicitly excluded by path rule: {}", rule.pattern),
                        };
                    }
                }
                ScopeRuleType::ExcludePort => {
                    if let Ok(p) = rule.pattern.parse::<u16>() {
                        if port == p {
                            return ScopeEvaluation {
                                target: target_input.to_string(),
                                allowed: false,
                                matched_rule: Some(rule.pattern.clone()),
                                reason: format!("Explicitly excluded by port rule: {}", rule.pattern),
                            };
                        }
                    }
                }
                _ => {}
            }
        }

        // 2. Check Protocol rules if specified
        let protocol_rules: Vec<&&ScopeRule> = active_rules
            .iter()
            .filter(|r| r.rule_type == ScopeRuleType::Protocol)
            .collect();
        if !protocol_rules.is_empty() {
            let matches_protocol = protocol_rules
                .iter()
                .any(|r| r.pattern.eq_ignore_ascii_case(&protocol));
            if !matches_protocol {
                return ScopeEvaluation {
                    target: target_input.to_string(),
                    allowed: false,
                    matched_rule: None,
                    reason: format!("Protocol '{}' is not in allowed protocols", protocol),
                };
            }
        }

        // 3. Check Port inclusion rules if specified
        let port_include_rules: Vec<&&ScopeRule> = active_rules
            .iter()
            .filter(|r| r.rule_type == ScopeRuleType::IncludePort)
            .collect();
        if !port_include_rules.is_empty() {
            let matches_port = port_include_rules.iter().any(|r| {
                if let Ok(p) = r.pattern.parse::<u16>() {
                    p == port
                } else {
                    false
                }
            });
            if !matches_port {
                return ScopeEvaluation {
                    target: target_input.to_string(),
                    allowed: false,
                    matched_rule: None,
                    reason: format!("Port '{}' is not in allowed include ports", port),
                };
            }
        }

        // 4. Check Include Domain rules
        let domain_include_rules: Vec<&&ScopeRule> = active_rules
            .iter()
            .filter(|r| r.rule_type == ScopeRuleType::IncludeDomain)
            .collect();
        
        let mut matched_domain_rule: Option<String> = None;
        if !domain_include_rules.is_empty() {
            for rule in domain_include_rules {
                if self.domain_matches(&host, &rule.pattern) {
                    matched_domain_rule = Some(rule.pattern.clone());
                    break;
                }
            }
            if matched_domain_rule.is_none() {
                return ScopeEvaluation {
                    target: target_input.to_string(),
                    allowed: false,
                    matched_rule: None,
                    reason: format!("Host '{}' does not match any included domains", host),
                };
            }
        }

        // 5. Check Include Path rules if specified
        let path_include_rules: Vec<&&ScopeRule> = active_rules
            .iter()
            .filter(|r| r.rule_type == ScopeRuleType::IncludePath)
            .collect();
        if !path_include_rules.is_empty() {
            let matches_path = path_include_rules
                .iter()
                .any(|r| path.starts_with(&r.pattern));
            if !matches_path {
                return ScopeEvaluation {
                    target: target_input.to_string(),
                    allowed: false,
                    matched_rule: None,
                    reason: format!("Path '{}' does not match any included paths", path),
                };
            }
        }

        ScopeEvaluation {
            target: target_input.to_string(),
            allowed: true,
            matched_rule: matched_domain_rule,
            reason: "Target is within approved scope".to_string(),
        }
    }

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
    use uuid::Uuid;

    #[test]
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
