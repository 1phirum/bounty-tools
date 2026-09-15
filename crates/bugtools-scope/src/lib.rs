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
        let decision = |allowed, matched_rule, reason: &str| ScopeEvaluation {
            target: target_input.to_string(),
            allowed,
            matched_rule,
            reason: reason.to_string(),
        };
        let (protocol, host, port, path) = match self.parse_target(target_input) {
            Ok(target) => target,
            Err(error) => return decision(false, None, &error.to_string()),
        };
        let rules = match self.rules.read() {
            Ok(rules) => rules,
            Err(_) => return decision(false, None, "Scope rules unavailable"),
        };

        let mut domain_match = None;
        let mut has_paths = false;
        let mut path_match = false;
        let mut has_ports = false;
        let mut port_match = false;
        let mut has_protocols = false;
        let mut protocol_match = false;

        // Exclusions always win, regardless of rule order. Includes for paths,
        // ports and protocols restrict included hosts; they never grant access
        // to an otherwise unlisted host. Within each dimension, includes OR.
        for rule in rules.iter().filter(|rule| rule.enabled) {
            let matches = match rule.rule_type {
                ScopeRuleType::IncludeDomain | ScopeRuleType::ExcludeDomain => {
                    if rule.pattern.is_empty() || rule.pattern == "*." {
                        return decision(false, Some(rule.pattern.clone()), "Invalid domain rule");
                    }
                    self.domain_matches(&host, &rule.pattern)
                }
                ScopeRuleType::IncludePath | ScopeRuleType::ExcludePath => {
                    if !rule.pattern.starts_with('/') {
                        return decision(false, Some(rule.pattern.clone()), "Invalid path rule");
                    }
                    path.starts_with(&rule.pattern)
                }
                ScopeRuleType::IncludePort | ScopeRuleType::ExcludePort => {
                    match rule.pattern.parse::<u16>() {
                        Ok(rule_port) if rule_port != 0 => port == rule_port,
                        _ => {
                            return decision(false, Some(rule.pattern.clone()), "Invalid port rule")
                        }
                    }
                }
                ScopeRuleType::Protocol => {
                    if !rule.pattern.eq_ignore_ascii_case("http")
                        && !rule.pattern.eq_ignore_ascii_case("https")
                    {
                        return decision(
                            false,
                            Some(rule.pattern.clone()),
                            "Invalid protocol rule",
                        );
                    }
                    protocol.eq_ignore_ascii_case(&rule.pattern)
                }
            };
            match rule.rule_type {
                ScopeRuleType::ExcludeDomain
                | ScopeRuleType::ExcludePath
                | ScopeRuleType::ExcludePort => {
                    if matches {
                        return decision(
                            false,
                            Some(rule.pattern.clone()),
                            "Matched exclusion rule",
                        );
                    }
                }
                ScopeRuleType::IncludeDomain => {
                    if matches {
                        domain_match = Some(rule.pattern.clone());
                    }
                }
                ScopeRuleType::IncludePath => {
                    has_paths = true;
                    path_match |= matches;
                }
                ScopeRuleType::IncludePort => {
                    has_ports = true;
                    port_match |= matches;
                }
                ScopeRuleType::Protocol => {
                    has_protocols = true;
                    protocol_match |= matches;
                }
            }
        }
        if domain_match.is_none() {
            return decision(false, None, "No enabled domain inclusion matched");
        }
        if (has_paths && !path_match)
            || (has_ports && !port_match)
            || (has_protocols && !protocol_match)
        {
            return decision(false, None, "Target does not satisfy scope restrictions");
        }
        decision(
            true,
            domain_match,
            "Matched domain inclusion and scope restrictions",
        )
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

    fn parse_target(
        &self,
        target_input: &str,
    ) -> Result<(String, String, u16, String), ScopeError> {
        let target_str = if !target_input.contains("://") {
            format!("https://{}", target_input)
        } else {
            target_input.to_string()
        };

        let parsed =
            Url::parse(&target_str).map_err(|e| ScopeError::InvalidTarget(e.to_string()))?;

        let protocol = parsed.scheme().to_lowercase();
        if protocol != "http" && protocol != "https" {
            return Err(ScopeError::InvalidTarget(
                "Only HTTP and HTTPS are supported".to_string(),
            ));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| ScopeError::InvalidTarget("Missing host".to_string()))?
            .to_string();

        let port = parsed
            .port_or_known_default()
            .unwrap_or(if protocol == "https" { 443 } else { 80 });

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
    fn default_deny_and_disabled_rules() {
        assert!(!ScopeEngine::new().evaluate("https://example.com").allowed);
        let mut rule = ScopeRule::new(Uuid::new_v4(), ScopeRuleType::IncludeDomain, "example.com");
        rule.enabled = false;
        assert!(
            !ScopeEngine::with_rules(vec![rule])
                .evaluate("https://example.com")
                .allowed
        );
    }

    #[test]
    fn exclusions_win_in_either_order() {
        for (kind, pattern) in [
            (ScopeRuleType::ExcludeDomain, "example.com"),
            (ScopeRuleType::ExcludePath, "/private"),
            (ScopeRuleType::ExcludePort, "443"),
        ] {
            let id = Uuid::new_v4();
            let mut rules = vec![
                ScopeRule::new(id, ScopeRuleType::IncludeDomain, "example.com"),
                ScopeRule::new(id, kind, pattern),
            ];
            for _ in 0..2 {
                let result = ScopeEngine::with_rules(rules.clone())
                    .evaluate("https://example.com/private/data");
                assert!(!result.allowed);
                assert_eq!(result.matched_rule.as_deref(), Some(pattern));
                rules.reverse();
            }
        }
    }

    #[test]
    fn inclusion_dimensions_restrict_domains_without_authorizing_other_hosts() {
        let id = Uuid::new_v4();
        let restrictions = vec![
            ScopeRule::new(id, ScopeRuleType::IncludePath, "/api"),
            ScopeRule::new(id, ScopeRuleType::IncludePort, "443"),
            ScopeRule::new(id, ScopeRuleType::Protocol, "https"),
        ];
        let engine = ScopeEngine::with_rules(restrictions);
        assert!(!engine.evaluate("https://example.com/api").allowed);
        engine.add_rule(ScopeRule::new(
            id,
            ScopeRuleType::IncludeDomain,
            "example.com",
        ));
        assert!(engine.evaluate("https://example.com/api/users").allowed);
        for target in [
            "https://other.com/api",
            "https://example.com/private",
            "https://example.com:8443/api",
            "http://example.com:443/api",
            "ftp://example.com/api",
            "https://",
            "https://example.com.attacker.com/api",
        ] {
            assert!(
                !engine.evaluate(target).allowed,
                "unexpectedly allowed {target}"
            );
        }
        engine.add_rule(ScopeRule::new(id, ScopeRuleType::ExcludePort, "invalid"));
        assert!(!engine.evaluate("https://example.com/api").allowed);
    }

    #[test]
    fn poisoned_rules_fail_closed() {
        let engine = ScopeEngine::with_rules(vec![ScopeRule::new(
            Uuid::new_v4(),
            ScopeRuleType::IncludeDomain,
            "example.com",
        )]);
        let _ = std::panic::catch_unwind(|| {
            let _guard = engine.rules.write().unwrap();
            panic!("poison scope lock");
        });
        assert!(!engine.evaluate("https://example.com").allowed);
    }

    #[test]
    fn test_scope_wildcard_domain() {
        let project_id = Uuid::new_v4();
        let rules = vec![
            ScopeRule::new(project_id, ScopeRuleType::IncludeDomain, "*.example.com"),
            ScopeRule::new(
                project_id,
                ScopeRuleType::ExcludeDomain,
                "admin.example.com",
            ),
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
