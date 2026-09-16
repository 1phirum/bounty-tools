//! Program-policy layer — encodes *any* bug bounty program's stated rules so
//! BugTools operates within them rather than merely being technically able to
//! scan.
//!
//! This is deliberately data-driven and program-agnostic: a policy is loaded
//! from a TOML file the researcher supplies, so the tool is never tied to one
//! program. Nothing here is advisory — a policy either permits a run or it
//! does not.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("target host '{host}' is out of scope for this program")]
    OutOfScope { host: String },
    #[error("scanner activity is prohibited by this program's rules")]
    ScannerProhibited,
    #[error("rate {rate}/s exceeds the program's maximum of {max}/s")]
    RateExceeded { rate: f32, max: f32 },
    #[error("a researcher identity header is required by this program but none was supplied")]
    IdentityRequired,
    #[error("cannot read policy file {path}: {reason}")]
    FileUnreadable { path: String, reason: String },
    #[error("policy file {path} is invalid TOML: {reason}")]
    FileInvalid { path: String, reason: String },
}

/// A program's rules as the engine must respect them.
///
/// Every field has a conservative default so a minimal policy file still works;
/// unspecified constraints take the safest value, not the most permissive.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramPolicy {
    pub name: String,
    /// Hosts that are in scope (exact or wildcard `*.example.com`).
    #[serde(default)]
    pub in_scope: Vec<String>,
    /// Hosts explicitly excluded. These always win over `in_scope`.
    #[serde(default)]
    pub out_of_scope: Vec<String>,
    /// Maximum sustained request rate per second.
    #[serde(default = "default_rate")]
    pub max_rate_per_second: f32,
    /// Maximum concurrent requests.
    #[serde(default = "default_concurrency")]
    pub max_concurrency: usize,
    /// Whether automated scanning is allowed at all. Defaults to `false` so a
    /// policy that does not state otherwise is treated as scanner-free
    /// (matching programs that prohibit automation). Set `true` to enable.
    #[serde(default)]
    pub scanners_allowed: bool,
    /// A header the researcher must send, as `[name, value]`.
    #[serde(default)]
    pub identity_header: Option<(String, String)>,
    /// Finding categories the program excludes outright.
    #[serde(default)]
    pub excluded_finding_kinds: Vec<String>,
    /// Free-text notes shown to the researcher before a run.
    #[serde(default)]
    pub notes: Vec<String>,
}

fn default_rate() -> f32 {
    2.0
}

fn default_concurrency() -> usize {
    2
}

impl ProgramPolicy {
    /// Parse a policy from TOML text.
    pub fn from_toml(text: &str) -> Result<Self, PolicyError> {
        toml::from_str(text).map_err(|e| PolicyError::FileInvalid {
            path: "<inline>".into(),
            reason: e.to_string(),
        })
    }

    /// Load a policy from a file path.
    pub fn from_file(path: &str) -> Result<Self, PolicyError> {
        let text = std::fs::read_to_string(path).map_err(|e| PolicyError::FileUnreadable {
            path: path.to_string(),
            reason: e.to_string(),
        })?;
        toml::from_str(&text).map_err(|e| PolicyError::FileInvalid {
            path: path.to_string(),
            reason: e.to_string(),
        })
    }

    /// Whether `host` is in scope. Out-of-scope entries always win.
    ///
    /// An empty `in_scope` list means "nothing is authorized" — the engine
    /// fails closed rather than scanning everything.
    pub fn allows_host(&self, host: &str) -> bool {
        let host = host.to_lowercase();
        for excl in &self.out_of_scope {
            if host_matches(excl, &host) {
                return false;
            }
        }
        self.in_scope.iter().any(|inc| host_matches(inc, &host))
    }

    /// Validate a planned run against the policy. Fails closed.
    pub fn validate_run(
        &self,
        rate: f32,
        concurrency: usize,
        headers_present: bool,
    ) -> Result<(), PolicyError> {
        if !self.scanners_allowed {
            return Err(PolicyError::ScannerProhibited);
        }
        if rate > self.max_rate_per_second {
            return Err(PolicyError::RateExceeded {
                rate,
                max: self.max_rate_per_second,
            });
        }
        if concurrency > self.max_concurrency {
            return Err(PolicyError::RateExceeded {
                rate: concurrency as f32,
                max: self.max_concurrency as f32,
            });
        }
        if self.identity_header.is_some() && !headers_present {
            return Err(PolicyError::IdentityRequired);
        }
        Ok(())
    }

    /// Whether a finding kind is reportable under this program.
    pub fn finding_reportable(&self, kind: &str) -> bool {
        !self
            .excluded_finding_kinds
            .iter()
            .any(|k| k.eq_ignore_ascii_case(kind))
    }

    /// A concise summary for the console.
    pub fn summary(&self) -> String {
        format!(
            "{} — {} in-scope pattern(s), {} excluded host(s), {} req/s, {} concurrent, scanners {}",
            self.name,
            self.in_scope.len(),
            self.out_of_scope.len(),
            self.max_rate_per_second,
            self.max_concurrency,
            if self.scanners_allowed {
                "allowed"
            } else {
                "PROHIBITED"
            }
        )
    }
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_lowercase();
    if pattern == host {
        return true;
    }
    if let Some(base) = pattern.strip_prefix("*.") {
        return host == base || host.ends_with(&format!(".{base}"));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ProgramPolicy {
        ProgramPolicy::from_toml(
            r#"
name = "Example Program"
in_scope = ["example.com", "*.example.com"]
out_of_scope = ["admin.example.com"]
max_rate_per_second = 3.0
max_concurrency = 4
scanners_allowed = true
excluded_finding_kinds = ["rate limiting", "user enumeration"]
notes = ["Use your researcher alias."]
"#,
        )
        .unwrap()
    }

    #[test]
    fn parses_a_policy_from_toml() {
        let p = sample();
        assert_eq!(p.name, "Example Program");
        assert_eq!(p.max_rate_per_second, 3.0);
        assert_eq!(p.max_concurrency, 4);
    }

    #[test]
    fn scope_includes_wildcard_subdomains() {
        let p = sample();
        assert!(p.allows_host("example.com"));
        assert!(p.allows_host("api.example.com"));
        assert!(p.allows_host("deep.api.example.com"));
    }

    #[test]
    fn out_of_scope_wins_over_wildcard() {
        let p = sample();
        assert!(!p.allows_host("admin.example.com"));
    }

    #[test]
    fn unrelated_hosts_are_out_of_scope() {
        let p = sample();
        assert!(!p.allows_host("evil.test"));
        assert!(!p.allows_host("example.com.evil.test"));
    }

    #[test]
    fn empty_scope_fails_closed() {
        let p = ProgramPolicy::from_toml(r#"name = "Empty""#).unwrap();
        assert!(!p.allows_host("anything.test"));
    }

    #[test]
    fn scanners_default_to_prohibited() {
        // A policy that does not say scanners are allowed must refuse.
        let p = ProgramPolicy::from_toml(r#"name = "Strict""#).unwrap();
        assert!(!p.scanners_allowed);
        assert!(matches!(
            p.validate_run(1.0, 1, true),
            Err(PolicyError::ScannerProhibited)
        ));
    }

    #[test]
    fn rate_and_concurrency_enforced() {
        let p = sample();
        assert!(p.validate_run(3.0, 4, true).is_ok());
        assert!(matches!(
            p.validate_run(9.0, 4, true),
            Err(PolicyError::RateExceeded { .. })
        ));
        assert!(matches!(
            p.validate_run(1.0, 99, true),
            Err(PolicyError::RateExceeded { .. })
        ));
    }

    #[test]
    fn identity_header_required_when_declared() {
        let p = ProgramPolicy::from_toml(
            r#"
name = "ID Required"
scanners_allowed = true
identity_header = ["X-Bug-Bounty", "hunter"]
"#,
        )
        .unwrap();
        assert!(matches!(
            p.validate_run(1.0, 1, false),
            Err(PolicyError::IdentityRequired)
        ));
        assert!(p.validate_run(1.0, 1, true).is_ok());
    }

    #[test]
    fn excluded_kinds_are_not_reportable() {
        let p = sample();
        assert!(!p.finding_reportable("rate limiting"));
        assert!(!p.finding_reportable("user enumeration"));
        assert!(p.finding_reportable("sql injection"));
        assert!(p.finding_reportable("xss"));
        assert!(p.finding_reportable("stored xss"));
        assert!(p.finding_reportable("sqli"));
    }

    #[test]
    fn unknown_field_is_rejected() {
        assert!(ProgramPolicy::from_toml(
            r#"name = "x"
bogus_field = 1"#
        )
        .is_err());
    }

    #[test]
    fn summary_is_readable() {
        let s = sample().summary();
        assert!(s.contains("Example Program"));
        assert!(s.contains("allowed"));
    }
}
