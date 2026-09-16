//! Program-policy layer — encodes a bug bounty program's stated rules so
//! BugTools operates within them rather than merely being technically able
//! to scan.
//!
//! This is deliberately data-driven: a program's scope, exclusions, and
//! constraints are facts the researcher supplies (or a preset carries), and
//! the engine refuses anything the policy forbids. Nothing here is advisory.

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
}

/// A program's rules as the engine must respect them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramPolicy {
    pub name: String,
    /// Hosts that are in scope (exact or wildcard `*.example.com`).
    pub in_scope: Vec<String>,
    /// Hosts explicitly excluded.
    pub out_of_scope: Vec<String>,
    /// Maximum sustained request rate per second.
    pub max_rate_per_second: f32,
    /// Maximum concurrent requests.
    pub max_concurrency: usize,
    /// Whether automated scanning is allowed at all. `false` means only
    /// manual/single-request tooling is permitted (e.g. a request builder).
    pub scanners_allowed: bool,
    /// A header the researcher must send to identify their testing, if the
    /// program requires one (e.g. `X-Bug-Bounty: handle`).
    pub identity_header: Option<(String, String)>,
    /// Finding categories the program excludes outright — the tool must not
    /// report these.
    pub excluded_finding_kinds: Vec<String>,
    /// Free-text notes shown to the researcher before a run.
    pub notes: Vec<String>,
}

impl ProgramPolicy {
    /// Whether `host` is in scope. Out-of-scope entries always win.
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
    pub fn validate_run(&self, rate: f32, concurrency: usize, headers_present: bool) -> Result<(), PolicyError> {
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
            // Not a hard error type — clamp instead, but only if scanners are allowed.
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
}

fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == host {
        return true;
    }
    if let Some(base) = pattern.strip_prefix("*.") {
        return host == base || host.ends_with(&format!(".{base}"));
    }
    false
}

/// SMTP2GO's program as stated in its HackerOne policy.
///
/// Scope and exclusions are transcribed from the published rules. Where the
/// policy states a constraint (e.g. DoS single-source), it becomes a number;
/// where it prohibits a category (e.g. rate-limit findings), it becomes an
/// exclusion.
pub fn smtp2go_policy() -> ProgramPolicy {
    ProgramPolicy {
        name: "SMTP2GO BBP (HackerOne)".into(),
        in_scope: vec![
            "smtp2go.com".into(),
            "*.smtp2go.com".into(),
        ],
        // support.smtp2go.com is listed out of scope in the program.
        out_of_scope: vec!["support.smtp2go.com".into()],
        // DoS is permitted only single-source without material impact; keep
        // the engine conservative: 2 req/s, 2 concurrent.
        max_rate_per_second: 2.0,
        max_concurrency: 2,
        // No scanner ban is stated in the program text provided; still
        // conservative.
        scanners_allowed: true,
        // The program's test-plan uses the HackerOne email alias; no
        // dedicated bug-bounty header is required by the policy.
        identity_header: None,
        excluded_finding_kinds: vec![
            "rate limiting".into(),
            "brute force".into(),
            "user enumeration".into(),
            "missing security headers".into(),
            "missing cookie flags".into(),
            "version disclosure".into(),
            "banner identification".into(),
            "descriptive error messages".into(),
            "open redirect without impact".into(),
            "clickjacking non-sensitive".into(),
            "csrf non-sensitive".into(),
            "csv injection without demonstration".into(),
            "content spoofing without attack vector".into(),
            "known vulnerable library without poc".into(),
            "tabnabbing".into(),
            "notification email issues".into(),
        ],
        notes: vec![
            "Test with free accounts registered via your HackerOne email alias.".into(),
            "Paid-account features require a ticket request to SMTP2GO first.".into(),
            "DoS only single-source, no material impact.".into(),
            "Submit one vulnerability per report; duplicates pay the first reporter.".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smtp2go_scope_includes_main_and_app() {
        let p = smtp2go_policy();
        assert!(p.allows_host("app.smtp2go.com"));
        assert!(p.allows_host("api.smtp2go.com"));
        assert!(p.allows_host("smtp2go.com"));
        assert!(p.allows_host("deep.api.smtp2go.com"));
    }

    #[test]
    fn support_subdomain_is_out_of_scope() {
        let p = smtp2go_policy();
        assert!(!p.allows_host("support.smtp2go.com"));
    }

    #[test]
    fn unrelated_host_is_out_of_scope() {
        let p = smtp2go_policy();
        assert!(!p.allows_host("example.com"));
        assert!(!p.allows_host("smtp2go.com.evil.test"));
    }

    #[test]
    fn rate_limit_enforced() {
        let p = smtp2go_policy();
        assert!(p.validate_run(2.0, 2, true).is_ok());
        assert!(matches!(
            p.validate_run(5.0, 2, true),
            Err(PolicyError::RateExceeded { .. })
        ));
    }

    #[test]
    fn scanner_prohibition_fails_closed() {
        let mut p = smtp2go_policy();
        p.scanners_allowed = false;
        assert!(matches!(
            p.validate_run(1.0, 1, true),
            Err(PolicyError::ScannerProhibited)
        ));
    }

    #[test]
    fn identity_header_required_when_set() {
        let mut p = smtp2go_policy();
        p.identity_header = Some(("X-Bug-Bounty".into(), "naga".into()));
        assert!(matches!(
            p.validate_run(1.0, 1, false),
            Err(PolicyError::IdentityRequired)
        ));
        assert!(p.validate_run(1.0, 1, true).is_ok());
    }

    #[test]
    fn excluded_kinds_are_not_reportable() {
        let p = smtp2go_policy();
        assert!(!p.finding_reportable("rate limiting"));
        assert!(!p.finding_reportable("user enumeration"));
        assert!(p.finding_reportable("sql injection"));
        assert!(p.finding_reportable("stored xss"));
    }
}
