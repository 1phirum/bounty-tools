//! Safety gate (brief §33).
//!
//! Every generated candidate passes through `SafetyPolicy` before execution.
//! Destructive statements, unbounded resource consumption, and scope
//! violations are blocked *by construction* — the gate is not advisory.

use crate::payload::PayloadCandidate;
use serde::{Deserialize, Serialize};

/// Why a candidate was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// The candidate contains a data-modifying statement.
    DestructiveStatement(String),
    /// The candidate contains a schema-modifying statement.
    SchemaModification(String),
    /// The candidate could consume unbounded resources.
    UnboundedResource(String),
    /// The candidate attempts to read credentials.
    CredentialAccess(String),
    /// The payload exceeds the size cap.
    PayloadTooLarge(usize),
    /// The technique is not permitted at the current safety level.
    TechniqueNotPermitted(String),
}

impl RejectionReason {
    pub fn label(&self) -> String {
        match self {
            Self::DestructiveStatement(s) => format!("destructive statement: {s}"),
            Self::SchemaModification(s) => format!("schema modification: {s}"),
            Self::UnboundedResource(s) => format!("unbounded resource: {s}"),
            Self::CredentialAccess(s) => format!("credential access: {s}"),
            Self::PayloadTooLarge(n) => format!("payload too large ({n} bytes)"),
            Self::TechniqueNotPermitted(t) => format!("technique not permitted: {t}"),
        }
    }
}

/// The result of evaluating a candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyVerdict {
    Permitted,
    Rejected(RejectionReason),
}

/// How permissive the gate is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyLevel {
    /// Detection only: no stacked statements, no time delays beyond a small cap.
    Detection,
    /// Adds timing probes and union column probing.
    Controlled,
    /// Adds stacked-query *detection* (benign statements only).
    Extended,
}

/// The policy applied to every candidate.
#[derive(Debug, Clone)]
pub struct SafetyPolicy {
    pub level: SafetyLevel,
    /// Maximum delay seconds a timing payload may request.
    pub max_delay_seconds: u32,
    /// Maximum payload byte length.
    pub max_payload_bytes: usize,
    /// Maximum UNION column count to probe.
    pub max_union_columns: usize,
}

impl Default for SafetyPolicy {
    fn default() -> Self {
        Self {
            level: SafetyLevel::Detection,
            max_delay_seconds: 10,
            max_payload_bytes: 4096,
            max_union_columns: 10,
        }
    }
}

/// Statement keywords that modify data or schema. Checked case-insensitively
/// and word-boundary-aware so `SELECT` is not flagged for containing "EL".
const DESTRUCTIVE: &[&str] = &["DROP", "DELETE", "TRUNCATE", "UPDATE", "INSERT", "REPLACE", "ALTER", "CREATE", "GRANT", "REVOKE", "SHUTDOWN"];
const CREDENTIAL: &[&str] = &["PG_SHADOW", "MYSQL.USER", "MYSQL.USER_PRIV", "SYS.USER$", "INFORMATION_SCHEMA.USER", "XP_CMDSHELL"];

impl SafetyPolicy {
    pub fn new(level: SafetyLevel) -> Self {
        Self {
            level,
            ..Default::default()
        }
    }

    /// Evaluate a candidate. Returns the verdict with a specific reason when
    /// rejected.
    pub fn check(&self, candidate: &PayloadCandidate) -> SafetyVerdict {
        let sql = candidate.rendered.to_uppercase();

        // Size cap.
        if candidate.rendered.len() > self.max_payload_bytes {
            return SafetyVerdict::Rejected(RejectionReason::PayloadTooLarge(
                candidate.rendered.len(),
            ));
        }

        // Destructive / schema-modifying keywords. Word-boundary matched to
        // avoid false positives inside identifiers or other keywords.
        for keyword in DESTRUCTIVE {
            if contains_word(&sql, keyword) {
                let reason = match *keyword {
                    "DROP" | "TRUNCATE" | "ALTER" | "CREATE" => {
                        RejectionReason::SchemaModification(keyword.to_string())
                    }
                    _ => RejectionReason::DestructiveStatement(keyword.to_string()),
                };
                return SafetyVerdict::Rejected(reason);
            }
        }

        // Credential tables.
        for table in CREDENTIAL {
            if sql.contains(table) {
                return SafetyVerdict::Rejected(RejectionReason::CredentialAccess(
                    table.to_string(),
                ));
            }
        }

        // Stacked statements are only permitted at Extended level, and even
        // then only as a benign detection marker.
        let stacked = sql.contains(';') && (sql.contains(";SELECT") || sql.contains(";SELECT 1"));
        if sql.contains(';') && !stacked {
            // A semicolon followed by anything other than the benign marker
            // is refused outright — we never execute a second statement we
            // did not construct.
            if sql.matches(';').count() > 0 && !sql.contains(";SELECT 1") {
                return SafetyVerdict::Rejected(RejectionReason::DestructiveStatement(
                    "stacked statement".into(),
                ));
            }
        }
        if stacked && self.level != SafetyLevel::Extended {
            return SafetyVerdict::Rejected(RejectionReason::TechniqueNotPermitted(
                "stacked query (requires Extended safety level)".into(),
            ));
        }

        // Delay cap.
        if let Some(delay) = extract_delay_seconds(&sql) {
            if delay > self.max_delay_seconds {
                return SafetyVerdict::Rejected(RejectionReason::UnboundedResource(format!(
                    "delay of {delay}s exceeds the {}-second cap",
                    self.max_delay_seconds
                )));
            }
        }

        // UNION column cap.
        if let Some(cols) = extract_union_columns(&candidate.logical_test) {
            if cols > self.max_union_columns {
                return SafetyVerdict::Rejected(RejectionReason::UnboundedResource(format!(
                    "UNION with {cols} columns exceeds the {} cap",
                    self.max_union_columns
                )));
            }
        }

        SafetyVerdict::Permitted
    }

    /// Filter a candidate list, returning (permitted, rejected-with-reasons).
    pub fn partition<'a>(
        &self,
        candidates: &'a [PayloadCandidate],
    ) -> (Vec<&'a PayloadCandidate>, Vec<(&'a PayloadCandidate, RejectionReason)>) {
        let mut permitted = Vec::new();
        let mut rejected = Vec::new();
        for c in candidates {
            match self.check(c) {
                SafetyVerdict::Permitted => permitted.push(c),
                SafetyVerdict::Rejected(reason) => rejected.push((c, reason)),
            }
        }
        (permitted, rejected)
    }
}

/// Word-boundary containment: `word` must appear delimited by non-identifier
/// characters (or string edges).
fn contains_word(haystack_upper: &str, word: &str) -> bool {
    let bytes = haystack_upper.as_bytes();
    let needle = word.as_bytes();
    if needle.len() > bytes.len() {
        return false;
    }
    let is_word_byte = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    for start in 0..=(bytes.len() - needle.len()) {
        if &bytes[start..start + needle.len()] == needle {
            let before_ok = start == 0 || !is_word_byte(bytes[start - 1]);
            let after = start + needle.len();
            let after_ok = after >= bytes.len() || !is_word_byte(bytes[after]);
            if before_ok && after_ok {
                return true;
            }
        }
    }
    false
}

fn extract_delay_seconds(sql_upper: &str) -> Option<u32> {
    for marker in ["SLEEP(", "PG_SLEEP(", "WAITFOR DELAY '0:0:"] {
        if let Some(idx) = sql_upper.find(marker) {
            let rest = &sql_upper[idx + marker.len()..];
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(seconds) = digits.parse::<u32>() {
                return Some(seconds);
            }
        }
    }
    None
}

fn extract_union_columns(logical_test: &str) -> Option<usize> {
    logical_test
        .strip_prefix("UnionProbe{columns:")
        .and_then(|s| s.strip_suffix('}'))
        .and_then(|s| s.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{GenerationContext, QuoteMode};
    use crate::types::ProbeType;

    fn candidate(rendered: &str) -> PayloadCandidate {
        PayloadCandidate {
            id: uuid::Uuid::new_v4(),
            technique: ProbeType::ErrorInjection,
            logical_test: "test".into(),
            rendered: rendered.into(),
            boundary: crate::payload::Boundary::numeric(),
            dialect: None,
            expected_dbms: None,
            rationale: "test".into(),
        }
    }

    #[test]
    fn benign_boolean_payload_is_permitted() {
        let policy = SafetyPolicy::default();
        assert_eq!(policy.check(&candidate(" AND 1=1-- ")), SafetyVerdict::Permitted);
    }

    #[test]
    fn drop_statement_is_rejected() {
        let policy = SafetyPolicy::default();
        let verdict = policy.check(&candidate("; DROP TABLE users-- "));
        assert!(matches!(verdict, SafetyVerdict::Rejected(RejectionReason::SchemaModification(_))));
    }

    #[test]
    fn delete_statement_is_rejected() {
        let policy = SafetyPolicy::default();
        let verdict = policy.check(&candidate("; DELETE FROM users-- "));
        assert!(matches!(verdict, SafetyVerdict::Rejected(RejectionReason::DestructiveStatement(_))));
    }

    #[test]
    fn update_statement_is_rejected() {
        let policy = SafetyPolicy::default();
        assert!(matches!(
            policy.check(&candidate("; UPDATE users SET admin=1-- ")),
            SafetyVerdict::Rejected(_)
        ));
    }

    #[test]
    fn credential_table_is_rejected() {
        let policy = SafetyPolicy::default();
        assert!(matches!(
            policy.check(&candidate("UNION SELECT password FROM MYSQL.USER-- ")),
            SafetyVerdict::Rejected(RejectionReason::CredentialAccess(_))
        ));
    }

    #[test]
    fn excessive_delay_is_rejected() {
        let policy = SafetyPolicy::default();
        assert!(matches!(
            policy.check(&candidate(" AND SLEEP(600)-- ")),
            SafetyVerdict::Rejected(RejectionReason::UnboundedResource(_))
        ));
    }

    #[test]
    fn delay_within_cap_is_permitted() {
        let policy = SafetyPolicy::default();
        assert_eq!(policy.check(&candidate(" AND SLEEP(5)-- ")), SafetyVerdict::Permitted);
    }

    #[test]
    fn word_boundary_avoids_false_positive() {
        // "UPDATE" must not fire on "UPDATED_AT" as an identifier.
        let policy = SafetyPolicy::default();
        assert_eq!(
            policy.check(&candidate(" AND updated_at > 0-- ")),
            SafetyVerdict::Permitted
        );
    }

    #[test]
    fn stacked_requires_extended_level() {
        let detection = SafetyPolicy::new(SafetyLevel::Detection);
        assert!(matches!(
            detection.check(&candidate(";SELECT 1-- ")),
            SafetyVerdict::Rejected(RejectionReason::TechniqueNotPermitted(_))
        ));
        let extended = SafetyPolicy::new(SafetyLevel::Extended);
        assert_eq!(extended.check(&candidate(";SELECT 1-- ")), SafetyVerdict::Permitted);
    }

    #[test]
    fn oversize_payload_rejected() {
        let policy = SafetyPolicy::default();
        let big = "A".repeat(5000);
        assert!(matches!(
            policy.check(&candidate(&big)),
            SafetyVerdict::Rejected(RejectionReason::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn partition_splits_permitted_from_rejected() {
        let policy = SafetyPolicy::default();
        let candidates = vec![
            candidate(" AND 1=1-- "),
            candidate("; DROP TABLE x-- "),
        ];
        let (ok, bad) = policy.partition(&candidates);
        assert_eq!(ok.len(), 1);
        assert_eq!(bad.len(), 1);
    }

    #[test]
    fn generated_boolean_candidates_all_pass_default_policy() {
        let policy = SafetyPolicy::default();
        let ctx = GenerationContext {
            quote_mode: QuoteMode::None,
            dbms_hypothesis: None,
            clause_hint: None,
            original_value: "1".into(),
        };
        for c in crate::payload::generate_boolean(&ctx) {
            assert_eq!(
                policy.check(&c),
                SafetyVerdict::Permitted,
                "generated candidate was rejected: {}",
                c.rendered
            );
        }
    }

    #[test]
    fn union_column_cap_enforced() {
        let mut policy = SafetyPolicy::default();
        policy.max_union_columns = 2;
        let mut c = candidate("UNION SELECT NULL,NULL,NULL-- ");
        c.logical_test = "UnionProbe{columns:3}".into();
        assert!(matches!(
            policy.check(&c),
            SafetyVerdict::Rejected(RejectionReason::UnboundedResource(_))
        ));
    }
}
