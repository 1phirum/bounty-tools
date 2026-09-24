use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Canonical DBMS families we can detect and map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DbmsFamily {
    MySQL,
    MariaDB,
    PostgreSQL,
    MSSQL,
    Oracle,
    SQLite,
    DB2,
    H2,
}

impl DbmsFamily {
    pub const ALL: &[DbmsFamily] = &[
        DbmsFamily::MySQL,
        DbmsFamily::MariaDB,
        DbmsFamily::PostgreSQL,
        DbmsFamily::MSSQL,
        DbmsFamily::Oracle,
        DbmsFamily::SQLite,
        DbmsFamily::DB2,
        DbmsFamily::H2,
    ];

    /// Stable precedence ordinal (position in `ALL`). Used only as a
    /// deterministic tie-break when two families score equally — it does
    /// not express any real preference between engines.
    pub fn rank_ordinal(&self) -> usize {
        Self::ALL
            .iter()
            .position(|d| d == self)
            .unwrap_or(usize::MAX)
    }

    pub fn label(&self) -> &'static str {
        match self {
            DbmsFamily::MySQL => "MySQL",
            DbmsFamily::MariaDB => "MariaDB",
            DbmsFamily::PostgreSQL => "PostgreSQL",
            DbmsFamily::MSSQL => "Microsoft SQL Server",
            DbmsFamily::Oracle => "Oracle Database",
            DbmsFamily::SQLite => "SQLite",
            DbmsFamily::DB2 => "IBM Db2",
            DbmsFamily::H2 => "H2 Database",
        }
    }

    pub fn display_name(&self) -> String {
        format!("{}", self.label())
    }
}

/// A single detection signal — a regex/needle pattern mapped to a
/// specific DBMS with a confidence contribution.
#[derive(Debug, Clone)]
pub struct DetectionSignal {
    /// Human label for UI display.
    pub label: &'static str,
    /// Lowercased needle to search in error text. Matching is
    /// case-insensitive substring on lowercased bodies.
    pub needle: &'static str,
    /// The DBMS this signal implicates.
    pub dbms: DbmsFamily,
    /// Confidence points added when this signal fires (0–100).
    pub weight: u32,
    /// Signal source category for the UI breakdown.
    pub category: SignalCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalCategory {
    ErrorPattern,
    DriverName,
    SyntaxFeature,
    FunctionPresence,
    CatalogTable,
    VersionBanner,
}

/// The complete, curated detection signal library. Each entry is a
/// real, observed error string, driver name, or syntax artifact from
/// production databases. No guessed patterns — only signatures we can
/// cite from actual DBMS behavior.
pub const DETECTION_SIGNALS: &[DetectionSignal] = &[
    // ── MySQL / MariaDB (share the wire protocol; distinct error phrasing) ──
    DetectionSignal {
        label: "MySQL syntax error preamble",
        needle: "check the manual that corresponds to your mysql server version",
        dbms: DbmsFamily::MySQL,
        weight: 45,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "MariaDB syntax error preamble",
        needle: "check the manual that corresponds to your mariadb server version",
        dbms: DbmsFamily::MariaDB,
        weight: 45,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "MySQL Connector/J exception",
        needle: "com.mysql.jdbc.exceptions",
        dbms: DbmsFamily::MySQL,
        weight: 40,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "MySqlException (.NET)",
        needle: "mysqlexception",
        dbms: DbmsFamily::MySQL,
        weight: 40,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "MySQL result keyword",
        needle: "valid mysql result",
        dbms: DbmsFamily::MySQL,
        weight: 35,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "MariaDB client error",
        needle: "mariadb server version",
        dbms: DbmsFamily::MariaDB,
        weight: 30,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "MySQLi driver error",
        needle: "mysqli",
        dbms: DbmsFamily::MySQL,
        weight: 30,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "PDO MySQL exception",
        needle: "pdo exception occurred: sqlstate[42000]",
        dbms: DbmsFamily::MySQL,
        weight: 35,
        category: SignalCategory::DriverName,
    },

    // ── PostgreSQL ──
    DetectionSignal {
        label: "pg_query() driver failure",
        needle: "pg_query(): query failed:",
        dbms: DbmsFamily::PostgreSQL,
        weight: 50,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "psycopg2 errors module",
        needle: "psycopg2.errors",
        dbms: DbmsFamily::PostgreSQL,
        weight: 45,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "PostgreSQL PSQLException",
        needle: "org.postgresql.util.psqlexception",
        dbms: DbmsFamily::PostgreSQL,
        weight: 45,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "PostgreSQL syntax error phrasing",
        needle: "syntax error at or near",
        dbms: DbmsFamily::PostgreSQL,
        weight: 35,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "PostgreSQL unterminated string",
        needle: "unterminated quoted string at or near",
        dbms: DbmsFamily::PostgreSQL,
        weight: 40,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "PostgreSQL system catalog",
        needle: "pg_catalog.",
        dbms: DbmsFamily::PostgreSQL,
        weight: 30,
        category: SignalCategory::CatalogTable,
    },
    DetectionSignal {
        label: "PostgreSQL pg_sleep",
        needle: "pg_sleep",
        dbms: DbmsFamily::PostgreSQL,
        weight: 35,
        category: SignalCategory::FunctionPresence,
    },

    // ── Microsoft SQL Server ──
    DetectionSignal {
        label: "ODBC SQL Server driver",
        needle: "driver][sql server]",
        dbms: DbmsFamily::MSSQL,
        weight: 45,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "OLE DB provider for SQL Server",
        needle: "microsoft ole db provider for sql server",
        dbms: DbmsFamily::MSSQL,
        weight: 45,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "MSSQL unclosed quotation mark",
        needle: "unclosed quotation mark after the character string",
        dbms: DbmsFamily::MSSQL,
        weight: 40,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        // Canonical MSSQL message is `Incorrect syntax near 'X'.` — the older
        // needle demanded a `Line 1: ` prefix that most responses don't carry,
        // so genuine MSSQL errors were being missed.
        label: "MSSQL incorrect syntax near",
        needle: "incorrect syntax near",
        dbms: DbmsFamily::MSSQL,
        weight: 40,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "MSSQL SqlException",
        needle: "system.data.sqlclient.sqlexception",
        dbms: DbmsFamily::MSSQL,
        weight: 40,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "MSSQL @@version (shared with MySQL — weak)",
        needle: "@@version",
        dbms: DbmsFamily::MSSQL,
        weight: 12,
        category: SignalCategory::SyntaxFeature,
    },
    DetectionSignal {
        label: "MSSQL SELECT TOP",
        needle: "select top ",
        dbms: DbmsFamily::MSSQL,
        weight: 15,
        category: SignalCategory::SyntaxFeature,
    },

    // ── Oracle Database ──
    DetectionSignal {
        label: "Oracle quoted string not terminated",
        needle: "ora-01756: quoted string not properly terminated",
        dbms: DbmsFamily::Oracle,
        weight: 50,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "Oracle SQL command not ended",
        needle: "ora-00933: sql command not properly ended",
        dbms: DbmsFamily::Oracle,
        weight: 45,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "Oracle missing right parenthesis",
        needle: "ora-00907: missing right parenthesis",
        dbms: DbmsFamily::Oracle,
        weight: 45,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "Oracle FROM keyword missing",
        needle: "ora-00923: from keyword not found",
        dbms: DbmsFamily::Oracle,
        weight: 45,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "Oracle invalid identifier",
        needle: "ora-00904: invalid identifier",
        dbms: DbmsFamily::Oracle,
        weight: 40,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "Oracle TNS listener",
        needle: "tns:",
        dbms: DbmsFamily::Oracle,
        weight: 35,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "Oracle FROM DUAL",
        needle: "from dual",
        dbms: DbmsFamily::Oracle,
        weight: 25,
        category: SignalCategory::CatalogTable,
    },
    DetectionSignal {
        label: "Oracle ROWNUM",
        needle: "rownum",
        dbms: DbmsFamily::Oracle,
        weight: 20,
        category: SignalCategory::SyntaxFeature,
    },

    // ── SQLite ──
    DetectionSignal {
        label: "SQLite3 OperationalError (Python)",
        needle: "sqlite3.operationalerror",
        dbms: DbmsFamily::SQLite,
        weight: 50,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "SQLite error prefix",
        needle: "sqlite_error",
        dbms: DbmsFamily::SQLite,
        weight: 45,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "SQLite unrecognized token",
        needle: "unrecognized token:",
        dbms: DbmsFamily::SQLite,
        weight: 45,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        // "incomplete input" is a real SQLite parser error but also ordinary
        // form-validation English, so it only corroborates — never enough on
        // its own to name SQLite.
        label: "SQLite incomplete input",
        needle: "incomplete input",
        dbms: DbmsFamily::SQLite,
        weight: 25,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        // SQLite reports `near "TOKEN": syntax error`. Match the literal
        // closing-quote + `: syntax error` shape — this is a plain substring
        // matcher, so a regex needle like `.*` would never fire. The leading
        // quote keeps this off PostgreSQL/H2 errors, which say `error: syntax
        // error ...` / `exception: syntax error ...` (no quote before the
        // colon).
        label: "SQLite quoted-token syntax error",
        needle: "\": syntax error",
        dbms: DbmsFamily::SQLite,
        weight: 40,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "SQLite version function",
        needle: "sqlite_version()",
        dbms: DbmsFamily::SQLite,
        weight: 30,
        category: SignalCategory::FunctionPresence,
    },
    DetectionSignal {
        label: "SQLite sqlite_master table",
        needle: "sqlite_master",
        dbms: DbmsFamily::SQLite,
        weight: 30,
        category: SignalCategory::CatalogTable,
    },
];

/// Compute the detection verdict for a response body. Pure function —
/// no network I/O. Returns every signal that fired, grouped by DBMS
/// with aggregated confidence.
pub fn analyze_error_body(body: &str) -> DbmsDetectionResult {
    let lower = body.to_lowercase();
    let mut signals: Vec<FiredSignal> = Vec::new();
    let mut scores: HashMap<DbmsFamily, u32> = HashMap::new();

    for signal in DETECTION_SIGNALS
        .iter()
        .chain(crate::dbms_ext::DB2_SIGNALS.iter())
        .chain(crate::dbms_ext::H2_SIGNALS.iter())
    {
        if lower.contains(signal.needle) {
            let score = scores.entry(signal.dbms).or_insert(0);
            *score = (*score + signal.weight).min(100);
            signals.push(FiredSignal {
                label: signal.label.to_string(),
                needle: signal.needle.to_string(),
                dbms: signal.dbms,
                weight: signal.weight,
                category: signal.category,
            });
        }
    }

    // Rank DBMS by confidence, highest first. `scores` comes from a HashMap,
    // so ties would otherwise resolve in nondeterministic iteration order and
    // the "detected" winner could flip run-to-run on the same body. Break ties
    // by the family's stable ordinal so the verdict is reproducible.
    let mut ranked: Vec<(DbmsFamily, u32)> = scores.into_iter().collect();
    ranked.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| a.0.rank_ordinal().cmp(&b.0.rank_ordinal()))
    });

    let (winner, winner_confidence) = ranked
        .first()
        .map(|(d, s)| (Some(*d), *s))
        .unwrap_or((None, 0));

    let runner_up = ranked.get(1).map(|(d, s)| (*d, *s));

    DbmsDetectionResult {
        detected_dbms: winner,
        confidence: winner_confidence,
        runner_up,
        signals,
        verdict: if winner.is_some() {
            if winner_confidence >= 80 {
                DetectionVerdict::HighConfidence
            } else if winner_confidence >= 50 {
                DetectionVerdict::MediumConfidence
            } else {
                DetectionVerdict::LowConfidence
            }
        } else {
            DetectionVerdict::NoSignal
        },
    }
}

/// One signal that fired during detection, with metadata for the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiredSignal {
    pub label: String,
    pub needle: String,
    pub dbms: DbmsFamily,
    pub weight: u32,
    pub category: SignalCategory,
}

/// Overall detection outcome for a response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbmsDetectionResult {
    pub detected_dbms: Option<DbmsFamily>,
    pub confidence: u32,
    pub runner_up: Option<(DbmsFamily, u32)>,
    pub signals: Vec<FiredSignal>,
    pub verdict: DetectionVerdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionVerdict {
    /// No DBMS-specific signals found — cannot determine.
    NoSignal,
    /// Some signal found but below the medium threshold.
    LowConfidence,
    /// Moderate signal strength.
    MediumConfidence,
    /// Strong, corroborated signal — high confidence in the result.
    HighConfidence,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_mysql_from_error() {
        let body = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1";
        let result = analyze_error_body(body);
        assert_eq!(result.detected_dbms, Some(DbmsFamily::MySQL));
        assert!(result.confidence >= 45);
        assert!(result.signals.len() >= 1);
    }

    #[test]
    fn detects_postgres_from_psycopg2() {
        let body = "psycopg2.errors.SyntaxError: syntax error at or near \"''\"\nLINE 1: SELECT * FROM users WHERE id = ''";
        let result = analyze_error_body(body);
        assert_eq!(result.detected_dbms, Some(DbmsFamily::PostgreSQL));
        assert!(result.confidence >= 45);
    }

    #[test]
    fn detects_oracle_from_ora_code() {
        let body = "ORA-01756: quoted string not properly terminated\nORA-00933: SQL command not properly ended";
        let result = analyze_error_body(body);
        assert_eq!(result.detected_dbms, Some(DbmsFamily::Oracle));
        assert!(result.confidence >= 45);
        assert!(result.signals.len() >= 2);
    }

    #[test]
    fn detects_sqlite_from_operational_error() {
        let body = "sqlite3.OperationalError: unrecognized token: \"''\"";
        let result = analyze_error_body(body);
        assert_eq!(result.detected_dbms, Some(DbmsFamily::SQLite));
        assert!(result.confidence >= 45);
    }

    #[test]
    fn no_signal_on_clean_page() {
        let body = "<html><body>Welcome to the application</body></html>";
        let result = analyze_error_body(body);
        assert_eq!(result.detected_dbms, None);
        assert_eq!(result.confidence, 0);
        assert_eq!(result.verdict, DetectionVerdict::NoSignal);
    }

    #[test]
    fn runner_up_tracked_when_ambiguous() {
        // Body contains signals for two different DBMS families.
        let body = "check the manual that corresponds to your MySQL server version\npg_query(): query failed:";
        let result = analyze_error_body(body);
        assert!(result.detected_dbms.is_some());
        assert!(result.runner_up.is_some());
    }

    #[test]
    fn mariadb_distinct_from_mysql() {
        let body = "check the manual that corresponds to your MariaDB server version";
        let result = analyze_error_body(body);
        assert_eq!(result.detected_dbms, Some(DbmsFamily::MariaDB));
    }

    #[test]
    fn sqlite_quoted_token_syntax_error_now_fires() {
        // Regression: this needle was authored as a regex (`near ".*": syntax
        // error`) but is matched as a literal substring, so it never fired and
        // real SQLite syntax errors went undetected.
        let body = "sqlite error near \"WHERE\": syntax error";
        let result = analyze_error_body(body);
        assert_eq!(result.detected_dbms, Some(DbmsFamily::SQLite));
        assert!(
            result
                .signals
                .iter()
                .any(|s| s.label == "SQLite quoted-token syntax error"),
            "the quoted-token signal must fire on a real SQLite message"
        );
    }

    #[test]
    fn postgres_syntax_error_is_not_misread_as_sqlite() {
        // PostgreSQL says `ERROR: syntax error at or near "..."` — the colon is
        // preceded by a letter, not a quote, so the SQLite needle must not fire.
        let body = "ERROR: syntax error at or near \"'\"";
        let result = analyze_error_body(body);
        assert_eq!(result.detected_dbms, Some(DbmsFamily::PostgreSQL));
    }

    #[test]
    fn plain_english_top_and_dual_do_not_false_positive() {
        // Ordinary page copy used to score Oracle ("dual") and MSSQL ("top ").
        let body = "<html><body>This dual-core laptop scrolls back to top of the page.</body></html>";
        let result = analyze_error_body(body);
        assert_eq!(result.detected_dbms, None, "no DBMS should be inferred from prose");
    }

    #[test]
    fn precise_oracle_and_mssql_syntax_still_fire() {
        assert_eq!(
            analyze_error_body("SELECT banner FROM dual").detected_dbms,
            Some(DbmsFamily::Oracle)
        );
        assert_eq!(
            analyze_error_body("query was: SELECT TOP 1 name FROM users").detected_dbms,
            Some(DbmsFamily::MSSQL)
        );
    }

    #[test]
    fn information_schema_alone_does_not_implicate_h2() {
        // INFORMATION_SCHEMA is ANSI-standard and shared across engines.
        let body = "SELECT * FROM information_schema.tables";
        let result = analyze_error_body(body);
        assert_ne!(result.detected_dbms, Some(DbmsFamily::H2));
    }

    #[test]
    fn mssql_incorrect_syntax_without_line_prefix_detects() {
        // Most MSSQL responses carry `Incorrect syntax near 'X'.` with no
        // `Line 1:` prefix; the signal must still fire.
        let body = "Incorrect syntax near 'FROM'.";
        let result = analyze_error_body(body);
        assert_eq!(result.detected_dbms, Some(DbmsFamily::MSSQL));
    }

    #[test]
    fn ranking_ties_break_deterministically() {
        // Two families scoring exactly 45 each (Oracle ORA-00907 vs. the MSSQL
        // ODBC driver banner). The tie must resolve to the same winner every
        // time, not flip with HashMap iteration order. MSSQL precedes Oracle in
        // `DbmsFamily::ALL`, so it wins by ordinal.
        let body = "ORA-00907: missing right parenthesis [Driver][SQL Server]";
        let result = analyze_error_body(body);
        assert_eq!(result.confidence, 45);
        assert_eq!(result.detected_dbms, Some(DbmsFamily::MSSQL));
        for _ in 0..64 {
            assert_eq!(analyze_error_body(body).detected_dbms, Some(DbmsFamily::MSSQL));
        }
    }
}
