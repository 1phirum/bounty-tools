//! DBMS fingerprint signals for DB2 and H2.
//!
//! These extend the existing `detection.rs` signal library with the two
//! families the brief adds. They follow the same shape and are aggregated
//! by `detection::analyze_error_body` when their needles match — DBMS
//! fingerprinting is *supporting evidence only* and never by itself
//! indicates injectability.

use crate::detection::{DetectionSignal, SignalCategory};

/// Additional DB2 signatures.
pub const DB2_SIGNALS: &[DetectionSignal] = &[
    DetectionSignal {
        label: "DB2 SQL error code",
        needle: "db2 sql error",
        dbms: crate::detection::DbmsFamily::DB2,
        weight: 50,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "DB2 CLI driver",
        needle: "cli driver",
        dbms: crate::detection::DbmsFamily::DB2,
        weight: 30,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "DB2 system catalog",
        needle: "sysibm.sys",
        dbms: crate::detection::DbmsFamily::DB2,
        weight: 35,
        category: SignalCategory::CatalogTable,
    },
    DetectionSignal {
        label: "DB2 fetch-first syntax",
        needle: "fetch first",
        dbms: crate::detection::DbmsFamily::DB2,
        weight: 20,
        category: SignalCategory::SyntaxFeature,
    },
];

/// Additional H2 (Java embedded database) signatures.
pub const H2_SIGNALS: &[DetectionSignal] = &[
    DetectionSignal {
        label: "H2 JdbcSQLException",
        needle: "org.h2.jdbc",
        dbms: crate::detection::DbmsFamily::H2,
        weight: 50,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "H2 syntax error location",
        needle: "syntax error in sql statement",
        dbms: crate::detection::DbmsFamily::H2,
        weight: 40,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "H2 expected identifier",
        needle: "expected \"identifier\"",
        dbms: crate::detection::DbmsFamily::H2,
        weight: 40,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "H2 INFORMATION_SCHEMA",
        needle: "information_schema",
        dbms: crate::detection::DbmsFamily::H2,
        weight: 15,
        category: SignalCategory::CatalogTable,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::{analyze_error_body, DbmsFamily};

    #[test]
    fn db2_error_identifies_db2() {
        let r = analyze_error_body("[IBM][CLI Driver][DB2] DB2 SQL Error: SQLCODE=-104");
        assert_eq!(r.detected_dbms, Some(DbmsFamily::DB2));
    }

    #[test]
    fn h2_exception_identifies_h2() {
        let r = analyze_error_body("org.h2.jdbc.JdbcSQLSyntaxErrorException: Syntax error in SQL statement");
        assert_eq!(r.detected_dbms, Some(DbmsFamily::H2));
    }

    #[test]
    fn signals_are_well_formed() {
        for s in DB2_SIGNALS.iter().chain(H2_SIGNALS.iter()) {
            assert!(!s.needle.is_empty());
            assert!(s.weight > 0 && s.weight <= 100);
        }
    }
}
