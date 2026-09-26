//! Detection signatures for the engine families added for sqlmap-parity
//! coverage.
//!
//! Same shape and same aggregation path as [`crate::dbms_ext`]: each needle is
//! a real, observed error banner, driver name or catalogue reference, matched
//! case-insensitively as a substring. Every needle here is deliberately
//! *specific* — a generic phrase like `syntax error` or a common English word
//! is excluded, because a DBMS hypothesis built on one would be a false
//! positive rather than a fingerprint.

use crate::detection::{DbmsFamily, DetectionSignal, SignalCategory};

/// Sybase Adaptive Server Enterprise. Shares T-SQL syntax with MSSQL, so the
/// driver and product banners are the discriminating evidence.
pub const SYBASE_SIGNALS: &[DetectionSignal] = &[
    DetectionSignal {
        label: "Sybase jConnect driver",
        needle: "com.sybase.jdbc",
        dbms: DbmsFamily::Sybase,
        weight: 50,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "Sybase ASE client",
        needle: "aseclient",
        dbms: DbmsFamily::Sybase,
        weight: 45,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "Sybase adaptive server banner",
        needle: "adaptive server",
        dbms: DbmsFamily::Sybase,
        weight: 45,
        category: SignalCategory::VersionBanner,
    },
    DetectionSignal {
        label: "Sybase ODBC driver tag",
        needle: "[sybase]",
        dbms: DbmsFamily::Sybase,
        weight: 40,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "Sybase catalog table",
        needle: "sysobjects",
        dbms: DbmsFamily::Sybase,
        weight: 30,
        category: SignalCategory::CatalogTable,
    },
]; // end SYBASE_SIGNALS

/// Firebird / InterBase. Its error vocabulary is highly distinctive.
pub const FIREBIRD_SIGNALS: &[DetectionSignal] = &[
    DetectionSignal {
        label: "Firebird dynamic SQL error",
        needle: "dynamic sql error",
        dbms: DbmsFamily::Firebird,
        weight: 50,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "Firebird SQL error code",
        needle: "sql error code = -",
        dbms: DbmsFamily::Firebird,
        weight: 45,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "Firebird Jaybird JDBC driver",
        needle: "org.firebirdsql.jdbc",
        dbms: DbmsFamily::Firebird,
        weight: 50,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "Firebird metadata update failure",
        needle: "unsuccessful metadata update",
        dbms: DbmsFamily::Firebird,
        weight: 45,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "Firebird system catalog",
        needle: "rdb$",
        dbms: DbmsFamily::Firebird,
        weight: 35,
        category: SignalCategory::CatalogTable,
    },
]; // end FIREBIRD_SIGNALS

/// IBM Informix Dynamic Server.
pub const INFORMIX_SIGNALS: &[DetectionSignal] = &[
    DetectionSignal {
        label: "Informix JDBC driver",
        needle: "com.informix.jdbc",
        dbms: DbmsFamily::Informix,
        weight: 50,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "Informix ODBC driver tag",
        needle: "[informix]",
        dbms: DbmsFamily::Informix,
        weight: 45,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "Informix dynamic server banner",
        needle: "informix dynamic server",
        dbms: DbmsFamily::Informix,
        weight: 50,
        category: SignalCategory::VersionBanner,
    },
    DetectionSignal {
        label: "Informix error code prefix",
        needle: "-2: the specified",
        dbms: DbmsFamily::Informix,
        weight: 35,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "Informix system catalog",
        needle: "sysmaster:",
        dbms: DbmsFamily::Informix,
        weight: 40,
        category: SignalCategory::CatalogTable,
    },
]; // end INFORMIX_SIGNALS

/// HSQLDB (HyperSQL).
pub const HSQLDB_SIGNALS: &[DetectionSignal] = &[
    DetectionSignal {
        label: "HSQLDB JDBC driver",
        needle: "org.hsqldb",
        dbms: DbmsFamily::HSQLDB,
        weight: 50,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "HSQLDB unexpected token",
        needle: "unexpected token:",
        dbms: DbmsFamily::HSQLDB,
        weight: 40,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "HSQLDB engine banner",
        needle: "hsqldb",
        dbms: DbmsFamily::HSQLDB,
        weight: 35,
        category: SignalCategory::VersionBanner,
    },
    DetectionSignal {
        label: "HSQLDB catalog table",
        needle: "information_schema.system_users",
        dbms: DbmsFamily::HSQLDB,
        weight: 35,
        category: SignalCategory::CatalogTable,
    },
]; // end HSQLDB_SIGNALS

/// SAP MaxDB (formerly SAP DB).
pub const MAXDB_SIGNALS: &[DetectionSignal] = &[
    DetectionSignal {
        label: "MaxDB JDBC driver",
        needle: "com.sap.dbtech",
        dbms: DbmsFamily::MaxDB,
        weight: 50,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "MaxDB product banner",
        needle: "maxdb",
        dbms: DbmsFamily::MaxDB,
        weight: 40,
        category: SignalCategory::VersionBanner,
    },
    DetectionSignal {
        label: "SAP DB legacy banner",
        needle: "sap db",
        dbms: DbmsFamily::MaxDB,
        weight: 40,
        category: SignalCategory::VersionBanner,
    },
    DetectionSignal {
        label: "MaxDB system catalog",
        needle: "domain.tables",
        dbms: DbmsFamily::MaxDB,
        weight: 35,
        category: SignalCategory::CatalogTable,
    },
]; // end MAXDB_SIGNALS

/// SAP HANA.
pub const SAPHANA_SIGNALS: &[DetectionSignal] = &[
    DetectionSignal {
        label: "SAP HANA JDBC driver",
        needle: "com.sap.db.jdbc",
        dbms: DbmsFamily::SAPHANA,
        weight: 50,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "SAP HANA invalid table error",
        needle: "invalid table name:",
        dbms: DbmsFamily::SAPHANA,
        weight: 45,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "SAP HANA product banner",
        needle: "sap hana",
        dbms: DbmsFamily::SAPHANA,
        weight: 45,
        category: SignalCategory::VersionBanner,
    },
    DetectionSignal {
        label: "SAP HANA system catalog",
        needle: "sys.m_database",
        dbms: DbmsFamily::SAPHANA,
        weight: 35,
        category: SignalCategory::CatalogTable,
    },
]; // end SAPHANA_SIGNALS

/// ClickHouse.
pub const CLICKHOUSE_SIGNALS: &[DetectionSignal] = &[
    DetectionSignal {
        label: "ClickHouse DB exception class",
        needle: "db::exception",
        dbms: DbmsFamily::ClickHouse,
        weight: 50,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "ClickHouse product banner",
        needle: "clickhouse",
        dbms: DbmsFamily::ClickHouse,
        weight: 40,
        category: SignalCategory::VersionBanner,
    },
    DetectionSignal {
        label: "ClickHouse unknown identifier code",
        needle: "code: 47",
        dbms: DbmsFamily::ClickHouse,
        weight: 30,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "ClickHouse system table",
        needle: "system.numbers",
        dbms: DbmsFamily::ClickHouse,
        weight: 35,
        category: SignalCategory::CatalogTable,
    },
]; // end CLICKHOUSE_SIGNALS

/// CUBRID.
pub const CUBRID_SIGNALS: &[DetectionSignal] = &[
    DetectionSignal {
        label: "CUBRID JDBC driver",
        needle: "cubrid.jdbc",
        dbms: DbmsFamily::Cubrid,
        weight: 50,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "CUBRID product banner",
        needle: "cubrid",
        dbms: DbmsFamily::Cubrid,
        weight: 40,
        category: SignalCategory::VersionBanner,
    },
    DetectionSignal {
        label: "CUBRID CAS diagnostic block",
        needle: "cas info -",
        dbms: DbmsFamily::Cubrid,
        weight: 40,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "CUBRID system catalog",
        needle: "db_class",
        dbms: DbmsFamily::Cubrid,
        weight: 30,
        category: SignalCategory::CatalogTable,
    },
]; // end CUBRID_SIGNALS

/// OpenLink Virtuoso.
pub const VIRTUOSO_SIGNALS: &[DetectionSignal] = &[
    DetectionSignal {
        label: "Virtuoso ODBC driver",
        needle: "virtuoso odbc driver",
        dbms: DbmsFamily::Virtuoso,
        weight: 50,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "OpenLink driver tag",
        needle: "[openlink]",
        dbms: DbmsFamily::Virtuoso,
        weight: 45,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "Virtuoso system catalog",
        needle: "db.dba.sys_keys",
        dbms: DbmsFamily::Virtuoso,
        weight: 40,
        category: SignalCategory::CatalogTable,
    },
]; // end VIRTUOSO_SIGNALS

/// MonetDB.
pub const MONETDB_SIGNALS: &[DetectionSignal] = &[
    DetectionSignal {
        label: "MonetDB JDBC driver",
        needle: "nl.cwi.monetdb",
        dbms: DbmsFamily::MonetDB,
        weight: 50,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "MonetDB MAL exception",
        needle: "malexception",
        dbms: DbmsFamily::MonetDB,
        weight: 45,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "MonetDB product banner",
        needle: "monetdb",
        dbms: DbmsFamily::MonetDB,
        weight: 40,
        category: SignalCategory::VersionBanner,
    },
    DetectionSignal {
        label: "MonetDB system catalog",
        needle: "sys.tables",
        dbms: DbmsFamily::MonetDB,
        weight: 30,
        category: SignalCategory::CatalogTable,
    },
]; // end MONETDB_SIGNALS

/// Vertica.
pub const VERTICA_SIGNALS: &[DetectionSignal] = &[
    DetectionSignal {
        label: "Vertica JDBC driver",
        needle: "com.vertica.jdbc",
        dbms: DbmsFamily::Vertica,
        weight: 50,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "Vertica product banner",
        needle: "vertica",
        dbms: DbmsFamily::Vertica,
        weight: 40,
        category: SignalCategory::VersionBanner,
    },
    DetectionSignal {
        label: "Vertica catalog schema",
        needle: "v_catalog.",
        dbms: DbmsFamily::Vertica,
        weight: 35,
        category: SignalCategory::CatalogTable,
    },
]; // end VERTICA_SIGNALS

/// Microsoft Access / Jet.
pub const ACCESS_SIGNALS: &[DetectionSignal] = &[
    DetectionSignal {
        label: "Jet OLEDB provider",
        needle: "microsoft.jet.oledb",
        dbms: DbmsFamily::Access,
        weight: 50,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "ACE provider",
        needle: "ace.oledb",
        dbms: DbmsFamily::Access,
        weight: 50,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "Access ODBC driver",
        needle: "microsoft access driver",
        dbms: DbmsFamily::Access,
        weight: 45,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "Jet database engine error",
        needle: "jet database engine",
        dbms: DbmsFamily::Access,
        weight: 45,
        category: SignalCategory::ErrorPattern,
    },
]; // end ACCESS_SIGNALS

/// Presto / Trino.
pub const PRESTO_SIGNALS: &[DetectionSignal] = &[
    DetectionSignal {
        label: "Presto exception class",
        needle: "com.facebook.presto",
        dbms: DbmsFamily::Presto,
        weight: 50,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "Trino exception class",
        needle: "io.trino",
        dbms: DbmsFamily::Presto,
        weight: 50,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "Presto exception name",
        needle: "prestoexception",
        dbms: DbmsFamily::Presto,
        weight: 45,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "Trino statement failure",
        needle: "trinoexception",
        dbms: DbmsFamily::Presto,
        weight: 45,
        category: SignalCategory::ErrorPattern,
    },
]; // end PRESTO_SIGNALS

/// Google Cloud Spanner.
pub const SPANNER_SIGNALS: &[DetectionSignal] = &[
    DetectionSignal {
        label: "Cloud Spanner client library",
        needle: "com.google.cloud.spanner",
        dbms: DbmsFamily::Spanner,
        weight: 50,
        category: SignalCategory::DriverName,
    },
    DetectionSignal {
        label: "Cloud Spanner banner",
        needle: "cloud spanner",
        dbms: DbmsFamily::Spanner,
        weight: 45,
        category: SignalCategory::VersionBanner,
    },
    DetectionSignal {
        label: "GoogleSQL error class",
        needle: "spanner.rpc",
        dbms: DbmsFamily::Spanner,
        weight: 35,
        category: SignalCategory::ErrorPattern,
    },
]; // end SPANNER_SIGNALS

/// InterSystems Cache / IRIS.
pub const CACHE_SIGNALS: &[DetectionSignal] = &[
    DetectionSignal {
        label: "InterSystems product banner",
        needle: "intersystems",
        dbms: DbmsFamily::Cache,
        weight: 45,
        category: SignalCategory::VersionBanner,
    },
    DetectionSignal {
        label: "Cache SQL error number",
        needle: "#5540",
        dbms: DbmsFamily::Cache,
        weight: 40,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "Cache SQLCODE phrasing",
        needle: "sqlcode: -",
        dbms: DbmsFamily::Cache,
        weight: 35,
        category: SignalCategory::ErrorPattern,
    },
    DetectionSignal {
        label: "Cache driver name",
        needle: "intersystems.jdbc",
        dbms: DbmsFamily::Cache,
        weight: 50,
        category: SignalCategory::DriverName,
    },
]; // end CACHE_SIGNALS




