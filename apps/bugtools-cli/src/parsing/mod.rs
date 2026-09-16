//! Shared CLI input parsing: cookies, headers, DNS record types, DBMS names,
//! and hypothesis rendering. One place for every string-to-typed conversion
//! the commands share.

use anyhow::{Context, Result};
use bugtools_dns::RecordType;
use bugtools_sql::DbmsFamily;
use std::collections::HashMap;

/// Resolve the cookie set from CLI flags and an optional file.
///
/// Accepts `--cookie "name=value"` (repeatable), `--cookie "a=1; b=2"`,
/// a `--cookie` argument naming an existing file, and `--cookie-file`
/// containing either a raw `Cookie:` header value or one `name=value` per
/// line. Returns name/value pairs.
pub fn resolve_cookies(
    cli_cookies: &[String],
    cookie_file: Option<&str>,
) -> Result<Vec<(String, String)>> {
    let mut jar = bugtools_sql::request::CookieJar::new("cli");

    for entry in cli_cookies {
        // A --cookie argument naming an existing file is read as a file.
        let path = std::path::Path::new(entry);
        if path.is_file() {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("cannot read cookie file {entry}"))?;
            import_cookie_text(&mut jar, &raw);
            continue;
        }
        import_cookie_text(&mut jar, entry);
    }

    if let Some(path) = cookie_file {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read cookie file {path}"))?;
        import_cookie_text(&mut jar, &raw);
    }

    Ok(jar.export_pairs())
}

/// Parse one cookie text: a raw `Cookie:` header, `a=1; b=2`, or one pair
/// per line with `#` comments.
fn import_cookie_text(jar: &mut bugtools_sql::request::CookieJar, raw: &str) {
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("Cookie:").unwrap_or(line).trim();
        for pair in line.split(';') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            if let Some((name, value)) = pair.split_once('=') {
                jar.import_pairs(&[(name.trim().to_string(), value.trim().to_string())]);
            }
        }
    }
}

/// Build a header map from `Name: value` flags plus an optional bearer token.
pub fn resolve_headers(
    headers: &[String],
    bearer: Option<&str>,
) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for flag in headers {
        let (name, value) = flag
            .split_once(':')
            .with_context(|| format!("invalid header {flag:?}: expected `Name: value`"))?;
        map.insert(name.trim().to_string(), value.trim().to_string());
    }
    if let Some(token) = bearer {
        map.insert(
            "Authorization".to_string(),
            format!("Bearer {token}"),
        );
    }
    Ok(map)
}

/// Add a researcher identity header (e.g. X-Bug-Bounty) when supplied.
pub fn apply_identity_header(headers: &mut HashMap<String, String>, handle: &str) {
    headers
        .entry("X-Bug-Bounty".to_string())
        .or_insert_with(|| handle.to_string());
}

/// Parse DNS record-type names.
pub fn parse_record_types(types: &[String]) -> Vec<RecordType> {
    types
        .iter()
        .filter_map(|t| match t.to_lowercase().as_str() {
            "a" => Some(RecordType::A),
            "aaaa" => Some(RecordType::Aaaa),
            "cname" => Some(RecordType::Cname),
            "mx" => Some(RecordType::Mx),
            "ns" => Some(RecordType::Ns),
            "txt" => Some(RecordType::Txt),
            "soa" => Some(RecordType::Soa),
            _ => None,
        })
        .collect()
}

/// Parse a DBMS family name from a CLI argument.
pub fn parse_dbms_arg(name: &str) -> Option<DbmsFamily> {
    match name.to_lowercase().as_str() {
        "mysql" => Some(DbmsFamily::MySQL),
        "mariadb" => Some(DbmsFamily::MariaDB),
        "postgresql" | "postgres" | "pg" => Some(DbmsFamily::PostgreSQL),
        "mssql" | "sqlserver" | "sql server" => Some(DbmsFamily::MSSQL),
        "oracle" => Some(DbmsFamily::Oracle),
        "sqlite" => Some(DbmsFamily::SQLite),
        "db2" => Some(DbmsFamily::DB2),
        "h2" => Some(DbmsFamily::H2),
        _ => None,
    }
}

/// Render a hypothesis list like `WHERE: 0.61 | LIKE: 0.24`, including
/// considered-but-unsupported alternatives so the engine visibly ruled them
/// out rather than silently dropping them.
pub fn render_hypotheses(hypotheses: &[(String, f32)]) -> String {
    if hypotheses.is_empty() {
        return "unknown (none considered)".to_string();
    }
    let present: Vec<String> = hypotheses
        .iter()
        .filter(|(_, p)| *p > 0.01)
        .map(|(label, p)| format!("{label}: {p:.2}"))
        .collect();
    let ruled_out: Vec<&str> = hypotheses
        .iter()
        .filter(|(_, p)| *p <= 0.01)
        .map(|(label, _)| label.as_str())
        .collect();
    let mut out = present.join(" | ");
    if out.is_empty() {
        out = "unknown".to_string();
    }
    if !ruled_out.is_empty() {
        out.push_str(&format!(
            "   (considered, no evidence: {})",
            ruled_out.join(", ")
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_from_inline_string() {
        let pairs = resolve_cookies(&["a=1".into(), "b=2".into()], None).unwrap();
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    fn headers_require_name_value() {
        assert!(resolve_headers(&["no-colon".into()], None).is_err());
        assert_eq!(
            resolve_headers(&["X-A: 1".into()], None).unwrap()["X-A"],
            "1"
        );
    }

    #[test]
    fn identity_header_is_not_overwritten() {
        let mut h = resolve_headers(&["X-Bug-Bounty: existing".into()], None).unwrap();
        apply_identity_header(&mut h, "naga");
        assert_eq!(h["X-Bug-Bounty"], "existing");
    }

    #[test]
    fn record_types_parse() {
        let rts = parse_record_types(&["a".into(), "mx".into(), "bogus".into()]);
        assert_eq!(rts.len(), 2);
    }

    #[test]
    fn dbms_aliases_parse() {
        assert_eq!(parse_dbms_arg("pg"), Some(DbmsFamily::PostgreSQL));
        assert_eq!(parse_dbms_arg("SQLServer"), Some(DbmsFamily::MSSQL));
        assert_eq!(parse_dbms_arg("unknown"), None);
    }

    #[test]
    fn hypotheses_show_ruled_out() {
        let out = render_hypotheses(&[("WHERE".into(), 0.61), ("LIKE".into(), 0.0)]);
        assert!(out.contains("WHERE: 0.61"));
        assert!(out.contains("considered, no evidence: LIKE"));
    }
}
