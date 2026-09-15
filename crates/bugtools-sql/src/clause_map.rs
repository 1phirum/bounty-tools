use crate::detection::DbmsFamily;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Every major SQL clause and its dialect-specific syntax variants.
/// Each variant is annotated with the DBMS families that accept it.
///
/// Coverage: SELECT, INSERT, UPDATE, DELETE, WHERE, ORDER BY, GROUP BY,
/// HAVING, LIMIT/OFFSET, JOIN (all types), UNION, subqueries, CASE,
/// string functions, date functions, and DDL (CREATE/ALTER/DROP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlClauseMap {
    pub clause: SqlClause,
    pub description: &'static str,
    pub variants: Vec<ClauseVariant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlClause {
    Select,
    Insert,
    Update,
    Delete,
    Where,
    OrderBy,
    GroupBy,
    Having,
    LimitOffset,
    JoinInner,
    JoinLeft,
    JoinRight,
    JoinFullOuter,
    JoinCross,
    Union,
    UnionAll,
    Subquery,
    CaseWhen,
    StringConcat,
    Substring,
    Length,
    Trim,
    UpperLower,
    Coalesce,
    Cast,
    CurrentDate,
    CurrentTimestamp,
    DateAdd,
    DateDiff,
    CreateTable,
    AlterTable,
    DropTable,
    CreateIndex,
    IfExists,
    AutoIncrement,
    BooleanLiteral,
    Comment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClauseVariant {
    /// The SQL syntax string for this variant.
    pub syntax: &'static str,
    /// DBMS families that accept this exact syntax.
    pub accepted_by: Vec<DbmsFamily>,
    /// DBMS families that explicitly reject or warn on this syntax.
    pub rejected_by: Vec<DbmsFamily>,
    /// Notes on edge cases or version constraints.
    pub notes: Option<&'static str>,
}

/// The complete clause syntax map. Built once at startup; lookup is
/// O(1) per clause.
pub fn clause_map() -> &'static [SqlClauseMap] {
    &CLAUSE_MAP
}

/// All dialect-accepted variants for a given clause.
pub fn variants_for(clause: SqlClause) -> Option<&'static [ClauseVariant]> {
    CLAUSE_MAP
        .iter()
        .find(|m| m.clause == clause)
        .map(|m| m.variants.as_slice())
}

/// Which dialects accept a specific syntax string for a given clause.
pub fn dialects_accepting(clause: SqlClause, syntax: &str) -> Vec<DbmsFamily> {
    let lower = syntax.to_lowercase();
    CLAUSE_MAP
        .iter()
        .find(|m| m.clause == clause)
        .map(|m| {
            m.variants
                .iter()
                .filter(|v| v.syntax.to_lowercase() == lower)
                .flat_map(|v| v.accepted_by.iter().copied())
                .collect()
        })
        .unwrap_or_default()
}

/// All syntax variants a given DBMS family accepts for a clause.
pub fn variants_accepted_by(dbms: DbmsFamily, clause: SqlClause) -> Vec<&'static ClauseVariant> {
    CLAUSE_MAP
        .iter()
        .find(|m| m.clause == clause)
        .map(|m| {
            m.variants
                .iter()
                .filter(|v| v.accepted_by.contains(&dbms))
                .collect()
        })
        .unwrap_or_default()
}

static CLAUSE_MAP: &[SqlClauseMap] = &[
    // ═══ SELECT ═══
    SqlClauseMap {
        clause: SqlClause::Select,
        description: "Retrieve rows from one or more tables",
        variants: vec![
            ClauseVariant {
                syntax: "SELECT * FROM table_name",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("Universal. Use specific column names in production."),
            },
            ClauseVariant {
                syntax: "SELECT col1, col2 FROM table_name WHERE condition",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
            ClauseVariant {
                syntax: "SELECT DISTINCT col FROM table_name",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("DISTINCT is universal but expensive on large tables."),
            },
            ClauseVariant {
                syntax: "SELECT col AS alias FROM table_name",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("AS keyword is optional in most dialects but explicit in Oracle."),
            },
            ClauseVariant {
                syntax: "SELECT TOP n col FROM table_name",
                accepted_by: vec![DbmsFamily::MSSQL],
                rejected_by: vec![DbmsFamily::PostgreSQL, DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::Oracle, DbmsFamily::SQLite],
                notes: Some("MSSQL-specific. Equivalent: LIMIT (MySQL/PG/SQLite), FETCH FIRST (Oracle 12c+)."),
            },
            ClauseVariant {
                syntax: "SELECT col FROM table_name LIMIT n",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::PostgreSQL, DbmsFamily::SQLite],
                rejected_by: vec![DbmsFamily::MSSQL, DbmsFamily::Oracle],
                notes: Some("LIMIT is the standard row-limiting clause for MySQL/PG/SQLite."),
            },
            ClauseVariant {
                syntax: "SELECT col FROM table_name FETCH FIRST n ROWS ONLY",
                accepted_by: vec![DbmsFamily::Oracle, DbmsFamily::MSSQL, DbmsFamily::PostgreSQL],
                rejected_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::SQLite],
                notes: Some("SQL:2008 standard. Oracle 12c+, MSSQL 2012+, PG 13+."),
            },
            ClauseVariant {
                syntax: "SELECT col FROM table_name WHERE ROWNUM <= n",
                accepted_by: vec![DbmsFamily::Oracle],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::Oracle).copied().collect(),
                notes: Some("Oracle legacy row limiting. Superseded by FETCH FIRST in 12c+."),
            },
        ],
    },
    // ═══ INSERT ═══
    SqlClauseMap {
        clause: SqlClause::Insert,
        description: "Insert new rows into a table",
        variants: vec![
            ClauseVariant {
                syntax: "INSERT INTO table_name (col1, col2) VALUES (val1, val2)",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
            ClauseVariant {
                syntax: "INSERT INTO table_name VALUES (val1, val2)",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("Implicit column list — fragile if schema changes."),
            },
            ClauseVariant {
                syntax: "INSERT INTO table_name (col) SELECT col FROM other_table",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("INSERT ... SELECT is universal."),
            },
            ClauseVariant {
                syntax: "INSERT INTO table_name (col) VALUES (val) ON DUPLICATE KEY UPDATE col=val",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB],
                rejected_by: vec![DbmsFamily::PostgreSQL, DbmsFamily::MSSQL, DbmsFamily::Oracle, DbmsFamily::SQLite],
                notes: Some("MySQL/MariaDB upsert. PG: ON CONFLICT. MSSQL: MERGE."),
            },
            ClauseVariant {
                syntax: "INSERT INTO table_name (col) VALUES (val) ON CONFLICT (col) DO UPDATE SET col=EXCLUDED.col",
                accepted_by: vec![DbmsFamily::PostgreSQL, DbmsFamily::SQLite],
                rejected_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::MSSQL, DbmsFamily::Oracle],
                notes: Some("PostgreSQL/SQLite upsert. MySQL: ON DUPLICATE KEY. MSSQL: MERGE."),
            },
            ClauseVariant {
                syntax: "MERGE INTO table_name USING source ON (condition) WHEN MATCHED THEN UPDATE WHEN NOT MATCHED THEN INSERT",
                accepted_by: vec![DbmsFamily::MSSQL, DbmsFamily::Oracle],
                rejected_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::PostgreSQL, DbmsFamily::SQLite],
                notes: Some("MSSQL/Oracle upsert. PG 15+: MERGE. MySQL: ON DUPLICATE KEY."),
            },
        ],
    },
    // ═══ UPDATE ═══
    SqlClauseMap {
        clause: SqlClause::Update,
        description: "Modify existing rows in a table",
        variants: vec![
            ClauseVariant {
                syntax: "UPDATE table_name SET col1 = val1 WHERE condition",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
            ClauseVariant {
                syntax: "UPDATE table_name SET col = val FROM table_name JOIN other ON ...",
                accepted_by: vec![DbmsFamily::PostgreSQL, DbmsFamily::MSSQL],
                rejected_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::Oracle, DbmsFamily::SQLite],
                notes: Some("PG/MSSQL allow FROM in UPDATE. MySQL: multi-table UPDATE. Oracle: correlated subquery."),
            },
            ClauseVariant {
                syntax: "UPDATE table_name t JOIN other_table o ON t.id = o.id SET t.col = o.col",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB],
                rejected_by: vec![DbmsFamily::PostgreSQL, DbmsFamily::MSSQL, DbmsFamily::Oracle, DbmsFamily::SQLite],
                notes: Some("MySQL multi-table UPDATE with JOIN syntax."),
            },
        ],
    },
    // ═══ DELETE ═══
    SqlClauseMap {
        clause: SqlClause::Delete,
        description: "Remove rows from a table",
        variants: vec![
            ClauseVariant {
                syntax: "DELETE FROM table_name WHERE condition",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("Omitting WHERE deletes all rows — always verify in scope first."),
            },
            ClauseVariant {
                syntax: "DELETE t FROM table_name t JOIN other_table o ON t.id = o.id",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB],
                rejected_by: vec![DbmsFamily::PostgreSQL, DbmsFamily::MSSQL, DbmsFamily::Oracle, DbmsFamily::SQLite],
                notes: Some("MySQL multi-table DELETE."),
            },
            ClauseVariant {
                syntax: "DELETE FROM table_name WHERE col IN (SELECT col FROM other_table)",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("Correlated subquery DELETE is universal."),
            },
        ],
    },
    // ═══ WHERE ═══
    SqlClauseMap {
        clause: SqlClause::Where,
        description: "Filter rows based on conditions",
        variants: vec![
            ClauseVariant {
                syntax: "WHERE col = 'value'",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
            ClauseVariant {
                syntax: "WHERE col LIKE 'pattern%'",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("LIKE is universal. Case sensitivity varies: PG case-sensitive, MySQL case-insensitive (collation-dependent)."),
            },
            ClauseVariant {
                syntax: "WHERE col IN (val1, val2, val3)",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
            ClauseVariant {
                syntax: "WHERE col BETWEEN val1 AND val2",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
            ClauseVariant {
                syntax: "WHERE col IS NULL",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("IS NULL is universal. = NULL is never correct."),
            },
            ClauseVariant {
                syntax: "WHERE EXISTS (SELECT 1 FROM ...)",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("EXISTS is universal and typically faster than IN for large sets."),
            },
            ClauseVariant {
                syntax: "WHERE col REGEXP 'pattern'",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB],
                rejected_by: vec![DbmsFamily::PostgreSQL, DbmsFamily::MSSQL, DbmsFamily::Oracle, DbmsFamily::SQLite],
                notes: Some("MySQL REGEXP. PG: ~ or SIMILAR TO. MSSQL: LIKE with PATINDEX. SQLite: REGEXP via extension."),
            },
            ClauseVariant {
                syntax: "WHERE col ~ 'pattern'",
                accepted_by: vec![DbmsFamily::PostgreSQL],
                rejected_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::MSSQL, DbmsFamily::Oracle, DbmsFamily::SQLite],
                notes: Some("PostgreSQL regex match operator."),
            },
        ],
    },
    // ═══ ORDER BY ═══
    SqlClauseMap {
        clause: SqlClause::OrderBy,
        description: "Sort result set",
        variants: vec![
            ClauseVariant {
                syntax: "ORDER BY col ASC",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
            ClauseVariant {
                syntax: "ORDER BY col DESC",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
            ClauseVariant {
                syntax: "ORDER BY col NULLS FIRST",
                accepted_by: vec![DbmsFamily::PostgreSQL, DbmsFamily::Oracle],
                rejected_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::MSSQL, DbmsFamily::SQLite],
                notes: Some("PG/Oracle NULLS FIRST/LAST. MySQL: ISNULL(col), col. MSSQL: CASE."),
            },
            ClauseVariant {
                syntax: "ORDER BY 1, 2",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("Ordinal position. Valid but fragile — prefer named columns."),
            },
        ],
    },
    // ═══ GROUP BY / HAVING ═══
    SqlClauseMap {
        clause: SqlClause::GroupBy,
        description: "Group rows sharing a value into summary rows",
        variants: vec![
            ClauseVariant {
                syntax: "GROUP BY col1, col2",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
            ClauseVariant {
                syntax: "SELECT col, COUNT(*) FROM t GROUP BY col HAVING COUNT(*) > 1",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
        ],
    },
    SqlClauseMap {
        clause: SqlClause::Having,
        description: "Filter groups after GROUP BY",
        variants: vec![
            ClauseVariant {
                syntax: "HAVING COUNT(*) > 1",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("HAVING applies to groups; WHERE applies to rows."),
            },
        ],
    },
    // ═══ LIMIT / OFFSET ═══
    SqlClauseMap {
        clause: SqlClause::LimitOffset,
        description: "Paginate or cap result set size",
        variants: vec![
            ClauseVariant {
                syntax: "LIMIT n",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::PostgreSQL, DbmsFamily::SQLite],
                rejected_by: vec![DbmsFamily::MSSQL, DbmsFamily::Oracle],
                notes: None,
            },
            ClauseVariant {
                syntax: "LIMIT n OFFSET m",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::PostgreSQL, DbmsFamily::SQLite],
                rejected_by: vec![DbmsFamily::MSSQL, DbmsFamily::Oracle],
                notes: Some("LIMIT + OFFSET for pagination."),
            },
            ClauseVariant {
                syntax: "OFFSET m ROWS FETCH NEXT n ROWS ONLY",
                accepted_by: vec![DbmsFamily::MSSQL, DbmsFamily::Oracle, DbmsFamily::PostgreSQL],
                rejected_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::SQLite],
                notes: Some("SQL:2008 standard pagination. MSSQL 2012+, Oracle 12c+, PG 13+."),
            },
            ClauseVariant {
                syntax: "FETCH FIRST n ROWS ONLY",
                accepted_by: vec![DbmsFamily::Oracle, DbmsFamily::MSSQL, DbmsFamily::PostgreSQL],
                rejected_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::SQLite],
                notes: Some("Without OFFSET. Equivalent to LIMIT n."),
            },
            ClauseVariant {
                syntax: "ROWNUM <= n",
                accepted_by: vec![DbmsFamily::Oracle],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::Oracle).copied().collect(),
                notes: Some("Oracle legacy row limiting (pre-12c)."),
            },
        ],
    },
    // ═══ JOIN ═══
    SqlClauseMap {
        clause: SqlClause::JoinInner,
        description: "Inner join — rows matching in both tables",
        variants: vec![
            ClauseVariant {
                syntax: "SELECT * FROM a INNER JOIN b ON a.id = b.id",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
            ClauseVariant {
                syntax: "SELECT * FROM a JOIN b ON a.id = b.id",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("JOIN without qualifier is INNER JOIN."),
            },
        ],
    },
    SqlClauseMap {
        clause: SqlClause::JoinLeft,
        description: "Left join — all rows from left, matched from right",
        variants: vec![
            ClauseVariant {
                syntax: "SELECT * FROM a LEFT JOIN b ON a.id = b.id",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
        ],
    },
    SqlClauseMap {
        clause: SqlClause::JoinRight,
        description: "Right join — all rows from right, matched from left",
        variants: vec![
            ClauseVariant {
                syntax: "SELECT * FROM a RIGHT JOIN b ON a.id = b.id",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("SQLite does not support RIGHT JOIN."),
            },
        ],
    },
    SqlClauseMap {
        clause: SqlClause::JoinFullOuter,
        description: "Full outer join — all rows from both tables",
        variants: vec![
            ClauseVariant {
                syntax: "SELECT * FROM a FULL OUTER JOIN b ON a.id = b.id",
                accepted_by: vec![DbmsFamily::PostgreSQL, DbmsFamily::MSSQL, DbmsFamily::Oracle],
                rejected_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::SQLite],
                notes: Some("MySQL: UNION of LEFT and RIGHT joins. SQLite 3.39+: FULL JOIN."),
            },
        ],
    },
    SqlClauseMap {
        clause: SqlClause::JoinCross,
        description: "Cross join — Cartesian product",
        variants: vec![
            ClauseVariant {
                syntax: "SELECT * FROM a CROSS JOIN b",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("Equivalent to SELECT * FROM a, b."),
            },
        ],
    },
    // ═══ UNION ═══
    SqlClauseMap {
        clause: SqlClause::Union,
        description: "Combine results of two queries, deduplicated",
        variants: vec![
            ClauseVariant {
                syntax: "SELECT col FROM a UNION SELECT col FROM b",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("Column count and types must match."),
            },
        ],
    },
    SqlClauseMap {
        clause: SqlClause::UnionAll,
        description: "Combine results of two queries, keeping duplicates",
        variants: vec![
            ClauseVariant {
                syntax: "SELECT col FROM a UNION ALL SELECT col FROM b",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("Faster than UNION — skips dedup."),
            },
        ],
    },
    // ═══ Subqueries ═══
    SqlClauseMap {
        clause: SqlClause::Subquery,
        description: "Nested query inside another query",
        variants: vec![
            ClauseVariant {
                syntax: "SELECT * FROM (SELECT ... ) AS sub",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("Derived table / inline view."),
            },
            ClauseVariant {
                syntax: "WHERE col = (SELECT MAX(col) FROM ...)",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("Scalar subquery."),
            },
            ClauseVariant {
                syntax: "WHERE EXISTS (SELECT 1 FROM ... WHERE ...)",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("Correlated EXISTS subquery."),
            },
        ],
    },
    // ═══ CASE ═══
    SqlClauseMap {
        clause: SqlClause::CaseWhen,
        description: "Conditional expression",
        variants: vec![
            ClauseVariant {
                syntax: "CASE WHEN condition THEN result ELSE default END",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
            ClauseVariant {
                syntax: "CASE col WHEN val1 THEN result1 WHEN val2 THEN result2 END",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("Simple CASE form."),
            },
        ],
    },
    // ═══ String Functions ═══
    SqlClauseMap {
        clause: SqlClause::StringConcat,
        description: "Concatenate strings",
        variants: vec![
            ClauseVariant {
                syntax: "col1 || col2",
                accepted_by: vec![DbmsFamily::PostgreSQL, DbmsFamily::SQLite, DbmsFamily::Oracle],
                rejected_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::MSSQL],
                notes: Some("SQL standard. MySQL: CONCAT(). MSSQL: + or CONCAT()."),
            },
            ClauseVariant {
                syntax: "CONCAT(col1, col2)",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::MSSQL, DbmsFamily::PostgreSQL, DbmsFamily::SQLite],
                rejected_by: vec![DbmsFamily::Oracle],
                notes: Some("Oracle has CONCAT but limited to 2 args (use || for chains)."),
            },
            ClauseVariant {
                syntax: "col1 + col2",
                accepted_by: vec![DbmsFamily::MSSQL],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::MSSQL).copied().collect(),
                notes: Some("MSSQL + operator. Type coercion risk with non-string types."),
            },
        ],
    },
    SqlClauseMap {
        clause: SqlClause::Substring,
        description: "Extract substring",
        variants: vec![
            ClauseVariant {
                syntax: "SUBSTRING(col, start, length)",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("Universal. 1-based indexing in all dialects."),
            },
            ClauseVariant {
                syntax: "SUBSTR(col, start, length)",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::Oracle, DbmsFamily::SQLite],
                rejected_by: vec![DbmsFamily::PostgreSQL, DbmsFamily::MSSQL],
                notes: Some("MySQL/Oracle/SQLite SUBSTR alias. PG uses SUBSTRING."),
            },
            ClauseVariant {
                syntax: "LEFT(col, n)",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::MSSQL, DbmsFamily::PostgreSQL],
                rejected_by: vec![DbmsFamily::Oracle, DbmsFamily::SQLite],
                notes: Some("Left substring. SQLite: SUBSTR(col,1,n)."),
            },
            ClauseVariant {
                syntax: "RIGHT(col, n)",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::MSSQL, DbmsFamily::PostgreSQL],
                rejected_by: vec![DbmsFamily::Oracle, DbmsFamily::SQLite],
                notes: Some("Right substring. SQLite: SUBSTR(col,-n)."),
            },
        ],
    },
    SqlClauseMap {
        clause: SqlClause::Length,
        description: "String length",
        variants: vec![
            ClauseVariant {
                syntax: "LENGTH(col)",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::Oracle, DbmsFamily::PostgreSQL, DbmsFamily::SQLite],
                rejected_by: vec![DbmsFamily::MSSQL],
                notes: Some("MSSQL: LEN()."),
            },
            ClauseVariant {
                syntax: "LEN(col)",
                accepted_by: vec![DbmsFamily::MSSQL],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::MSSQL).copied().collect(),
                notes: Some("MSSQL-specific. Excludes trailing spaces."),
            },
            ClauseVariant {
                syntax: "CHAR_LENGTH(col)",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::PostgreSQL],
                rejected_by: vec![DbmsFamily::MSSQL, DbmsFamily::Oracle, DbmsFamily::SQLite],
                notes: Some("Character count (vs byte count for multi-byte)."),
            },
        ],
    },
    SqlClauseMap {
        clause: SqlClause::Trim,
        description: "Remove leading/trailing whitespace",
        variants: vec![
            ClauseVariant {
                syntax: "TRIM(col)",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
            ClauseVariant {
                syntax: "LTRIM(RTRIM(col))",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("Nested LTRIM/RTRIM is universal for TRIM."),
            },
        ],
    },
    SqlClauseMap {
        clause: SqlClause::UpperLower,
        description: "Case conversion",
        variants: vec![
            ClauseVariant {
                syntax: "UPPER(col)",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
            ClauseVariant {
                syntax: "LOWER(col)",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
        ],
    },
    // ═══ NULL handling ═══
    SqlClauseMap {
        clause: SqlClause::Coalesce,
        description: "Return first non-NULL value",
        variants: vec![
            ClauseVariant {
                syntax: "COALESCE(col, default)",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("SQL standard."),
            },
            ClauseVariant {
                syntax: "IFNULL(col, default)",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB],
                rejected_by: vec![DbmsFamily::PostgreSQL, DbmsFamily::MSSQL, DbmsFamily::Oracle, DbmsFamily::SQLite],
                notes: Some("MySQL-specific. Equivalent: COALESCE."),
            },
            ClauseVariant {
                syntax: "ISNULL(col, default)",
                accepted_by: vec![DbmsFamily::MSSQL],
                rejected_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::PostgreSQL, DbmsFamily::Oracle, DbmsFamily::SQLite],
                notes: Some("MSSQL ISNULL. Not the same as IS NULL."),
            },
            ClauseVariant {
                syntax: "NVL(col, default)",
                accepted_by: vec![DbmsFamily::Oracle],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::Oracle).copied().collect(),
                notes: Some("Oracle NVL. NVL2 for 3-arg variant."),
            },
        ],
    },
    // ═══ Casting ═══
    SqlClauseMap {
        clause: SqlClause::Cast,
        description: "Type conversion",
        variants: vec![
            ClauseVariant {
                syntax: "CAST(col AS type)",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("SQL standard."),
            },
            ClauseVariant {
                syntax: "CONVERT(type, col)",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::MSSQL],
                rejected_by: vec![DbmsFamily::PostgreSQL, DbmsFamily::Oracle, DbmsFamily::SQLite],
                notes: Some("MSSQL CONVERT has style argument for dates."),
            },
            ClauseVariant {
                syntax: "col::type",
                accepted_by: vec![DbmsFamily::PostgreSQL],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::PostgreSQL).copied().collect(),
                notes: Some("PostgreSQL cast operator."),
            },
        ],
    },
    // ═══ Date/Time ═══
    SqlClauseMap {
        clause: SqlClause::CurrentDate,
        description: "Current date",
        variants: vec![
            ClauseVariant {
                syntax: "CURRENT_DATE",
                accepted_by: vec![DbmsFamily::PostgreSQL, DbmsFamily::Oracle, DbmsFamily::SQLite, DbmsFamily::MySQL, DbmsFamily::MariaDB],
                rejected_by: vec![DbmsFamily::MSSQL],
                notes: Some("MSSQL: GETDATE() or CAST(GETDATE() AS DATE)."),
            },
            ClauseVariant {
                syntax: "CURDATE()",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::MySQL && **d != DbmsFamily::MariaDB).copied().collect(),
                notes: Some("MySQL CURDATE()."),
            },
            ClauseVariant {
                syntax: "GETDATE()",
                accepted_by: vec![DbmsFamily::MSSQL],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::MSSQL).copied().collect(),
                notes: Some("MSSQL GETDATE(). Returns datetime."),
            },
            ClauseVariant {
                syntax: "SYSDATE",
                accepted_by: vec![DbmsFamily::Oracle],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::Oracle).copied().collect(),
                notes: Some("Oracle SYSDATE. FROM DUAL required."),
            },
            ClauseVariant {
                syntax: "DATE('now')",
                accepted_by: vec![DbmsFamily::SQLite],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::SQLite).copied().collect(),
                notes: Some("SQLite date function."),
            },
        ],
    },
    SqlClauseMap {
        clause: SqlClause::CurrentTimestamp,
        description: "Current timestamp",
        variants: vec![
            ClauseVariant {
                syntax: "CURRENT_TIMESTAMP",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("Universal."),
            },
            ClauseVariant {
                syntax: "NOW()",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::PostgreSQL],
                rejected_by: vec![DbmsFamily::MSSQL, DbmsFamily::Oracle, DbmsFamily::SQLite],
                notes: Some("MySQL/PG NOW(). MSSQL: GETDATE()."),
            },
            ClauseVariant {
                syntax: "SYSTIMESTAMP",
                accepted_by: vec![DbmsFamily::Oracle],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::Oracle).copied().collect(),
                notes: Some("Oracle SYSTIMESTAMP."),
            },
            ClauseVariant {
                syntax: "DATETIME('now')",
                accepted_by: vec![DbmsFamily::SQLite],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::SQLite).copied().collect(),
                notes: Some("SQLite datetime function."),
            },
        ],
    },
    SqlClauseMap {
        clause: SqlClause::DateAdd,
        description: "Add interval to a date",
        variants: vec![
            ClauseVariant {
                syntax: "DATEADD(unit, amount, date)",
                accepted_by: vec![DbmsFamily::MSSQL],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::MSSQL).copied().collect(),
                notes: Some("MSSQL DATEADD. Units: year, month, day, hour, etc."),
            },
            ClauseVariant {
                syntax: "DATE_ADD(date, INTERVAL amount unit)",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::MySQL && **d != DbmsFamily::MariaDB).copied().collect(),
                notes: Some("MySQL DATE_ADD with INTERVAL."),
            },
            ClauseVariant {
                syntax: "date + INTERVAL 'amount unit'",
                accepted_by: vec![DbmsFamily::PostgreSQL],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::PostgreSQL).copied().collect(),
                notes: Some("PostgreSQL interval arithmetic."),
            },
            ClauseVariant {
                syntax: "date + amount",
                accepted_by: vec![DbmsFamily::Oracle],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::Oracle).copied().collect(),
                notes: Some("Oracle date + number (days)."),
            },
            ClauseVariant {
                syntax: "DATETIME(date, '+amount unit')",
                accepted_by: vec![DbmsFamily::SQLite],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::SQLite).copied().collect(),
                notes: Some("SQLite DATETIME modifier."),
            },
        ],
    },
    SqlClauseMap {
        clause: SqlClause::DateDiff,
        description: "Difference between two dates",
        variants: vec![
            ClauseVariant {
                syntax: "DATEDIFF(unit, date1, date2)",
                accepted_by: vec![DbmsFamily::MSSQL],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::MSSQL).copied().collect(),
                notes: Some("MSSQL DATEDIFF."),
            },
            ClauseVariant {
                syntax: "DATEDIFF(date1, date2)",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::MySQL && **d != DbmsFamily::MariaDB).copied().collect(),
                notes: Some("MySQL DATEDIFF (days only)."),
            },
            ClauseVariant {
                syntax: "date1 - date2",
                accepted_by: vec![DbmsFamily::Oracle, DbmsFamily::PostgreSQL],
                rejected_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::MSSQL, DbmsFamily::SQLite],
                notes: Some("Oracle/PG date subtraction (days or interval)."),
            },
            ClauseVariant {
                syntax: "JULIANDAY(date1) - JULIANDAY(date2)",
                accepted_by: vec![DbmsFamily::SQLite],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::SQLite).copied().collect(),
                notes: Some("SQLite JULIANDAY difference."),
            },
        ],
    },
    // ═══ DDL ═══
    SqlClauseMap {
        clause: SqlClause::CreateTable,
        description: "Create a new table",
        variants: vec![
            ClauseVariant {
                syntax: "CREATE TABLE name (col1 type1, col2 type2)",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("Type names differ per dialect."),
            },
            ClauseVariant {
                syntax: "CREATE TABLE IF NOT EXISTS name (...)",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::PostgreSQL, DbmsFamily::SQLite],
                rejected_by: vec![DbmsFamily::MSSQL, DbmsFamily::Oracle],
                notes: Some("MSSQL: IF NOT EXISTS (SELECT ...). Oracle: no IF NOT EXISTS."),
            },
            ClauseVariant {
                syntax: "CREATE TABLE name AS SELECT ...",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("CTAS — create table as select."),
            },
        ],
    },
    SqlClauseMap {
        clause: SqlClause::AlterTable,
        description: "Modify an existing table",
        variants: vec![
            ClauseVariant {
                syntax: "ALTER TABLE name ADD col type",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
            ClauseVariant {
                syntax: "ALTER TABLE name DROP COLUMN col",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("SQLite requires 3.35.0+ for DROP COLUMN."),
            },
            ClauseVariant {
                syntax: "ALTER TABLE name ALTER COLUMN col TYPE new_type",
                accepted_by: vec![DbmsFamily::PostgreSQL, DbmsFamily::MSSQL],
                rejected_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::Oracle, DbmsFamily::SQLite],
                notes: Some("MySQL: MODIFY COLUMN. Oracle: MODIFY. SQLite: no ALTER COLUMN."),
            },
            ClauseVariant {
                syntax: "ALTER TABLE name MODIFY COLUMN col new_type",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::Oracle],
                rejected_by: vec![DbmsFamily::PostgreSQL, DbmsFamily::MSSQL, DbmsFamily::SQLite],
                notes: Some("MySQL/Oracle MODIFY."),
            },
        ],
    },
    SqlClauseMap {
        clause: SqlClause::DropTable,
        description: "Drop a table",
        variants: vec![
            ClauseVariant {
                syntax: "DROP TABLE name",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
            ClauseVariant {
                syntax: "DROP TABLE IF EXISTS name",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::PostgreSQL, DbmsFamily::SQLite],
                rejected_by: vec![DbmsFamily::MSSQL, DbmsFamily::Oracle],
                notes: Some("MSSQL: IF OBJECT_ID(...) IS NOT NULL. Oracle: no IF EXISTS."),
            },
        ],
    },
    SqlClauseMap {
        clause: SqlClause::CreateIndex,
        description: "Create an index",
        variants: vec![
            ClauseVariant {
                syntax: "CREATE INDEX idx_name ON table_name (col)",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
            ClauseVariant {
                syntax: "CREATE UNIQUE INDEX idx_name ON table_name (col)",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: None,
            },
        ],
    },
    // ═══ Utility clauses ═══
    SqlClauseMap {
        clause: SqlClause::IfExists,
        description: "Conditional existence check",
        variants: vec![
            ClauseVariant {
                syntax: "IF EXISTS (SELECT 1 FROM ...)",
                accepted_by: vec![DbmsFamily::MSSQL],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::MSSQL).copied().collect(),
                notes: Some("MSSQL procedural IF EXISTS."),
            },
            ClauseVariant {
                syntax: "SELECT EXISTS (SELECT 1 FROM ...)",
                accepted_by: vec![DbmsFamily::PostgreSQL, DbmsFamily::MySQL, DbmsFamily::MariaDB],
                rejected_by: vec![DbmsFamily::MSSQL, DbmsFamily::Oracle, DbmsFamily::SQLite],
                notes: Some("Returns boolean directly."),
            },
        ],
    },
    SqlClauseMap {
        clause: SqlClause::AutoIncrement,
        description: "Auto-incrementing primary key",
        variants: vec![
            ClauseVariant {
                syntax: "col INT AUTO_INCREMENT PRIMARY KEY",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::MySQL && **d != DbmsFamily::MariaDB).copied().collect(),
                notes: Some("MySQL AUTO_INCREMENT."),
            },
            ClauseVariant {
                syntax: "col SERIAL PRIMARY KEY",
                accepted_by: vec![DbmsFamily::PostgreSQL],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::PostgreSQL).copied().collect(),
                notes: Some("PG SERIAL. PG 10+: GENERATED ALWAYS AS IDENTITY."),
            },
            ClauseVariant {
                syntax: "col INT IDENTITY(1,1) PRIMARY KEY",
                accepted_by: vec![DbmsFamily::MSSQL],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::MSSQL).copied().collect(),
                notes: Some("MSSQL IDENTITY."),
            },
            ClauseVariant {
                syntax: "col INTEGER PRIMARY KEY AUTOINCREMENT",
                accepted_by: vec![DbmsFamily::SQLite],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::SQLite).copied().collect(),
                notes: Some("SQLite AUTOINCREMENT."),
            },
            ClauseVariant {
                syntax: "col NUMBER GENERATED ALWAYS AS IDENTITY",
                accepted_by: vec![DbmsFamily::Oracle],
                rejected_by: DbmsFamily::ALL.iter().filter(|d| **d != DbmsFamily::Oracle).copied().collect(),
                notes: Some("Oracle 12c+ identity column."),
            },
        ],
    },
    SqlClauseMap {
        clause: SqlClause::BooleanLiteral,
        description: "Boolean literals",
        variants: vec![
            ClauseVariant {
                syntax: "TRUE / FALSE",
                accepted_by: vec![DbmsFamily::PostgreSQL, DbmsFamily::MySQL, DbmsFamily::MariaDB, DbmsFamily::SQLite],
                rejected_by: vec![DbmsFamily::MSSQL, DbmsFamily::Oracle],
                notes: Some("MSSQL: 1/0. Oracle: 1/0 (no native boolean in SQL)."),
            },
            ClauseVariant {
                syntax: "1 / 0",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("Universal workaround for boolean literals."),
            },
        ],
    },
    SqlClauseMap {
        clause: SqlClause::Comment,
        description: "SQL comments",
        variants: vec![
            ClauseVariant {
                syntax: "-- comment",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("Universal single-line comment."),
            },
            ClauseVariant {
                syntax: "/* comment */",
                accepted_by: DbmsFamily::ALL.to_vec(),
                rejected_by: vec![],
                notes: Some("Universal multi-line comment."),
            },
            ClauseVariant {
                syntax: "# comment",
                accepted_by: vec![DbmsFamily::MySQL, DbmsFamily::MariaDB],
                rejected_by: vec![DbmsFamily::PostgreSQL, DbmsFamily::MSSQL, DbmsFamily::Oracle, DbmsFamily::SQLite],
                notes: Some("MySQL-specific single-line comment."),
            },
        ],
    },
];

/// Summary of clause coverage for a specific DBMS family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DialectCoverage {
    pub dbms: DbmsFamily,
    pub total_clauses: usize,
    pub accepted_variants: usize,
    pub rejected_variants: usize,
}

/// Compute coverage statistics for every DBMS family.
pub fn coverage_report() -> Vec<DialectCoverage> {
    let mut report = Vec::new();
    for &dbms in DbmsFamily::ALL {
        let mut accepted = 0;
        let mut rejected = 0;
        for map in CLAUSE_MAP {
            for variant in &map.variants {
                if variant.accepted_by.contains(&dbms) {
                    accepted += 1;
                }
                if variant.rejected_by.contains(&dbms) {
                    rejected += 1;
                }
            }
        }
        report.push(DialectCoverage {
            dbms,
            total_clauses: CLAUSE_MAP.len(),
            accepted_variants: accepted,
            rejected_variants: rejected,
        });
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_clauses_have_variants() {
        for map in CLAUSE_MAP {
            assert!(!map.variants.is_empty(), "clause {:?} has no variants", map.clause);
        }
    }

    #[test]
    fn universal_select_works_everywhere() {
        let accepting = dialects_accepting(SqlClause::Select, "SELECT * FROM table_name");
        assert_eq!(accepting.len(), DbmsFamily::ALL.len());
    }

    #[test]
    fn limit_not_in_mssql_or_oracle() {
        let accepting = dialects_accepting(SqlClause::LimitOffset, "LIMIT n");
        assert!(!accepting.contains(&DbmsFamily::MSSQL));
        assert!(!accepting.contains(&DbmsFamily::Oracle));
    }

    #[test]
    fn top_only_in_mssql() {
        let accepting = dialects_accepting(SqlClause::Select, "SELECT TOP n col FROM table_name");
        assert!(accepting.contains(&DbmsFamily::MSSQL));
        assert!(!accepting.contains(&DbmsFamily::PostgreSQL));
    }

    #[test]
    fn mysql_concat_not_in_oracle() {
        let accepting = dialects_accepting(SqlClause::StringConcat, "CONCAT(col1, col2)");
        assert!(!accepting.contains(&DbmsFamily::Oracle));
        assert!(accepting.contains(&DbmsFamily::MySQL));
    }

    #[test]
    fn pg_cast_operator_only_in_pg() {
        let accepting = dialects_accepting(SqlClause::Cast, "col::type");
        assert_eq!(accepting, vec![DbmsFamily::PostgreSQL]);
    }

    #[test]
    fn right_join_not_in_sqlite() {
        let accepted_by_sqlite = variants_accepted_by(DbmsFamily::SQLite, SqlClause::JoinRight);
        assert!(accepted_by_sqlite.is_empty());
    }

    #[test]
    fn coverage_report_all_dialects() {
        let report = coverage_report();
        assert_eq!(report.len(), DbmsFamily::ALL.len());
        for r in &report {
            assert!(r.accepted_variants > 0);
        }
    }
}
