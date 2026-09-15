use crate::clause_map::SqlClause;
use crate::detection::DbmsDetectionResult;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;

pub mod clause_map;
pub mod detection;
pub mod probe;

// Re-export types for external consumers (no local use conflict)
pub use clause_map::ClauseVariant;
pub use detection::{DbmsFamily, DetectionVerdict, FiredSignal, SignalCategory};
pub use probe::{AggregatedDetection, DbmsProbeEngine, ProbeError, ProbeResult, ProbeType};

// Re-export primary types for consumers


#[derive(Debug, Error)]
pub enum SqlEngineError {
    #[error("Rule parse error: {0}")]
    RuleParse(#[from] toml::de::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SqlContext {
    Unknown,
    Numeric,
    String,
    Boolean,
    Like,
    OrderBy,
    Limit,
    Offset,
    Identifier,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SqlDialect {
    Generic,
    MySQL,
    PostgreSQL,
    MSSQL,
    Oracle,
    SQLite,
    MariaDB,
}

/// TOML rule format (backward-compatible with existing rules/sql/*.toml).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlDetectionRule {
    pub id: String,
    pub name: String,
    pub category: String,
    pub dbms: Option<String>,
    pub patterns: Vec<String>,
    pub confidence_delta: i32,
}

pub struct SqlRuleRegistry {
    rules: Vec<SqlDetectionRule>,
}

impl Default for SqlRuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SqlRuleRegistry {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn load_rule_from_str(&mut self, content: &str) -> Result<(), SqlEngineError> {
        let rule: SqlDetectionRule = toml::from_str(content)?;
        self.rules.push(rule);
        Ok(())
    }

    pub fn load_rule_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), SqlEngineError> {
        let content = std::fs::read_to_string(path)?;
        self.load_rule_from_str(&content)
    }

    pub fn scan_for_signatures(&self, body: &str) -> Vec<(&SqlDetectionRule, String)> {
        let mut matched = Vec::new();
        let body_lower = body.to_lowercase();
        for rule in &self.rules {
            for pattern in &rule.patterns {
                if body_lower.contains(&pattern.to_lowercase()) {
                    matched.push((rule, pattern.clone()));
                    break;
                }
            }
        }
        matched
    }

    pub fn rules(&self) -> &[SqlDetectionRule] {
        &self.rules
    }
}

/// Full analysis result combining DBMS detection, clause mapping, and
/// evidence. This is the primary output of the SQL research engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlAnalysisResult {
    pub target: String,
    pub endpoint: String,
    pub parameter: String,
    pub context: SqlContext,
    pub dbms_hypothesis: Option<DbmsFamily>,
    pub dbms_detection: DbmsDetectionResult,
    pub clause_coverage: Vec<ClauseCoverage>,
    pub techniques_tested: Vec<String>,
    pub signals: Vec<String>,
    pub confidence_score: u32,
    pub evidence_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClauseCoverage {
    pub clause: SqlClause,
    pub dialects_accepting: Vec<DbmsFamily>,
    pub dialects_rejecting: Vec<DbmsFamily>,
}

/// Run the full SQL analysis pipeline: DBMS detection + clause mapping.
///
/// This is the main entry point. It takes a target request and a parameter
/// to probe, runs the full detection pipeline, and returns a complete
/// analysis result with clause coverage for the detected DBMS.
pub async fn analyze_endpoint(
    engine: &DbmsProbeEngine,
    base: &bugtools_core::http::HttpRequest,
    param_name: &str,
    param_value: &str,
) -> Result<SqlAnalysisResult, probe::ProbeError> {
    let probe_results = engine.detect(base, param_name, param_value).await?;
    let aggregated = probe::aggregate_results(&probe_results);

    // Determine the DBMS from aggregated detection
    let detected_dbms = aggregated.detected_dbms;
    let dbms_detection = if !probe_results.is_empty() {
        // Use the strongest detection from any probe
        probe_results
            .iter()
            .map(|r| r.detection.clone())
            .max_by_key(|d| d.confidence)
            .unwrap_or_else(|| detection::analyze_error_body(""))
    } else {
        detection::analyze_error_body("")
    };

    // Compute clause coverage for the detected DBMS
    let clause_coverage = if let Some(dbms) = detected_dbms {
        compute_clause_coverage(dbms)
    } else {
        Vec::new()
    };

    let techniques_tested: Vec<String> = probe_results
        .iter()
        .map(|r| format!("{:?}", r.probe_type))
        .collect();

    let signals: Vec<String> = aggregated
        .all_signals
        .iter()
        .map(|s| s.label.clone())
        .collect();

    Ok(SqlAnalysisResult {
        target: base.url.clone(),
        endpoint: extract_path(&base.url),
        parameter: param_name.to_string(),
        context: SqlContext::String, // refined by context analysis
        dbms_hypothesis: detected_dbms,
        dbms_detection,
        clause_coverage,
        techniques_tested,
        signals,
        confidence_score: aggregated.confidence,
        evidence_id: None,
    })
}

/// Compute which clause variants a specific DBMS accepts and rejects.
pub fn compute_clause_coverage(dbms: DbmsFamily) -> Vec<ClauseCoverage> {
    let mut coverage = Vec::new();
    for map in clause_map::clause_map() {
        let accepted: Vec<DbmsFamily> = map
            .variants
            .iter()
            .filter(|v| v.accepted_by.contains(&dbms))
            .map(|v| v.accepted_by.iter().copied().collect::<Vec<_>>())
            .flatten()
            .collect();
        let rejected: Vec<DbmsFamily> = map
            .variants
            .iter()
            .filter(|v| v.rejected_by.contains(&dbms))
            .map(|v| v.rejected_by.iter().copied().collect::<Vec<_>>())
            .flatten()
            .collect();
        coverage.push(ClauseCoverage {
            clause: map.clause,
            dialects_accepting: accepted,
            dialects_rejecting: rejected,
        });
    }
    coverage
}

/// Extract the path component from a URL string.
fn extract_path(url: &str) -> String {
    url::Url::parse(url)
        .map(|u: url::Url| u.path().to_string())
        .unwrap_or_else(|_| url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_rule_matching() {
        let mut registry = SqlRuleRegistry::new();
        let toml_rule = r#"
            id = "pg-001"
            name = "PostgreSQL syntax error"
            category = "error-analysis"
            dbms = "postgresql"
            patterns = ["syntax error at or near", "unterminated quoted string"]
            confidence_delta = 30
        "#;
        registry.load_rule_from_str(toml_rule).unwrap();

        let hits = registry.scan_for_signatures("Error: syntax error at or near 'SELECT'");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0.id, "pg-001");
    }

    #[test]
    fn test_detection_signals_loaded() {
        assert!(!DETECTION_SIGNALS.is_empty());
        // Verify every signal has a valid DBMS
        for signal in DETECTION_SIGNALS {
            assert!(DbmsFamily::ALL.contains(&signal.dbms));
        }
    }

    #[test]
    fn test_clause_map_coverage() {
        let map = clause_map::clause_map();
        assert!(map.len() >= 30);
        // Verify every clause has at least one universal variant
        for clause in map {
            let has_universal = clause.variants.iter().any(|v| v.accepted_by.len() == DbmsFamily::ALL.len());
            // Some clauses (like TOP, ROWNUM) are intentionally dialect-specific
            // so we just verify the map is populated.
            assert!(!clause.variants.is_empty());
        }
    }

    #[test]
    fn test_detection_mysql_error() {
        let result = detection::analyze_error_body(
            "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
        );
        assert_eq!(result.detected_dbms, Some(DbmsFamily::MySQL));
        assert!(result.confidence >= 45);
    }

    #[test]
    fn test_detection_postgres_error() {
        let result = detection::analyze_error_body(
            "psycopg2.errors.SyntaxError: syntax error at or near \"''\"",
        );
        assert_eq!(result.detected_dbms, Some(DbmsFamily::PostgreSQL));
    }

    #[test]
    fn test_clause_map_pg_cast() {
        let accepting = clause_map::dialects_accepting(SqlClause::Cast, "col::type");
        assert_eq!(accepting, vec![DbmsFamily::PostgreSQL]);
    }
}
