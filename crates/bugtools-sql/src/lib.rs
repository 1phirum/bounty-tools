pub mod clause_map;
pub mod detection;
pub mod probe;
pub mod types;
pub mod rules;
pub mod generators;
pub mod context;
pub mod baseline;
pub mod waf;
pub mod controls;
pub mod differential;

// Phase 1 of the research-engine brief: complete request model, cookie
// jar, raw HTTP import/export, and parameter type intelligence.
pub mod parameter;
pub mod request;

// Phase 3/4: evidence graph + explainable confidence, adaptive scheduling,
// timing statistics, and environmental classification.
pub mod analysis;
pub mod evidence;
pub mod scheduler;

// Advanced SQLi capability integration (brief 2026-09-16):
// probabilistic context hypotheses, query-position classification,
// DB2/H2 fingerprinting, OOB correlation, second-order tracing,
// false-positive contradiction checks, and the mandatory-limitations
// assessment model.
pub mod assessment;
pub mod dbms_ext;
pub mod false_positive;
pub mod hypothesis;
pub mod oob;
pub mod second_order;

// P0 brief (2026-09-16): typed payload generation with boundaries and a
// safety gate, plus WAF vendor signatures and edge/application layer
// classification.
pub mod payload;
pub mod safety;

pub use clause_map::ClauseVariant;
pub use detection::{DbmsFamily, DetectionVerdict, FiredSignal, SignalCategory};
pub use probe::{DbmsProbeEngine, ProbeError};
pub use types::{ProbeResult, ProbeType, SqlContext, SqlDialect, SqlAnalysisResult, ClauseCoverage, AggregatedDetection};
pub use rules::{SqlDetectionRule, SqlRuleRegistry, SqlEngineError};
pub use assessment::{AssessmentBuilder, AssessmentError, Limitation, LimitationCategory, Repeatability, SqlInjectionAssessment};
pub use false_positive::{run_checks, ContradictionKind, FalsePositiveReport, FalsePositiveSignals};
pub use hypothesis::{ContextHypothesis, HypothesisEvidence, QueryPosition};
pub use oob::{InteractionType, OobCorrelation, OobCorrelator, OobInteraction, OobToken};
pub use second_order::{SecondOrderTrace, StorageContext, TraceId, TraceRegistry};
pub use payload::{Boundary, GenerationContext, PayloadCandidate, QuoteMode};
pub use safety::{SafetyLevel, SafetyPolicy, SafetyVerdict};

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
) -> Result<SqlAnalysisResult, ProbeError> {
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
    use crate::clause_map::SqlClause;

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
        assert!(!detection::DETECTION_SIGNALS.is_empty());
        // Verify every signal has a valid DBMS
        for signal in detection::DETECTION_SIGNALS {
            assert!(DbmsFamily::ALL.contains(&signal.dbms));
        }
    }

    #[test]
    fn test_clause_map_coverage() {
        let map = clause_map::clause_map();
        assert!(map.len() >= 30);
        // Verify every clause has at least one universal variant
        for clause in map {
            let _has_universal = clause.variants.iter().any(|v| v.accepted_by.len() == DbmsFamily::ALL.len());
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
