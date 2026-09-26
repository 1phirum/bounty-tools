use crate::clause_map::{self, SqlClause};
use crate::detection::{self, DbmsFamily};
use crate::types::{AggregatedDetection, ProbeResult, ProbeType};
use crate::generators::{self, GeneratedPayload};
use crate::waf::classifier;
use crate::waf::models::ResponseOrigin;
use crate::waf::origin::OriginReachabilityEngine;
use bugtools_core::http::{HttpRequest, HttpResponse};
use bugtools_http::profile::RequestProfile;
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

/// The scalable probe engine orchestrator.
/// This engine is strictly responsible for execution and delegates
/// payload generation to the expert modules in `generators/`.
pub struct DbmsProbeEngine {
    scope: Arc<ScopeEngine>,
    http: reqwest::Client,
    fingerprinter: ResponseFingerprinter,
    profile: RequestProfile,
}

impl DbmsProbeEngine {
    pub fn new(scope: Arc<ScopeEngine>) -> Self {
        Self {
            scope,
            http: reqwest::Client::new(),
            fingerprinter: ResponseFingerprinter::new(),
            profile: RequestProfile::PROFILE_STABLE_CHROME,
        }
    }

    /// Run the full detection pipeline against a parameterized endpoint.
    ///
    /// This is the single-URL `analyze` path: the whole catalogue, once. The
    /// batch scanner shares it through [`DbmsProbeEngine::sweep`].
    pub async fn detect(
        &self,
        base: &HttpRequest,
        param_name: &str,
        _param_value: &str,
    ) -> Result<Vec<ProbeResult>, ProbeError> {
        let catalog = generators::catalog();
        // Diagnostics go to stderr: stdout carries structured results (a JSON
        // document under `--json`), and a progress line printed there would
        // make the output unparseable.
        eprintln!(
            "[*] catalogue: {} payload(s) across {} technique(s)",
            catalog.len(),
            generators::catalog_summary()
                .iter()
                .filter(|(_, n)| *n > 0)
                .count()
        );
        self.sweep(base, param_name, catalog).await
    }

    /// Run a caller-supplied payload catalogue against the endpoint.
    ///
    /// This is the shared engine: `detect` calls it with the full catalogue,
    /// while the batch scanner (`sqli`) calls it with a tier-gated, tampered
    /// subset. Both therefore execute through the same signal attribution —
    /// timing deltas, sentinel reflection, boolean divergence — instead of two
    /// implementations that drift apart.
    pub async fn sweep(
        &self,
        base: &HttpRequest,
        param_name: &str,
        payloads: Vec<GeneratedPayload>,
    ) -> Result<Vec<ProbeResult>, ProbeError> {
        let mut results = Vec::new();

        // Phase 1: Baseline
        let (baseline, raw_resp) = self.baseline_probe(base).await?;
        results.push(baseline.clone());

        // Phase 1b: WAF Classification on Baseline
        let waf_obs = classifier::classify_origin(&raw_resp);
        let reachability = OriginReachabilityEngine::assess(&waf_obs, &raw_resp);
        println!("Baseline Reachability: {:?}", reachability.state);
        if waf_obs.origin == ResponseOrigin::CloudflareWaf
            || waf_obs.origin == ResponseOrigin::CloudflareChallenge
            || waf_obs.origin == ResponseOrigin::CloudflareRateLimit
        {
            // Do not abort: the response is recorded so nothing downstream can
            // mistake an edge block for SQL evidence.
            eprintln!("[!] baseline intercepted by WAF: {:?}", waf_obs.action);
        }

        results.extend(self.run_payloads(base, param_name, &baseline, payloads).await?);

        Ok(results)
    }

    /// Baseline: send the request as-is, capture the reference response.
    async fn baseline_probe(&self, base: &HttpRequest) -> Result<(ProbeResult, HttpResponse), ProbeError> {
        self.scope.evaluate(&base.url).allowed
            .then(|| ())
            .ok_or_else(|| ProbeError::OutOfScope(base.url.clone()))?;

        let mut req = base.clone();
        for (k, v) in self.profile.generate_headers() {
            req.headers.insert(k, v);
        }

        let start = std::time::Instant::now();
        let resp = self.send(&req).await?;
        let duration_ms = start.elapsed().as_millis() as u64;

        let body_hash = self.fingerprinter.compute_hash(
            &self.fingerprinter.normalize_body(&resp.body),
        );

        Ok((ProbeResult {
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
        }, resp))
    }

    /// Run a batch of payloads through the engine, evaluating the results based on their type.
    async fn run_payloads(
        &self,
        base: &HttpRequest,
        param_name: &str,
        baseline: &ProbeResult,
        payloads: Vec<GeneratedPayload>,
    ) -> Result<Vec<ProbeResult>, ProbeError> {
        let mut results = Vec::new();

        for payload_def in payloads {
            let probe_req = self.build_probe(base, param_name, &payload_def.payload_str);
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

            let dialects_confirmed = match payload_def.probe_type {
                ProbeType::TimingProbe => {
                    let timing_delta = duration_ms as i64 - baseline.response_duration_ms as i64;
                    if timing_delta > 3000 {
                        payload_def.expected_dbms.map_or(vec![], |d| vec![d])
                    } else if detection.detected_dbms == payload_def.expected_dbms {
                        payload_def.expected_dbms.map_or(vec![], |d| vec![d])
                    } else {
                        vec![]
                    }
                }
                ProbeType::SyntaxFeature => {
                    if detection.detected_dbms == payload_def.expected_dbms {
                        payload_def.expected_dbms.map_or(vec![], |d| vec![d])
                    } else {
                        vec![]
                    }
                }
                ProbeType::ClauseVariant => {
                    let clause = payload_def.clause.unwrap_or(SqlClause::Select);
                    let accepting = clause_map::dialects_accepting(clause, &payload_def.payload_str);
                    if detection.detected_dbms.is_some() {
                        vec![detection.detected_dbms.unwrap()]
                    } else if body_hash == baseline.response_body_hash {
                        accepting
                    } else {
                        vec![]
                    }
                }
                ProbeType::ErrorInjection => {
                    // Fingerprint/extraction probes: trust the dialect the
                    // error text reveals (extraction probes leak it directly).
                    detection.detected_dbms.map_or(vec![], |d| vec![d])
                }
                ProbeType::UnionBased => {
                    // Strongest signal: our sentinel was reflected in the body,
                    // meaning the injected UNION column rendered back to us.
                    if resp.body.contains(crate::generators::union_based::SENTINEL_HEAD) {
                        payload_def
                            .expected_dbms
                            .or(detection.detected_dbms)
                            .map_or(vec![], |d| vec![d])
                    } else {
                        detection.detected_dbms.map_or(vec![], |d| vec![d])
                    }
                }
                ProbeType::BooleanBlind => {
                    // A FALSE predicate that changed the page (its TRUE twin
                    // matches the baseline) shows the condition reached SQL.
                    let diverged = body_hash != baseline.response_body_hash;
                    if let Some(d) = detection.detected_dbms {
                        vec![d]
                    } else if payload_def.name.ends_with("-false") && diverged {
                        payload_def.expected_dbms.map_or(vec![], |d| vec![d])
                    } else {
                        vec![]
                    }
                }
                _ => vec![],
            };

            results.push(ProbeResult {
                probe_id: payload_def.name,
                probe_type: payload_def.probe_type,
                payload: payload_def.payload_str,
                response_status: resp.status_code,
                response_body_hash: body_hash,
                response_duration_ms: duration_ms,
                detection,
                clause_tested: payload_def.clause,
                dialects_confirmed,
                dialects_rejected: vec![],
            });
        }

        Ok(results)
    }

    /// Build a probe request by injecting a payload at the parameter.
    fn build_probe(&self, base: &HttpRequest, param_name: &str, payload: &str) -> HttpRequest {
        let mut url = base.url.clone();
        let mut headers = base.headers.clone();
        let mut body = base.body.clone();

        for (k, v) in self.profile.generate_headers() {
            headers.insert(k, v);
        }

        if param_name == "__RAW_MARKER__" {
            // Replace `*` in URL, Headers, and Body
            url = url.replace('*', payload);
            
            for val in headers.values_mut() {
                *val = val.replace('*', payload);
            }
            
            if let Some(b) = &mut body {
                *b = b.replace('*', payload);
            }
        } else {
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
        }

        HttpRequest {
            id: Uuid::new_v4(),
            job_id: base.job_id,
            url,
            method: base.method.clone(),
            headers,
            body,
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
            duration_ms: 0,
            timestamp: Utc::now(),
        })
    }
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
