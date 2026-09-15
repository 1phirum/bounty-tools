use crate::rate_limiter::TokenBucket;
use crate::traffic::{TrafficSource, TrafficStore};
use bugtools_core::http::{HttpRequest, HttpResponse};
use chrono::Utc;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum FuzzerError {
    #[error("No fuzz positions defined")]
    NoPositions,
    #[error("Position {marker} has an empty payload set")]
    EmptyPayloadSet { marker: String },
    #[error("Expanded combos ({count}) exceed the per-run ceiling ({max})")]
    TooManyCombos { count: usize, max: usize },
    #[error("Run aborted: {count} consecutive failures (ceiling {ceiling})")]
    TooManyFailures { count: usize, ceiling: usize },
}

/// One marker (e.g. `§id§`) and the analyst-supplied payloads for it.
/// The engine never invents payloads — it only orchestrates dispatch.
#[derive(Debug, Clone)]
pub struct FuzzPosition {
    pub marker: String,
    pub payloads: Vec<String>,
}

/// Per-run tuning knobs with safe defaults.
#[derive(Debug, Clone)]
pub struct FuzzRunOptions {
    pub concurrency: usize,
    /// Abort the run after this many consecutive request failures.
    pub max_consecutive_failures: usize,
}

impl Default for FuzzRunOptions {
    fn default() -> Self {
        Self { concurrency: 4, max_consecutive_failures: 20 }
    }
}

/// Outcome of one fuzz iteration, for the results grid.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FuzzIterationResult {
    pub replacements: HashMap<String, String>,
    pub status: u16,
    pub duration_ms: u64,
    pub size_bytes: usize,
    /// Normalized body hash — compare across iterations to spot anomalies
    /// (one payload producing a structurally different response).
    pub body_hash: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FuzzRunSummary {
    pub total: usize,
    pub completed: usize,
    pub failed: usize,
    pub deduped: usize,
    pub results: Vec<FuzzIterationResult>,
}

/// Parameterized payload dispatcher (the "Intruder" analog): expand a
/// cartesian product of positions, render the template, scope-check
/// every rendered URL, rate-limit, and dispatch with bounded concurrency.
pub struct Fuzzer {
    scope: Arc<bugtools_scope::ScopeEngine>,
    limiter: Arc<TokenBucket>,
    store: Arc<TrafficStore>,
    http: reqwest::Client,
}

impl Fuzzer {
    pub fn new(
        scope: Arc<bugtools_scope::ScopeEngine>,
        limiter: Arc<TokenBucket>,
        store: Arc<TrafficStore>,
    ) -> Self {
        Self { scope, limiter, store, http: reqwest::Client::new() }
    }

    /// Expand positions into concrete replacement combos (cartesian,
    /// bounded by `max_combos`). Errors before any network I/O so a
    /// runaway wordlist cannot start hammering the target.
    pub fn expand(&self, positions: &[FuzzPosition], max_combos: usize) -> Result<Vec<HashMap<String, String>>, FuzzerError> {
        if positions.is_empty() {
            return Err(FuzzerError::NoPositions);
        }
        for pos in positions {
            if pos.payloads.is_empty() {
                return Err(FuzzerError::EmptyPayloadSet { marker: pos.marker.clone() });
            }
        }

        let mut combos: Vec<HashMap<String, String>> = vec![HashMap::new()];
        for pos in positions {
            let mut next: Vec<HashMap<String, String>> = Vec::with_capacity(combos.len() * pos.payloads.len());
            for combo in &combos {
                for payload in &pos.payloads {
                    let mut c = combo.clone();
                    c.insert(pos.marker.clone(), payload.clone());
                    next.push(c);
                }
                if next.len() > max_combos {
                    return Err(FuzzerError::TooManyCombos { count: next.len(), max: max_combos });
                }
            }
            combos = next;
        }
        Ok(combos)
    }

    /// Substitute markers in the request template. Pure — returns a new
    /// request. Markers may appear in the URL and/or body.
    pub fn render_template(base: &HttpRequest, replacements: &HashMap<String, String>) -> HttpRequest {
        let mut url = base.url.clone();
        let mut body = base.body.clone().unwrap_or_default();
        for (marker, value) in replacements {
            let token = format!("§{}§", marker);
            url = url.replace(&token, value);
            body = body.replace(&token, value);
        }
        HttpRequest {
            id: Uuid::new_v4(),
            job_id: base.job_id,
            url,
            method: base.method.clone(),
            headers: base.headers.clone(),
            body: if body.is_empty() { None } else { Some(body) },
            timestamp: Utc::now(),
        }
    }

    /// Execute a full fuzz run. Every rendered request is individually
    /// scope-checked; an out-of-scope render fails the iteration (and
    /// counts toward the failure ceiling) rather than being sent.
    pub async fn run(
        &self,
        base: &HttpRequest,
        positions: &[FuzzPosition],
        max_combos: usize,
        options: FuzzRunOptions,
    ) -> Result<FuzzRunSummary, FuzzerError> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let combos = self.expand(positions, max_combos)?;
        let combos_len = combos.len();
        let concurrency = options.concurrency.clamp(1, 32);

        let completed = Arc::new(AtomicUsize::new(0));
        let failed = Arc::new(AtomicUsize::new(0));
        let deduped = Arc::new(AtomicUsize::new(0));

        let results: Arc<std::sync::Mutex<Vec<FuzzIterationResult>>> =
            Arc::new(std::sync::Mutex::new(Vec::with_capacity(combos.len())));

        let queue: Arc<std::sync::Mutex<VecDeque<HashMap<String, String>>>> =
            Arc::new(std::sync::Mutex::new(combos.into_iter().collect::<VecDeque<_>>()));

        let mut handles = Vec::with_capacity(concurrency);
        let queue_len = match queue.lock() {
            Ok(q) => q.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        };
        for _ in 0..concurrency.min(queue_len) {
            let scope = self.scope.clone();
            let limiter = self.limiter.clone();
            let store = self.store.clone();
            let http = self.http.clone();
            let queue = queue.clone();
            let results = results.clone();
            let completed = completed.clone();
            let failed = failed.clone();
            let deduped = deduped.clone();
            let max_failures = options.max_consecutive_failures;
            let base = base.clone();

            handles.push(tokio::spawn(async move {
                loop {
                    if failed.load(Ordering::SeqCst) >= max_failures {
                        // Drain the queue so all workers exit promptly.
                        if let Ok(mut q) = queue.lock() {
                            q.clear();
                        }
                        return;
                    }
                    let next = match queue.lock() {
                        Ok(mut q) => q.pop_front(),
                        Err(poisoned) => poisoned.into_inner().pop_front(),
                    };
                    let replacements = match next {
                        Some(r) => r,
                        None => return,
                    };

                    let rendered = Fuzzer::render_template(&base, &replacements);

                    // Scope check per rendered request.
                    let eval = scope.evaluate(&rendered.url);
                    if !eval.allowed {
                        failed.fetch_add(1, Ordering::SeqCst);
                        continue;
                    }

                    // Rate limit: wait for a token before touching the wire.
                    let wait = limiter.wait_duration();
                    if !wait.is_zero() {
                        tokio::time::sleep(wait).await;
                    }
                    while !limiter.try_acquire() {
                        tokio::time::sleep(limiter.wait_duration()).await;
                    }

                    let start = std::time::Instant::now();
                    let builder = match rendered.method.to_uppercase().as_str() {
                        "POST" => http.post(&rendered.url),
                        "PUT" => http.put(&rendered.url),
                        "DELETE" => http.delete(&rendered.url),
                        "PATCH" => http.patch(&rendered.url),
                        "HEAD" => http.head(&rendered.url),
                        _ => http.get(&rendered.url),
                    };
                    let builder = rendered.headers.iter().fold(builder, |b, (k, v)| b.header(k, v));
                    let builder = match &rendered.body {
                        Some(b) => builder.body(b.clone()),
                        None => builder,
                    };

                    match builder.send().await {
                        Ok(resp) => {
                            let duration_ms = start.elapsed().as_millis() as u64;
                            let status_code = resp.status().as_u16();
                            let mut headers = HashMap::new();
                            for (k, v) in resp.headers() {
                                if let Ok(val) = v.to_str() {
                                    headers.insert(k.as_str().to_string(), val.to_string());
                                }
                            }
                            let body = resp.text().await.unwrap_or_default();
                            let size_bytes = body.len();

                            // Normalized body hash for anomaly comparison.
                            let fingerprinter = bugtools_fingerprint::ResponseFingerprinter::default();
                            let body_hash = fingerprinter.compute_hash(&fingerprinter.normalize_body(&body));

                            let response = HttpResponse {
                                id: Uuid::new_v4(),
                                request_id: rendered.id,
                                status_code,
                                headers,
                                body,
                                size_bytes,
                                duration_ms,
                                timestamp: Utc::now(),
                            };

                            let fp = TrafficStore::fingerprint_request(&rendered);
                            let stored = store.append(crate::traffic::TrafficEntry {
                                id: Uuid::new_v4(),
                                request: rendered,
                                response: Some(response),
                                captured_at: Utc::now(),
                                fingerprint: fp,
                                source: TrafficSource::Fuzzer,
                            });

                            if stored {
                                completed.fetch_add(1, Ordering::SeqCst);
                            } else {
                                deduped.fetch_add(1, Ordering::SeqCst);
                            }

                            {
                                let mut r = match results.lock() {
                                    Ok(r) => r,
                                    Err(poisoned) => poisoned.into_inner(),
                                };
                                r.push(FuzzIterationResult {
                                    replacements,
                                    status: status_code,
                                    duration_ms,
                                    size_bytes,
                                    body_hash,
                                });
                            }
                        }
                        Err(_) => {
                            failed.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            }));
        }

        for handle in handles {
            let _ = handle.await;
        }

        let final_results = match results.lock() {
            Ok(r) => r.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };

        Ok(FuzzRunSummary {
            total: combos_len + completed.load(Ordering::SeqCst)
                + failed.load(Ordering::SeqCst) + deduped.load(Ordering::SeqCst),
            completed: completed.load(Ordering::SeqCst),
            failed: failed.load(Ordering::SeqCst),
            deduped: deduped.load(Ordering::SeqCst),
            results: final_results,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_req() -> HttpRequest {
        HttpRequest {
            id: Uuid::new_v4(),
            job_id: None,
            url: "https://api.example.com/items/§id§".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: None,
            timestamp: Utc::now(),
        }
    }

    fn scope() -> Arc<bugtools_scope::ScopeEngine> {
        let engine = bugtools_scope::ScopeEngine::new();
        use bugtools_core::scope::{ScopeRule, ScopeRuleType};
        let project_id = Uuid::new_v4();
        engine.add_rule(ScopeRule::new(project_id, ScopeRuleType::IncludeDomain, "*.example.com"));
        Arc::new(engine)
    }

    fn fuzzer() -> Fuzzer {
        Fuzzer::new(
            scope(),
            Arc::new(TokenBucket::new(100.0, 100.0)),
            Arc::new(TrafficStore::new(100)),
        )
    }

    #[test]
    fn expand_cartesian_bounded() {
        let f = fuzzer();
        let positions = vec![
            FuzzPosition { marker: "a".into(), payloads: vec!["1".into(), "2".into()] },
            FuzzPosition { marker: "b".into(), payloads: vec!["x".into(), "y".into(), "z".into()] },
        ];
        let combos = f.expand(&positions, 100).unwrap();
        assert_eq!(combos.len(), 6);
    }

    #[test]
    fn expand_rejects_ceiling() {
        let f = fuzzer();
        let positions = vec![
            FuzzPosition { marker: "a".into(), payloads: vec!["1".into(), "2".into(), "3".into()] },
        ];
        assert!(matches!(f.expand(&positions, 2), Err(FuzzerError::TooManyCombos { .. })));
    }

    #[test]
    fn expand_rejects_empty_payloads() {
        let f = fuzzer();
        let positions = vec![FuzzPosition { marker: "a".into(), payloads: vec![] }];
        assert!(matches!(f.expand(&positions, 10), Err(FuzzerError::EmptyPayloadSet { .. })));
    }

    #[test]
    fn render_substitutes_markers() {
        let base = base_req();
        let mut replacements = HashMap::new();
        replacements.insert("id".to_string(), "99".to_string());
        let rendered = Fuzzer::render_template(&base, &replacements);
        assert_eq!(rendered.url, "https://api.example.com/items/99");
        // Template not mutated.
        assert!(base.url.contains("§id§"));
    }
}
