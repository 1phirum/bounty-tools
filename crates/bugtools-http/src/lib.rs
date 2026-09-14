use bugtools_core::http::{HttpRequest, HttpResponse};
use bugtools_scope::ScopeEngine;
use chrono::Utc;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Semaphore;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum HttpEngineError {
    #[error("Out of scope: {0}")]
    OutOfScope(String),
    #[error("Request budget exceeded (limit: {0})")]
    BudgetExceeded(u64),
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
}

pub struct HttpClientConfig {
    pub max_concurrency: usize,
    pub rate_limit_rps: f64,
    pub timeout: Duration,
    pub max_budget: u64,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 5,
            rate_limit_rps: 5.0,
            timeout: Duration::from_secs(15),
            max_budget: 1000,
        }
    }
}

pub struct SafeHttpClient {
    client: Client,
    scope: Arc<ScopeEngine>,
    semaphore: Arc<Semaphore>,
    budget_counter: AtomicU64,
    max_budget: u64,
}

impl SafeHttpClient {
    pub fn new(scope: Arc<ScopeEngine>, config: HttpClientConfig) -> Self {
        let client = Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .unwrap_or_default();

        Self {
            client,
            scope,
            semaphore: Arc::new(Semaphore::new(config.max_concurrency)),
            budget_counter: AtomicU64::new(0),
            max_budget: config.max_budget,
        }
    }

    pub fn requests_sent(&self) -> u64 {
        self.budget_counter.load(Ordering::Relaxed)
    }

    pub async fn execute(&self, req: HttpRequest) -> Result<HttpResponse, HttpEngineError> {
        // 1. RULE 2: Scope check
        let scope_eval = self.scope.evaluate(&req.url);
        if !scope_eval.allowed {
            return Err(HttpEngineError::OutOfScope(scope_eval.reason));
        }

        // 2. Budget check
        let current_count = self.budget_counter.fetch_add(1, Ordering::SeqCst);
        if current_count >= self.max_budget {
            return Err(HttpEngineError::BudgetExceeded(self.max_budget));
        }

        // 3. Concurrency permit
        let _permit = self.semaphore.acquire().await;

        let start_time = Instant::now();
        let mut builder = match req.method.to_uppercase().as_str() {
            "POST" => self.client.post(&req.url),
            "PUT" => self.client.put(&req.url),
            "DELETE" => self.client.delete(&req.url),
            "HEAD" => self.client.head(&req.url),
            _ => self.client.get(&req.url),
        };

        for (k, v) in &req.headers {
            builder = builder.header(k, v);
        }

        if let Some(body) = &req.body {
            builder = builder.body(body.clone());
        }

        let resp = builder.send().await?;
        let duration_ms = start_time.elapsed().as_millis() as u64;
        let status_code = resp.status().as_u16();

        let mut headers = HashMap::new();
        for (k, v) in resp.headers() {
            if let Ok(val) = v.to_str() {
                headers.insert(k.as_str().to_string(), val.to_string());
            }
        }

        let body_text = resp.text().await.unwrap_or_default();
        let size_bytes = body_text.len();

        Ok(HttpResponse {
            id: Uuid::new_v4(),
            request_id: req.id,
            status_code,
            headers,
            body: body_text,
            size_bytes,
            duration_ms,
            timestamp: Utc::now(),
        })
    }
}
