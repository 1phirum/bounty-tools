use bugtools_core::http::{HttpRequest, HttpResponse};
use bugtools_scope::ScopeEngine;
use chrono::Utc;
use reqwest::{Client, Method};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Semaphore;
use uuid::Uuid;

// Cap retained response header bytes plus body bytes (2 MiB).
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

pub mod fuzzer;
pub mod profile;
pub mod rate_limiter;
pub mod repeater;
pub mod traffic;

pub use fuzzer::{FuzzIterationResult, FuzzPosition, FuzzRunOptions, FuzzRunSummary, Fuzzer};
pub use rate_limiter::TokenBucket;
pub use repeater::{Repeater, RepeaterEdit, RepeaterError};
pub use traffic::{TrafficEntry, TrafficSource, TrafficStore};

#[derive(Error, Debug)]
pub enum HttpEngineError {
    #[error("Out of scope: {0}")]
    OutOfScope(String),
    #[error("Request budget exceeded (limit: {0})")]
    BudgetExceeded(u64),
    #[error("Rate limited: next token in {wait_ms}ms")]
    RateLimited { wait_ms: u64 },
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Invalid HTTP method: {0}")]
    InvalidMethod(String),
    #[error("Response exceeds the 2097152-byte limit")]
    ResponseTooLarge,
    #[error("Invalid response header: {0}")]
    InvalidResponseHeader(String),
    #[error("HTTP concurrency limiter is closed")]
    ConcurrencyClosed,
}

pub struct HttpClientConfig {
    pub max_concurrency: usize,
    pub rate_limit_rps: f64,
    /// Burst capacity for the token bucket (immediate requests allowed).
    pub rate_limit_burst: f64,
    pub timeout: Duration,
    pub max_budget: u64,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 5,
            rate_limit_rps: 5.0,
            rate_limit_burst: 10.0,
            timeout: Duration::from_secs(15),
            max_budget: 1000,
        }
    }
}

pub struct SafeHttpClient {
    client: Client,
    scope: Arc<ScopeEngine>,
    semaphore: Arc<Semaphore>,
    /// Enforced token-bucket rate limiter. Previously `rate_limit_rps`
    /// was declared in config but never enforced — this closes that gap.
    rate_limiter: Arc<TokenBucket>,
    budget_counter: AtomicU64,
    max_budget: u64,
}

impl SafeHttpClient {
    /// Panics on invalid configuration or client initialization failure rather
    /// than silently replacing the configured safety limits with defaults.
    pub fn new(scope: Arc<ScopeEngine>, config: HttpClientConfig) -> Self {
        assert!(
            config.max_concurrency > 0 && config.max_concurrency <= Semaphore::MAX_PERMITS,
            "HTTP concurrency must be between 1 and Semaphore::MAX_PERMITS"
        );
        assert!(!config.timeout.is_zero(), "HTTP timeout must be positive");
        assert!(
            config.rate_limit_burst.is_finite() && config.rate_limit_burst >= 1.0,
            "HTTP rate-limit burst must be finite and at least one"
        );
        assert!(
            config.rate_limit_rps.is_finite()
                && config.rate_limit_rps > 0.0
                && Duration::try_from_secs_f64(1.0 / config.rate_limit_rps).is_ok(),
            "HTTP rate must be finite, positive, and have a representable wait"
        );
        // Honor the platform/user CA configuration. Without this, BugTools
        // cannot talk through a TLS-intercepting proxy (corporate MITM, or a
        // sandbox egress proxy) because rustls trusts only its bundled roots.
        // We read the standard environment variables curl and Python use.
        let mut builder = Client::builder();
        if let Some(ca_path) = ca_bundle_path() {
            if let Ok(pem) = std::fs::read(&ca_path) {
                for cert in reqwest::Certificate::from_pem_bundle(&pem).unwrap_or_default() {
                    builder = builder.add_root_certificate(cert);
                }
            }
        }
        let client = builder
            .timeout(config.timeout)
            // Redirect destinations have not been scope-checked. Return 3xx
            // to the caller; any follow-up must be an independently checked request.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to initialize safe HTTP transport");

        Self {
            client,
            scope,
            semaphore: Arc::new(Semaphore::new(config.max_concurrency)),
            rate_limiter: Arc::new(TokenBucket::new(
                config.rate_limit_burst,
                config.rate_limit_rps,
            )),
            budget_counter: AtomicU64::new(0),
            max_budget: config.max_budget,
        }
    }

    pub fn requests_sent(&self) -> u64 {
        self.budget_counter.load(Ordering::Relaxed)
    }

    /// Current rate-limiter token count, for status reporting / UI.
    pub fn available_rate_tokens(&self) -> f64 {
        self.rate_limiter.available_tokens()
    }

    /// Shared handle to the rate limiter (for repeater/fuzzer engines
    /// that must obey the same budget as the proxy path).
    pub fn rate_limiter(&self) -> Arc<TokenBucket> {
        self.rate_limiter.clone()
    }

    pub async fn execute(&self, req: HttpRequest) -> Result<HttpResponse, HttpEngineError> {
        // 1. Scope check — safety checks are free; they never consume
        //    budget or rate tokens.
        let scope_eval = self.scope.evaluate(&req.url);
        if !scope_eval.allowed {
            return Err(HttpEngineError::OutOfScope(scope_eval.reason));
        }

        // Parse without a fallback to GET (HTTP method tokens are case-sensitive).
        let method = Method::from_bytes(req.method.as_bytes())
            .map_err(|error| HttpEngineError::InvalidMethod(error.to_string()))?;
        let mut builder = self.client.request(method, &req.url);
        for (key, value) in &req.headers {
            builder = builder.header(key, value);
        }
        if let Some(body) = &req.body {
            builder = builder.body(body.clone());
        }
        // Validate URL/headers before consuming a request reservation.
        let request = builder.build()?;

        // 2. Atomically reserve budget without incrementing past the limit or
        // wrapping. Zero budget intentionally denies all requests. Reservations
        // remain consumed after cancellation/network failure (conservative).
        self.budget_counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                if count < self.max_budget {
                    Some(count + 1)
                } else {
                    None
                }
            })
            .map_err(|_| HttpEngineError::BudgetExceeded(self.max_budget))?;

        // 3. Rate limit: wait for a token before acquiring the concurrency
        //    permit, so queued requests do not hold semaphore slots while
        //    throttled (avoids starving other engines).
        let wait = self.rate_limiter.wait_duration();
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        while !self.rate_limiter.try_acquire() {
            tokio::time::sleep(self.rate_limiter.wait_duration()).await;
        }

        // 4. Concurrency permit
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| HttpEngineError::ConcurrencyClosed)?;

        // Rules can change while this request waits for rate/concurrency.
        let scope_eval = self.scope.evaluate(&req.url);
        if !scope_eval.allowed {
            return Err(HttpEngineError::OutOfScope(scope_eval.reason));
        }
        let start_time = Instant::now();
        let mut resp = self.client.execute(request).await?;
        let status_code = resp.status().as_u16();

        let mut headers = HashMap::new();
        let mut header_bytes = 0usize;
        for (key, value) in resp.headers() {
            // Include duplicate header fields in accounting, even though the
            // existing public response map can only retain one value per name.
            header_bytes = header_bytes
                .checked_add(key.as_str().len())
                .and_then(|size| size.checked_add(value.as_bytes().len()))
                .and_then(|size| size.checked_add(4)) // ": " and CRLF
                .filter(|size| *size <= MAX_RESPONSE_BYTES)
                .ok_or(HttpEngineError::ResponseTooLarge)?;
            let value = value
                .to_str()
                .map_err(|error| HttpEngineError::InvalidResponseHeader(error.to_string()))?;
            headers.insert(key.as_str().to_string(), value.to_string());
        }
        let body_limit = MAX_RESPONSE_BYTES - header_bytes;
        if resp
            .content_length()
            .is_some_and(|size| size > body_limit as u64)
        {
            return Err(HttpEngineError::ResponseTooLarge);
        }
        let mut body = Vec::new();
        // Stream and check every chunk: Content-Length is optional/untrusted.
        // reqwest's configured timeout also covers reading this entire body.
        while let Some(chunk) = resp.chunk().await? {
            if chunk.len() > body_limit - body.len() {
                return Err(HttpEngineError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        let size_bytes = body.len();
        let body_text = String::from_utf8_lossy(&body).into_owned();
        // Replacement characters can expand invalid UTF-8. Bound the retained
        // text too, not just the received byte stream.
        if body_text.len() > body_limit {
            return Err(HttpEngineError::ResponseTooLarge);
        }
        let duration_ms = start_time.elapsed().as_millis() as u64;

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

#[cfg(test)]
mod tests {
    use super::*;
    use bugtools_core::scope::{ScopeRule, ScopeRuleType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn client(config: HttpClientConfig) -> SafeHttpClient {
        let scope = ScopeEngine::with_rules(vec![ScopeRule::new(
            Uuid::new_v4(),
            ScopeRuleType::IncludeDomain,
            "127.0.0.1",
        )]);
        SafeHttpClient::new(Arc::new(scope), config)
    }

    fn request(url: String, method: &str) -> HttpRequest {
        HttpRequest {
            id: Uuid::new_v4(),
            job_id: None,
            url,
            method: method.to_string(),
            headers: HashMap::new(),
            body: None,
            timestamp: Utc::now(),
        }
    }

    async fn serve_once(response: Vec<u8>) -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let mut buffer = [0u8; 1024];
            while !received.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = socket.read(&mut buffer).await.unwrap();
                assert_ne!(count, 0);
                received.extend_from_slice(&buffer[..count]);
            }
            // The client deliberately closes early on oversized responses.
            let _ = socket.write_all(&response).await;
            let _ = socket.shutdown().await;
            String::from_utf8(received).unwrap()
        });
        (format!("http://{address}/"), server)
    }

    #[tokio::test]
    async fn preserves_method_and_does_not_follow_redirects() {
        let (url, server) = serve_once(
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.2:1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
        ).await;
        let client = client(HttpClientConfig::default());
        let response = client.execute(request(url, "PATCH")).await.unwrap();
        assert_eq!(response.status_code, 302);
        assert!(server.await.unwrap().starts_with("PATCH / HTTP/1.1\r\n"));
        assert_eq!(client.requests_sent(), 1);
    }

    #[tokio::test]
    async fn invalid_method_and_exhausted_budget_never_send() {
        let client = client(HttpClientConfig {
            max_budget: 0,
            ..HttpClientConfig::default()
        });
        let url = "http://127.0.0.1:1/".to_string();
        assert!(matches!(
            client.execute(request(url.clone(), "BAD METHOD")).await,
            Err(HttpEngineError::InvalidMethod(_))
        ));
        for _ in 0..3 {
            assert!(matches!(
                client.execute(request(url.clone(), "GET")).await,
                Err(HttpEngineError::BudgetExceeded(0))
            ));
        }
        assert_eq!(client.requests_sent(), 0);
    }

    #[tokio::test]
    async fn truncated_response_body_is_an_error() {
        let (url, server) = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nshort".to_vec(),
        )
        .await;
        assert!(matches!(
            client(HttpClientConfig::default())
                .execute(request(url, "GET"))
                .await,
            Err(HttpEngineError::Network(_))
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_advertised_or_chunked_body_is_rejected() {
        let advertised = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            MAX_RESPONSE_BYTES + 1
        )
        .into_bytes();
        let mut chunked = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
            MAX_RESPONSE_BYTES + 1
        )
        .into_bytes();
        chunked.extend(std::iter::repeat(b'a').take(MAX_RESPONSE_BYTES + 1));
        chunked.extend_from_slice(b"\r\n0\r\n\r\n");
        let headers_plus_body = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            MAX_RESPONSE_BYTES
        )
        .into_bytes();
        for response in [advertised, chunked, headers_plus_body] {
            let (url, server) = serve_once(response).await;
            assert!(matches!(
                client(HttpClientConfig::default())
                    .execute(request(url, "GET"))
                    .await,
                Err(HttpEngineError::ResponseTooLarge)
            ));
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn body_read_preserves_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 1024];
            socket.read(&mut buffer).await.unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let client = client(HttpClientConfig {
            timeout: Duration::from_millis(100),
            ..HttpClientConfig::default()
        });
        let result = client.execute(request(url, "GET")).await;
        server.abort();
        assert!(matches!(result, Err(HttpEngineError::Network(error)) if error.is_timeout()));
    }

    #[test]
    #[should_panic(expected = "HTTP concurrency")]
    fn zero_concurrency_is_rejected() {
        client(HttpClientConfig {
            max_concurrency: 0,
            ..HttpClientConfig::default()
        });
    }

    #[test]
    #[should_panic(expected = "HTTP rate-limit burst")]
    fn fractional_burst_is_rejected() {
        client(HttpClientConfig {
            rate_limit_burst: 0.5,
            ..HttpClientConfig::default()
        });
    }
}

/// Resolve the CA bundle to trust, following the conventions curl and Python
/// use. Explicit env vars win; otherwise fall back to well-known system paths.
///
/// Returns `None` when nothing is found, in which case the client keeps its
/// bundled root set (the previous behaviour).
fn ca_bundle_path() -> Option<std::path::PathBuf> {
    // 1. Explicit overrides, in the order curl/OpenSSL honour them.
    for var in ["SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "AWS_CA_BUNDLE"] {
        if let Ok(value) = std::env::var(var) {
            let path = std::path::PathBuf::from(value);
            if path.is_file() {
                return Some(path);
            }
        }
    }
    // 2. Well-known system locations (Debian/Ubuntu, RHEL/Fedora).
    for candidate in [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
    ] {
        let path = std::path::PathBuf::from(candidate);
        if path.is_file() {
            return Some(path);
        }
    }
    // 3. SSL_CERT_DIR (a hashed directory rather than a bundle) is not read
    //    here; reqwest's rustls backend does not accept a directory.
    None
}
