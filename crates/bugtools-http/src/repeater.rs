use crate::rate_limiter::TokenBucket;
use crate::traffic::{TrafficSource, TrafficStore};
use bugtools_core::http::{HttpRequest, HttpResponse};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum RepeaterError {
    #[error("Out of scope: {0}")]
    OutOfScope(String),
    #[error("Invalid target URL: {0}")]
    InvalidTarget(String),
    #[error(transparent)]
    Network(#[from] reqwest::Error),
}

/// Analyst-supplied edits applied to a captured request before replay.
/// The original capture is never mutated — edits produce a new request.
#[derive(Debug, Clone, Default)]
pub struct RepeaterEdit {
    pub method: Option<String>,
    pub url: Option<String>,
    pub header_overrides: HashMap<String, String>,
    pub body: Option<String>,
}

/// Deterministic single-request replay with scope enforcement and rate
/// limiting. `send` applies the edit, re-checks the (possibly edited)
/// URL against scope, waits for a rate-limit token, then sends exactly
/// once and records the exchange into the traffic store.
pub struct Repeater {
    scope: Arc<bugtools_scope::ScopeEngine>,
    limiter: Arc<TokenBucket>,
    store: Arc<TrafficStore>,
    http: reqwest::Client,
}

impl Repeater {
    pub fn new(
        scope: Arc<bugtools_scope::ScopeEngine>,
        limiter: Arc<TokenBucket>,
        store: Arc<TrafficStore>,
    ) -> Self {
        Self {
            scope,
            limiter,
            store,
            http: reqwest::Client::new(),
        }
    }

    /// Pure: apply an edit spec to a captured request, producing a new
    /// request with a fresh ID (the original stays immutable in the audit
    /// trail). URL shape is validated eagerly with a typed error.
    pub fn apply_edit(base: &HttpRequest, edit: &RepeaterEdit) -> Result<HttpRequest, RepeaterError> {
        let url = edit.url.clone().unwrap_or_else(|| base.url.clone());
        let parsed = url::Url::parse(&url).map_err(|e| RepeaterError::InvalidTarget(e.to_string()))?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(RepeaterError::InvalidTarget(format!("unsupported scheme: {}", parsed.scheme())));
        }

        let mut headers = base.headers.clone();
        for (k, v) in &edit.header_overrides {
            headers.insert(k.clone(), v.clone());
        }

        Ok(HttpRequest {
            id: Uuid::new_v4(),
            job_id: base.job_id,
            url,
            method: edit.method.clone().unwrap_or_else(|| base.method.clone()),
            headers,
            body: edit.body.clone().or_else(|| base.body.clone()),
            timestamp: Utc::now(),
        })
    }

    /// Send the edited request exactly once. Scope is checked on the
    /// *edited* URL — an edit can point anywhere, so the original
    /// capture's clearance does not carry over.
    pub async fn send(
        &self,
        base: &HttpRequest,
        edit: &RepeaterEdit,
    ) -> Result<(HttpRequest, HttpResponse), RepeaterError> {
        let sent = Self::apply_edit(base, edit)?;

        let scope_eval = self.scope.evaluate(&sent.url);
        if !scope_eval.allowed {
            return Err(RepeaterError::OutOfScope(scope_eval.reason));
        }

        // Wait for a rate-limit token (bounded by bucket wait time).
        let wait = self.limiter.wait_duration();
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        // Consume the token; if the wait raced another consumer, wait again
        // for the next token — never exceed the configured rate.
        while !self.limiter.try_acquire() {
            tokio::time::sleep(self.limiter.wait_duration()).await;
        }

        let start = std::time::Instant::now();
        let builder = match sent.method.to_uppercase().as_str() {
            "POST" => self.http.post(&sent.url),
            "PUT" => self.http.put(&sent.url),
            "DELETE" => self.http.delete(&sent.url),
            "PATCH" => self.http.patch(&sent.url),
            "HEAD" => self.http.head(&sent.url),
            _ => self.http.get(&sent.url),
        };
        let builder = sent.headers.iter().fold(builder, |b, (k, v)| b.header(k, v));
        let builder = match &sent.body {
            Some(body) => builder.body(body.clone()),
            None => builder,
        };

        let resp = builder.send().await?;
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

        let response = HttpResponse {
            id: Uuid::new_v4(),
            request_id: sent.id,
            status_code,
            headers,
            body,
            size_bytes,
            duration_ms,
            timestamp: Utc::now(),
        };

        // Record into the traffic store (dedup applies — repeated identical
        // replays collapse, which is exactly what an analyst expects).
        let fingerprint = TrafficStore::fingerprint_request(&sent);
        let _ = self.store.append(crate::traffic::TrafficEntry {
            id: Uuid::new_v4(),
            request: sent.clone(),
            response: Some(response.clone()),
            captured_at: Utc::now(),
            fingerprint,
            source: TrafficSource::Repeater,
        });

        Ok((sent, response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn base_req() -> HttpRequest {
        HttpRequest {
            id: Uuid::new_v4(),
            job_id: None,
            url: "https://api.example.com/v1/users?id=42".to_string(),
            method: "GET".to_string(),
            headers: HashMap::from([("accept".to_string(), "application/json".to_string())]),
            body: None,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn apply_edit_preserves_base_and_overrides() {
        let base = base_req();
        let edit = RepeaterEdit {
            method: Some("POST".to_string()),
            header_overrides: HashMap::from([("x-probe".to_string(), "1".to_string())]),
            body: Some("{\"a\":1}".to_string()),
            url: None,
        };
        let edited = Repeater::apply_edit(&base, &edit).unwrap();
        assert_eq!(edited.method, "POST");
        assert_eq!(edited.headers.get("x-probe").map(String::as_str), Some("1"));
        assert_eq!(edited.headers.get("accept").map(String::as_str), Some("application/json"));
        assert_eq!(edited.body.as_deref(), Some("{\"a\":1}"));
        // Base untouched.
        assert_eq!(base.method, "GET");
        assert_ne!(base.id, edited.id);
    }

    #[test]
    fn apply_edit_rejects_bad_scheme() {
        let base = base_req();
        let edit = RepeaterEdit {
            url: Some("ftp://evil.example.net/x".to_string()),
            ..Default::default()
        };
        assert!(matches!(
            Repeater::apply_edit(&base, &edit),
            Err(RepeaterError::InvalidTarget(_))
        ));
    }
}
