//! Shared HTTP fetching for the command layer.
//!
//! Every command requests through the shared [`SafeHttpClient`], so scope
//! checks, rate limits, budgets and size bounds apply uniformly. One helper
//! here keeps the commands from each growing their own transport.

use anyhow::{anyhow, Result};
use bugtools_core::http::HttpRequest;
use bugtools_http::{HttpEngineError, SafeHttpClient};
use std::collections::HashMap;
use uuid::Uuid;

/// Bound manual redirect following; the safe client itself never follows.
const MAX_REDIRECTS: usize = 5;

/// One fetched page: everything the analysis pipeline needs from a response.
pub struct Fetched {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// Fetch through the safe client, following redirects only while the next hop
/// stays in scope.
///
/// The safe client never follows redirects itself, so this preserves that
/// behaviour without ever requesting an unchecked host: an out-of-scope
/// redirect target is an error, not a silent hop. Redirects are followed for
/// GET only — replaying a POST body at a new location would send the caller's
/// data somewhere they did not point it, so a redirected POST is returned as
/// the 3xx response it is.
pub async fn fetch(
    http: &SafeHttpClient,
    url: &str,
    method: &str,
    body: Option<&str>,
    headers: &HashMap<String, String>,
) -> Result<Fetched> {
    let follow = method.eq_ignore_ascii_case("GET");
    let mut current = url.to_string();
    for _ in 0..=if follow { MAX_REDIRECTS } else { 0 } {
        let req = HttpRequest {
            id: Uuid::new_v4(),
            job_id: None,
            url: current.clone(),
            method: method.to_string(),
            headers: headers.clone(),
            body: body.map(String::from),
            timestamp: chrono::Utc::now(),
        };
        let resp = match http.execute(req).await {
            Ok(r) => r,
            Err(HttpEngineError::OutOfScope(reason)) => {
                return Err(anyhow!("refusing to follow redirect out of scope: {reason}"))
            }
            // A budget/rate/size failure is reported, never swallowed.
            Err(e) => return Err(anyhow!("{e}")),
        };

        if follow && (300..400).contains(&resp.status_code) {
            if let Some(loc) = resp
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                .map(|(_, v)| v.clone())
            {
                if let Ok(next) = url::Url::parse(&current).and_then(|base| base.join(&loc)) {
                    let next = next.to_string();
                    if next != current {
                        eprintln!("[*] redirect {current} -> {next}");
                        current = next;
                        continue;
                    }
                }
            }
        }

        return Ok(Fetched {
            status: resp.status_code,
            headers: resp.headers.into_iter().collect(),
            body: resp.body,
        });
    }
    Err(anyhow!("exceeded {MAX_REDIRECTS} redirects from {url}"))
}
