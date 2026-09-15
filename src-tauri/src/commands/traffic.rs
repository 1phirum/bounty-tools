use crate::state::AppState;
use bugtools_http::{Repeater, RepeaterEdit, SafeHttpClient, TrafficStore};
use std::sync::Arc;
use tauri::State;

/// Shared engine registry on AppState so commands reuse one client,
/// one rate limiter, and one traffic store per app session.
pub struct EngineRegistry {
    pub http: SafeHttpClient,
    pub repeater: Repeater,
    pub store: Arc<TrafficStore>,
}

impl EngineRegistry {
    pub fn new(scope: Arc<bugtools_scope::ScopeEngine>) -> Self {
        let http = SafeHttpClient::new(scope.clone(), Default::default());
        let limiter = http.rate_limiter();
        let store = Arc::new(TrafficStore::new(50_000));
        let repeater = Repeater::new(scope, limiter, store.clone());
        Self { http, repeater, store }
    }
}

#[tauri::command]
pub async fn get_traffic_page(
    offset: usize,
    limit: usize,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let entries = state.engines.store.page(offset, limit);
    let (total, evicted) = state.engines.store.stats();
    Ok(serde_json::json!({
        "entries": entries,
        "total": total,
        "evicted": evicted,
    }))
}

#[tauri::command]
pub async fn get_traffic_entry(
    entry_id: String,
    state: State<'_, AppState>,
) -> Result<Option<bugtools_http::TrafficEntry>, String> {
    let id = uuid::Uuid::parse_str(&entry_id).map_err(|e| e.to_string())?;
    Ok(state.engines.store.get(id))
}

#[tauri::command]
pub async fn clear_traffic(state: State<'_, AppState>) -> Result<bool, String> {
    state.engines.store.clear();
    Ok(true)
}

#[tauri::command]
pub async fn send_request(
    url: String,
    method: String,
    headers: Option<std::collections::HashMap<String, String>>,
    body: Option<String>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    use bugtools_core::http::HttpRequest;
    use chrono::Utc;
    use uuid::Uuid;

    let req = HttpRequest {
        id: Uuid::new_v4(),
        job_id: None,
        url,
        method,
        headers: headers.unwrap_or_default(),
        body,
        timestamp: Utc::now(),
    };

    let response = state.engines.http.execute(req.clone()).await.map_err(|e| e.to_string())?;

    // Record the exchange and emit the capture event.
    let fingerprint = TrafficStore::fingerprint_request(&req);    let entry_id = Uuid::new_v4();
    let stored = state.engines.store.append(bugtools_http::TrafficEntry {
        id: entry_id,
        request: req.clone(),
        response: Some(response.clone()),
        captured_at: Utc::now(),
        fingerprint: fingerprint.clone(),
        source: bugtools_http::TrafficSource::Proxy,
    });

    if stored {
        state.event_bus.publish(bugtools_core::events::BugToolsEvent::TrafficCaptured {
            entry_id,
            request_id: response.request_id,
            source: "proxy".to_string(),
            method: req.method,
            url: req.url,
            status_code: Some(response.status_code),
            duration_ms: Some(response.duration_ms),
            size_bytes: Some(response.size_bytes),
            fingerprint,
            captured_at: Utc::now(),
        });
    } else {
        state
            .event_bus
            .publish(bugtools_core::events::BugToolsEvent::TrafficDeduped { fingerprint });
    }

    Ok(serde_json::json!({
        "status_code": response.status_code,
        "headers": response.headers,
        "body": response.body,
        "size_bytes": response.size_bytes,
        "duration_ms": response.duration_ms,
    }))
}

#[tauri::command]
pub async fn repeater_send(
    base_entry_id: String,
    method: Option<String>,
    url: Option<String>,
    header_overrides: Option<std::collections::HashMap<String, String>>,
    body: Option<String>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let id = uuid::Uuid::parse_str(&base_entry_id).map_err(|e| e.to_string())?;
    let base = state
        .engines
        .store
        .get(id)
        .ok_or_else(|| "Base traffic entry not found".to_string())?
        .request;

    let edit = RepeaterEdit {
        method,
        url,
        header_overrides: header_overrides.unwrap_or_default(),
        body,
    };

    let (sent, response) = state
        .engines
        .repeater
        .send(&base, &edit)
        .await
        .map_err(|e| e.to_string())?;

    state
        .event_bus
        .publish(bugtools_core::events::BugToolsEvent::RepeaterSent {
            request_id: response.request_id,
            status_code: response.status_code,
            duration_ms: response.duration_ms,
        });

    Ok(serde_json::json!({
        "sent": {
            "method": sent.method,
            "url": sent.url,
            "headers": sent.headers,
            "body": sent.body,
        },
        "response": {
            "status_code": response.status_code,
            "headers": response.headers,
            "body": response.body,
            "size_bytes": response.size_bytes,
            "duration_ms": response.duration_ms,
        },
    }))
}
