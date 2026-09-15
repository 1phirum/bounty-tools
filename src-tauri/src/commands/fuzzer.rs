use crate::state::AppState;
use bugtools_http::{FuzzPosition, FuzzRunOptions, Fuzzer};

use tauri::State;
use uuid::Uuid;

#[tauri::command]
pub async fn fuzzer_run(
    url_template: String,
    method: String,
    headers: Option<std::collections::HashMap<String, String>>,
    body: Option<String>,
    positions: Vec<FuzzPositionPayload>,
    max_combos: Option<usize>,
    concurrency: Option<usize>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    use bugtools_core::http::HttpRequest;
    use chrono::Utc;

    if positions.is_empty() {
        return Err("No fuzz positions defined".to_string());
    }

    let base = HttpRequest {
        id: Uuid::new_v4(),
        job_id: None,
        url: url_template,
        method,
        headers: headers.unwrap_or_default(),
        body,
        timestamp: Utc::now(),
    };

    let positions: Vec<FuzzPosition> = positions
        .into_iter()
        .map(|p| FuzzPosition { marker: p.marker, payloads: p.payloads })
        .collect();

    let fuzzer = Fuzzer::new(
        state.scope.clone(),
        state.engines.http.rate_limiter(),
        state.engines.store.clone(),
    );

    let options = FuzzRunOptions {
        concurrency: concurrency.unwrap_or(4),
        ..Default::default()
    };

    let summary = fuzzer
        .run(&base, &positions, max_combos.unwrap_or(10_000), options)
        .await
        .map_err(|e| e.to_string())?;

    state
        .event_bus
        .publish(bugtools_core::events::BugToolsEvent::FuzzerRunCompleted {
            total: summary.total,
            completed: summary.completed,
            failed: summary.failed,
            deduped: summary.deduped,
        });

    Ok(serde_json::to_value(&summary).map_err(|e| e.to_string())?)
}

#[derive(serde::Deserialize)]
pub struct FuzzPositionPayload {
    pub marker: String,
    pub payloads: Vec<String>,
}
