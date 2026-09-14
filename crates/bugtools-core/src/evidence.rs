use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Evidence {
    pub id: Uuid,
    pub finding_id: Uuid,
    pub baseline_request: String,
    pub baseline_response: String,
    pub test_request: String,
    pub test_response: String,
    pub response_diff: Option<String>,
    pub timing_data: Option<String>,
    pub fingerprints: Option<String>,
    pub analysis_notes: String,
    pub created_at: DateTime<Utc>,
}
