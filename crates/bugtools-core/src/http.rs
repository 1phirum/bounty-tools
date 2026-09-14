use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpRequest {
    pub id: Uuid,
    pub job_id: Option<Uuid>,
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HttpResponse {
    pub id: Uuid,
    pub request_id: Uuid,
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub size_bytes: usize,
    pub duration_ms: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResponseFingerprint {
    pub id: Uuid,
    pub response_id: Uuid,
    pub status: u16,
    pub content_type: Option<String>,
    pub content_length: usize,
    pub body_hash: String,
    pub normalized_body_hash: String,
    pub redirect_location: Option<String>,
    pub response_time_ms: u64,
    pub structural_signature: String,
}
