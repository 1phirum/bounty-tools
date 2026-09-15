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

impl HttpRequest {
    pub fn parse_raw(raw: &str) -> Option<Self> {
        let mut lines = raw.lines();
        let request_line = lines.next()?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?.to_string();
        let path = parts.next()?.to_string();
        
        let mut headers = HashMap::new();
        let mut host = String::new();
        
        for line in lines.by_ref() {
            if line.trim().is_empty() {
                break;
            }
            if let Some(idx) = line.find(':') {
                let key = line[..idx].trim().to_string();
                let value = line[idx + 1..].trim().to_string();
                if key.to_lowercase() == "host" {
                    host = value.clone();
                }
                headers.insert(key, value);
            }
        }
        
        let body_parts: Vec<&str> = lines.collect();
        let body = if body_parts.is_empty() {
            None
        } else {
            Some(body_parts.join("\n"))
        };
        
        let url = if path.starts_with("http://") || path.starts_with("https://") {
            path
        } else {
            let scheme = if path.starts_with(":443") || headers.get("X-Forwarded-Proto").map(String::as_str) == Some("https") {
                "https"
            } else {
                "http"
            };
            format!("{}://{}{}", scheme, host, path)
        };
        
        Some(Self {
            id: Uuid::new_v4(),
            job_id: None,
            url,
            method,
            headers,
            body,
            timestamp: Utc::now(),
        })
    }
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
