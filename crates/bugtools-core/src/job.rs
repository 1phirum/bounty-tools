use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobStatus {
    Queued,
    Running,
    Paused,
    Cancelled,
    Failed,
    Completed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModuleType {
    Dns,
    Recon,
    HttpProbe,
    Crawler,
    SqlInjection,
    Technology,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Job {
    pub id: Uuid,
    pub project_id: Uuid,
    pub module: ModuleType,
    pub target: String,
    pub status: JobStatus,
    pub progress: f32,
    pub current_step: String,
    pub requests_sent: u64,
    pub max_requests: u64,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
}

impl Job {
    pub fn new(project_id: Uuid, module: ModuleType, target: impl Into<String>, max_requests: u64) -> Self {
        Self {
            id: Uuid::new_v4(),
            project_id,
            module,
            target: target.into(),
            status: JobStatus::Queued,
            progress: 0.0,
            current_step: "Queued".to_string(),
            requests_sent: 0,
            max_requests,
            created_at: Utc::now(),
            started_at: None,
            finished_at: None,
            error_message: None,
        }
    }
}
