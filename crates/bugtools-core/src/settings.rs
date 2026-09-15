use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub max_requests_per_second: f32,
    pub max_worker_concurrency: usize,
    pub max_requests_per_job: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_requests_per_second: 5.0,
            max_worker_concurrency: 4,
            max_requests_per_job: 1000,
        }
    }
}
