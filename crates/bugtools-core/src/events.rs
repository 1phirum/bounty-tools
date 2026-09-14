use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{finding::Finding, job::Job, project::Project, scope::ScopeEvaluation};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum BugToolsEvent {
    ProjectCreated(Project),
    ProjectUpdated(Project),
    
    JobCreated(Job),
    JobStarted { job_id: Uuid },
    JobProgress { job_id: Uuid, progress: f32, current_step: String },
    JobPaused { job_id: Uuid },
    JobCancelled { job_id: Uuid },
    JobFailed { job_id: Uuid, error: String },
    JobCompleted { job_id: Uuid },
    
    ScopeChecked(ScopeEvaluation),
    
    TargetDiscovered { project_id: Uuid, url: String },
    EndpointDiscovered { project_id: Uuid, host: String, path: String, method: String },
    ParameterDiscovered { project_id: Uuid, endpoint: String, parameter: String },
    
    FindingDiscovered(Finding),
    FindingUpdated(Finding),
    
    AuditLog {
        timestamp: DateTime<Utc>,
        level: String,
        component: String,
        message: String,
    },
}
