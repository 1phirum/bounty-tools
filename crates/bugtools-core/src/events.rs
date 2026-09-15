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

    // ── Traffic / engine events (new) ─────────────────────────────
    /// A request/response exchange was captured (proxy, repeater, or fuzzer).
    /// The frontend traffic table appends rows from this event.
    TrafficCaptured {
        entry_id: Uuid,
        request_id: Uuid,
        source: String,
        method: String,
        url: String,
        status_code: Option<u16>,
        duration_ms: Option<u64>,
        size_bytes: Option<usize>,
        fingerprint: String,
        captured_at: DateTime<Utc>,
    },
    /// A repeater replay completed.
    RepeaterSent {
        request_id: Uuid,
        status_code: u16,
        duration_ms: u64,
    },
    /// A fuzzer run's aggregate outcome.
    FuzzerRunCompleted {
        total: usize,
        completed: usize,
        failed: usize,
        deduped: usize,
    },
    /// An exchange was suppressed as an exact duplicate of an existing entry.
    TrafficDeduped { fingerprint: String },
    /// An out-of-scope target was blocked before any network I/O.
    ScopeViolationBlocked { url: String, reason: String },

    AuditLog {
        timestamp: DateTime<Utc>,
        level: String,
        component: String,
        message: String,
    },
}
