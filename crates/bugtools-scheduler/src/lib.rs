use bugtools_core::{
    events::BugToolsEvent,
    job::{Job, JobStatus},
};
use bugtools_events::EventBus;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone)]
pub struct JobScheduler {
    jobs: Arc<RwLock<HashMap<Uuid, Job>>>,
    event_bus: EventBus,
}

impl JobScheduler {
    pub fn new(event_bus: EventBus) -> Self {
        Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
            event_bus,
        }
    }

    pub async fn submit_job(&self, job: Job) -> Uuid {
        let id = job.id;
        {
            let mut lock = self.jobs.write().await;
            lock.insert(id, job.clone());
        }
        self.event_bus.publish(BugToolsEvent::JobCreated(job));
        id
    }

    pub async fn cancel_job(&self, job_id: Uuid) -> bool {
        let mut lock = self.jobs.write().await;
        if let Some(job) = lock.get_mut(&job_id) {
            job.status = JobStatus::Cancelled;
            self.event_bus.publish(BugToolsEvent::JobCancelled { job_id });
            true
        } else {
            false
        }
    }

    pub async fn update_progress(&self, job_id: Uuid, progress: f32, current_step: String) {
        let mut lock = self.jobs.write().await;
        if let Some(job) = lock.get_mut(&job_id) {
            job.progress = progress;
            job.current_step = current_step.clone();
            if progress >= 100.0 {
                job.status = JobStatus::Completed;
                self.event_bus.publish(BugToolsEvent::JobCompleted { job_id });
            } else {
                job.status = JobStatus::Running;
                self.event_bus.publish(BugToolsEvent::JobProgress {
                    job_id,
                    progress,
                    current_step,
                });
            }
        }
    }

    pub async fn get_job(&self, job_id: Uuid) -> Option<Job> {
        let lock = self.jobs.read().await;
        lock.get(&job_id).cloned()
    }

    pub async fn list_jobs(&self) -> Vec<Job> {
        let lock = self.jobs.read().await;
        lock.values().cloned().collect()
    }
}
