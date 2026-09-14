use bugtools_events::EventBus;
use bugtools_scheduler::JobScheduler;
use bugtools_scope::ScopeEngine;
use bugtools_storage::Database;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub scope: Arc<ScopeEngine>,
    pub scheduler: JobScheduler,
    pub event_bus: EventBus,
    pub active_project_id: Arc<RwLock<Option<Uuid>>>,
}

impl AppState {
    pub fn new(db: Database) -> Self {
        let event_bus = EventBus::default();
        let scheduler = JobScheduler::new(event_bus.clone());
        let scope = Arc::new(ScopeEngine::new());
        Self {
            db,
            scope,
            scheduler,
            event_bus,
            active_project_id: Arc::new(RwLock::new(None)),
        }
    }
}
