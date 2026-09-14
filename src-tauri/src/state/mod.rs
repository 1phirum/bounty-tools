use bugtools_events::EventBus;
use bugtools_scheduler::JobScheduler;
use bugtools_scope::ScopeEngine;
use bugtools_storage::Database;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::commands::traffic::EngineRegistry;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub scope: Arc<ScopeEngine>,
    pub scheduler: JobScheduler,
    pub event_bus: EventBus,
    pub active_project_id: Arc<RwLock<Option<Uuid>>>,
    /// HTTP/repeater/fuzzer engine registry — one shared client,
    /// rate limiter, and traffic store per app session.
    pub engines: Arc<EngineRegistry>,
}

impl AppState {
    pub fn new(db: Database) -> Self {
        let event_bus = EventBus::default();
        let scheduler = JobScheduler::new(event_bus.clone());
        let scope = Arc::new(ScopeEngine::new());
        let engines = Arc::new(EngineRegistry::new(scope.clone()));
        Self {
            db,
            scope,
            scheduler,
            event_bus,
            active_project_id: Arc::new(RwLock::new(None)),
            engines,
        }
    }
}
