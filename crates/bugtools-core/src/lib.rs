pub mod events;
pub mod evidence;
pub mod finding;
pub mod http;
pub mod job;
pub mod project;
pub mod scope;
pub mod settings;
pub mod target;
pub mod scheduling;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("Scope violation: {0}")]
    ScopeViolation(String),
    #[error("Project not found: {0}")]
    ProjectNotFound(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}
