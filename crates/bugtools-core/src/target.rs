use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Target {
    pub id: Uuid,
    pub project_id: Uuid,
    pub url: String,
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Endpoint {
    pub id: Uuid,
    pub project_id: Uuid,
    pub target_id: Option<Uuid>,
    pub host: String,
    pub path: String,
    pub method: String,
    pub status_code: Option<u16>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParameterLocation {
    Query,
    Body,
    Header,
    Path,
    Cookie,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Parameter {
    pub id: Uuid,
    pub endpoint_id: Uuid,
    pub name: String,
    pub location: ParameterLocation,
    pub example_value: Option<String>,
}
