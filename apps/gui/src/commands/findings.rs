use crate::state::AppState;
use bugtools_core::finding::{Confidence, Finding, FindingStatus, Severity};
use chrono::Utc;
use uuid::Uuid;

pub async fn list_findings(project_id: String, state: &AppState) -> Result<Vec<Finding>, String> {
    let proj_uuid = Uuid::parse_str(&project_id).map_err(|e| e.to_string())?;
    state.db.get_findings(proj_uuid).map_err(|e| e.to_string())
}

pub async fn create_finding(
    project_id: String,
    title: String,
    severity: String,
    confidence: String,
    target: String,
    endpoint: String,
    parameter: Option<String>,
    module: String,
    technique: String,
    dbms_hypothesis: Option<String>,
    notes: Option<String>,
    state: &AppState,
) -> Result<Finding, String> {
    let proj_uuid = Uuid::parse_str(&project_id).map_err(|e| e.to_string())?;

    let sev = match severity.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    };

    let conf = match confidence.to_uppercase().as_str() {
        "VERY_HIGH" | "VERYHIGH" => Confidence::VeryHigh,
        "HIGH" => Confidence::High,
        "MEDIUM" => Confidence::Medium,
        "LOW" => Confidence::Low,
        _ => Confidence::Info,
    };

    let finding = Finding {
        id: Uuid::new_v4(),
        project_id: proj_uuid,
        title,
        severity: sev,
        confidence: conf,
        status: FindingStatus::Candidate,
        target,
        endpoint,
        parameter,
        module,
        technique,
        dbms_hypothesis,
        notes,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    state.db.insert_finding(&finding).map_err(|e| e.to_string())?;
    Ok(finding)
}
