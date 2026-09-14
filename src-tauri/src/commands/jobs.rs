use crate::state::AppState;
use bugtools_core::job::{Job, ModuleType};
use std::time::Duration;
use tauri::State;
use uuid::Uuid;

#[tauri::command]
pub async fn list_jobs(project_id: String, state: State<'_, AppState>) -> Result<Vec<Job>, String> {
    let proj_uuid = Uuid::parse_str(&project_id).map_err(|e| e.to_string())?;
    state.db.get_jobs(proj_uuid).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn start_test_job(
    project_id: String,
    target: String,
    module: String,
    state: State<'_, AppState>,
) -> Result<Job, String> {
    let proj_uuid = Uuid::parse_str(&project_id).map_err(|e| e.to_string())?;

    // Evaluate target scope before starting job
    let eval = state.scope.evaluate(&target);
    if !eval.allowed {
        return Err(format!("Target denied by Scope Engine: {}", eval.reason));
    }

    let mod_type = match module.to_lowercase().as_str() {
        "dns" => ModuleType::Dns,
        "recon" => ModuleType::Recon,
        "http_probe" => ModuleType::HttpProbe,
        "crawler" => ModuleType::Crawler,
        "sql_injection" => ModuleType::SqlInjection,
        _ => ModuleType::Custom,
    };

    let job = Job::new(proj_uuid, mod_type, target.clone(), 500);
    state.db.insert_job(&job).map_err(|e| e.to_string())?;
    let job_id = state.scheduler.submit_job(job.clone()).await;

    if matches!(mod_type, ModuleType::Dns | ModuleType::Recon) {
        // Execute real Go worker
        crate::process::worker::execute_recon_worker(
            job_id,
            proj_uuid,
            target,
            module,
            (*state).clone(),
        );
    } else {
        // Phase 4 simulated progression for other modules
        let scheduler = state.scheduler.clone();
        tokio::spawn(async move {
            let steps = [
                (20.0, "Analyzing endpoints & parameter surface..."),
                (50.0, "Establishing response baseline & structural hashes..."),
                (80.0, "Executing non-destructive differential test hypothesis..."),
                (100.0, "Job completed successfully."),
            ];

            for (pct, step) in steps {
                tokio::time::sleep(Duration::from_millis(800)).await;
                scheduler.update_progress(job_id, pct, step.to_string()).await;
            }
        });
    }

    Ok(job)
}

#[tauri::command]
pub async fn cancel_job(job_id: String, state: State<'_, AppState>) -> Result<bool, String> {
    let id = Uuid::parse_str(&job_id).map_err(|e| e.to_string())?;
    Ok(state.scheduler.cancel_job(id).await)
}
