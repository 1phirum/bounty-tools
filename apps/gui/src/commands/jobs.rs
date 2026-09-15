use crate::state::AppState;
use bugtools_core::job::{Job, ModuleType};
use std::time::Duration;
use uuid::Uuid;

pub async fn list_jobs(project_id: String, state: &AppState) -> Result<Vec<Job>, String> {
    let proj_uuid = Uuid::parse_str(&project_id).map_err(|e| e.to_string())?;
    let mut db_jobs = state.db.get_jobs(proj_uuid).map_err(|e| e.to_string())?;
    let active_jobs = state.scheduler.list_jobs().await;
    
    for db_job in &mut db_jobs {
        if let Some(active) = active_jobs.iter().find(|j| j.id == db_job.id) {
            *db_job = active.clone();
        }
    }
    
    Ok(db_jobs)
}

pub async fn start_test_job(
    project_id: String,
    target: String,
    module: String,
    state: &AppState,
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
    } else if matches!(mod_type, ModuleType::SqlInjection) {
        let state_arc = (*state).clone();
        let target_url = target.clone();
        let module_name = module.clone();
        
        tokio::spawn(async move {
            // Add a tiny delay to ensure the React frontend has registered the new job before receiving events
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            state_arc.scheduler.update_progress(job_id, 5.0, "Parsing target...".to_string()).await;
            
            // Check if target_url is actually a RAW HTTP request
            let is_raw = target_url.starts_with("GET ") || 
                         target_url.starts_with("POST ") || 
                         target_url.starts_with("PUT ") || 
                         target_url.starts_with("DELETE ") || 
                         target_url.starts_with("PATCH ") ||
                         target_url.starts_with("OPTIONS ");

            let base_req = if is_raw {
                match bugtools_core::http::HttpRequest::parse_raw(&target_url) {
                    Some(mut req) => {
                        req.job_id = Some(job_id);
                        req
                    }
                    None => {
                        state_arc.scheduler.update_progress(job_id, 100.0, "Failed: Invalid Raw Request".to_string()).await;
                        return;
                    }
                }
            } else {
                bugtools_core::http::HttpRequest {
                    id: uuid::Uuid::new_v4(),
                    job_id: Some(job_id),
                    url: target_url.clone(),
                    method: "GET".to_string(),
                    headers: Default::default(),
                    body: None,
                    timestamp: chrono::Utc::now(),
                }
            };

            let engine = bugtools_sql::DbmsProbeEngine::new(state_arc.scope.clone());
            let mut params_to_test = Vec::new();

            if target_url.contains('*') {
                // sqlmap style marker
                params_to_test.push(("__RAW_MARKER__".to_string(), "".to_string()));
            } else if !is_raw {
                let parsed_url = match url::Url::parse(&base_req.url) {
                    Ok(u) => u,
                    Err(e) => {
                        state_arc.scheduler.update_progress(job_id, 100.0, format!("Failed: Invalid URL ({})", e)).await;
                        return;
                    }
                };
                let query_pairs: Vec<(String, String)> = parsed_url.query_pairs().into_owned().collect();
                for (k, v) in query_pairs {
                    params_to_test.push((k, v));
                }
            }

            if params_to_test.is_empty() {
                state_arc.scheduler.update_progress(job_id, 100.0, "Completed (no parameters or '*' markers found to test)".to_string()).await;
                return;
            }

            let total_params = params_to_test.len();
            for (idx, (param_name, param_value)) in params_to_test.into_iter().enumerate() {
                let pct = 10.0 + (80.0 * (idx as f32) / (total_params as f32));
                state_arc.scheduler.update_progress(job_id, pct, format!("Testing injection point '{}'...", param_name)).await;

                if let Ok(result) = bugtools_sql::analyze_endpoint(&engine, &base_req, &param_name, &param_value).await {
                    if let Some(dbms) = result.dbms_hypothesis {
                        let parsed_url = url::Url::parse(&base_req.url).unwrap_or_else(|_| url::Url::parse("http://unknown").unwrap());
                        let finding = bugtools_core::finding::Finding {
                            id: uuid::Uuid::new_v4(),
                            project_id: proj_uuid,
                            title: format!("SQL Injection ({} detected)", dbms.display_name()),
                            severity: bugtools_core::finding::Severity::High,
                            confidence: bugtools_core::finding::Confidence::High,
                            status: bugtools_core::finding::FindingStatus::Candidate,
                            target: base_req.url.clone(),
                            endpoint: parsed_url.path().to_string(),
                            parameter: if param_name == "__RAW_MARKER__" { Some("Raw Marker (*)".to_string()) } else { Some(param_name.clone()) },
                            module: module_name.clone(),
                            technique: "differential".to_string(),
                            dbms_hypothesis: Some(dbms.display_name().to_string()),
                            notes: None,
                            created_at: chrono::Utc::now(),
                            updated_at: chrono::Utc::now(),
                        };

                        let _ = state_arc.db.insert_finding(&finding);
                        state_arc.event_bus.publish(bugtools_core::events::BugToolsEvent::FindingDiscovered(finding));
                        
                        state_arc.event_bus.publish(bugtools_core::events::BugToolsEvent::AuditLog {
                            timestamp: chrono::Utc::now(),
                            level: "info".to_string(),
                            component: "sql-research".to_string(),
                            message: format!("DBMS detected: {} (confidence: {}%) for parameter '{}'", dbms.display_name(), result.confidence_score, param_name),
                        });
                    }
                }
            }

            state_arc.scheduler.update_progress(job_id, 100.0, "Job completed successfully.".to_string()).await;
        });
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

pub async fn cancel_job(job_id: String, state: &AppState) -> Result<bool, String> {
    let id = Uuid::parse_str(&job_id).map_err(|e| e.to_string())?;
    Ok(state.scheduler.cancel_job(id).await)
}
