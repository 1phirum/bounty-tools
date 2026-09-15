use crate::state::AppState;
use bugtools_core::events::BugToolsEvent;
use bugtools_core::finding::{Confidence, Finding, FindingStatus, Severity};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use uuid::Uuid;

#[derive(Serialize)]
struct JobRequestPayload {
    protocol_version: u32,
    #[serde(rename = "type")]
    msg_type: String,
    id: String,
    module: String,
    target: String,
}

#[derive(Deserialize)]
struct FindingPayload {
    target: String,
    host: String,
    title: String,
    description: String,
}

#[derive(Deserialize)]
struct ResultPayload {
    #[serde(default)]
    findings: Vec<FindingPayload>,
}

pub fn execute_recon_worker(
    job_id: Uuid,
    project_id: Uuid,
    target: String,
    module: String,
    state: AppState,
) {
    tokio::task::spawn_blocking(move || {
        // Find recon.exe or use go run as fallback
        let binary_path = find_recon_binary();
        let mut cmd = if let Some(bin) = binary_path {
            Command::new(bin)
        } else {
            let mut c = Command::new("go");
            c.args(["run", "./cmd/recon"]);
            c.current_dir("engines/recon-go");
            c
        };

        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let rt = tokio::runtime::Handle::current();
                rt.block_on(async {
                    state
                        .scheduler
                        .update_progress(
                            job_id,
                            100.0,
                            format!("Failed to start Go recon worker: {}", e),
                        )
                        .await;
                });
                return;
            }
        };

        // Send job payload to Go worker via stdin
        let payload = JobRequestPayload {
            protocol_version: 1,
            msg_type: "job".to_string(),
            id: job_id.to_string(),
            module,
            target: target.clone(),
        };

        if let Some(mut stdin) = child.stdin.take() {
            if let Ok(json) = serde_json::to_string(&payload) {
                let _ = writeln!(stdin, "{}", json);
                let _ = stdin.flush();
            }
        }

        // Stream stdout events
        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            for line in reader.lines().flatten() {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                    let msg_type = val.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    let rt = tokio::runtime::Handle::current();

                    if msg_type == "progress" {
                        let pct = val.get("progress").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
                        let step = val.get("step").and_then(|v| v.as_str()).unwrap_or("Working...").to_string();
                        rt.block_on(async {
                            state.scheduler.update_progress(job_id, pct, step).await;
                        });
                    } else if msg_type == "result" {
                        if let Ok(res) = serde_json::from_value::<ResultPayload>(val) {
                            for f in res.findings {
                                let finding = Finding {
                                    id: Uuid::new_v4(),
                                    project_id,
                                    title: f.title,
                                    severity: Severity::Info,
                                    confidence: Confidence::High,
                                    status: FindingStatus::Verified,
                                    target: f.target,
                                    endpoint: f.host,
                                    parameter: None,
                                    module: "recon-go".to_string(),
                                    technique: "dns-resolution".to_string(),
                                    dbms_hypothesis: None,
                                    notes: Some(f.description),
                                    created_at: Utc::now(),
                                    updated_at: Utc::now(),
                                };
                                let _ = state.db.insert_finding(&finding);
                                state.event_bus.publish(BugToolsEvent::FindingDiscovered(finding));
                            }
                            rt.block_on(async {
                                state
                                    .scheduler
                                    .update_progress(job_id, 100.0, "Recon scan completed successfully".to_string())
                                    .await;
                            });
                        }
                    }
                }
            }
        }

        let _ = child.wait();
    });
}

fn find_recon_binary() -> Option<PathBuf> {
    let candidates = [
        PathBuf::from("engines/recon-go/recon.exe"),
        PathBuf::from("../engines/recon-go/recon.exe"),
        PathBuf::from("engines/recon-go/bin/recon.exe"),
    ];

    for c in candidates {
        if c.exists() {
            return Some(c);
        }
    }
    None
}
