//! Host-side bridge to the out-of-process Go engines.
//!
//! Each Go engine (`engines/<module>-go`) speaks a line-oriented JSON protocol
//! on stdin/stdout: the host writes exactly one [`JobRequest`] line, then reads
//! [`ProgressUpdate`] / [`JobResult`] lines until a terminal `result`/`error`.
//! This module owns locating the binary, spawning it, and translating that
//! stream into typed values for a command handler.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

/// Versioned contract shared with the Go engines (see their `protocol` pkg).
pub const PROTOCOL_VERSION: i64 = 1;

/// The single job object written to an engine's stdin.
#[derive(Debug, Serialize)]
pub struct JobRequest {
    pub protocol_version: i64,
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    pub module: String,
    pub target: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub config: HashMap<String, Value>,
}

/// One discovered fact returned by an engine. Mirrors the Go `FindingEvent`;
/// unknown fields are ignored so the engine can add more without breaking us.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Finding {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub port: i64,
    #[serde(default)]
    pub record_type: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Like [`locate_explicit`] but for an *explicitly configured* binary only.
///
/// Returns the path from `override_path` or `BUGTOOLS_<MODULE>_ENGINE` (erroring
/// if either is set but missing), or `Ok(None)` when neither is set — letting
/// the caller fall back to the embedded engine. An explicit `--engine`/env
/// value still wins over the baked-in copy, so users can swap in their own.
pub fn locate_explicit(module: &str, override_path: Option<&str>) -> Result<Option<PathBuf>> {
    if let Some(p) = override_path {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Ok(Some(pb));
        }
        bail!("engine binary not found at --engine path: {p}");
    }

    let env_key = format!("BUGTOOLS_{}_ENGINE", module.to_uppercase());
    if let Ok(p) = std::env::var(&env_key) {
        let pb = PathBuf::from(&p);
        if pb.exists() {
            return Ok(Some(pb));
        }
        bail!("{env_key} points to a missing binary: {p}");
    }

    Ok(None)
}

/// Spawn the engine and drive one job to completion.
///
/// `on_progress` is called for every progress line (percent, step). Returns
/// the collected findings on success, or an error if the engine reports one,
/// exits non-zero, or emits no terminal message.
pub async fn run_job<F>(
    binary: &PathBuf,
    module: &str,
    target: &str,
    config: HashMap<String, Value>,
    mut on_progress: F,
) -> Result<Vec<Finding>>
where
    F: FnMut(f64, &str),
{
    let req = JobRequest {
        protocol_version: PROTOCOL_VERSION,
        kind: "job".to_string(),
        id: uuid::Uuid::new_v4().to_string(),
        module: module.to_string(),
        target: target.to_string(),
        config,
    };
    let line = serde_json::to_string(&req).context("serialize job request")?;

    let mut child = Command::new(binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn engine binary: {}", binary.display()))?;

    // Write the single job line, then close stdin so the engine's scanner
    // sees EOF and starts work.
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("engine stdin unavailable"))?;
        stdin.write_all(line.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.shutdown().await?;
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("engine stdout unavailable"))?;
    let mut lines = BufReader::new(stdout).lines();

    let mut findings: Option<Vec<Finding>> = None;
    let mut engine_error: Option<String> = None;

    while let Some(line) = lines.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            // A stray non-JSON log line from the engine is not fatal; skip it.
            Err(_) => continue,
        };
        match msg.get("type").and_then(Value::as_str) {
            Some("progress") => {
                let pct = msg.get("progress").and_then(Value::as_f64).unwrap_or(0.0);
                let step = msg.get("step").and_then(Value::as_str).unwrap_or("");
                on_progress(pct, step);
            }
            Some("result") => {
                let f = msg.get("findings").cloned().unwrap_or(Value::Null);
                findings = Some(if f.is_null() {
                    Vec::new()
                } else {
                    serde_json::from_value(f).context("decode findings")?
                });
            }
            Some("error") => {
                engine_error = Some(
                    msg.get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown engine error")
                        .to_string(),
                );
            }
            _ => {}
        }
    }

    let status = child.wait().await.context("waiting for engine to exit")?;

    if let Some(err) = engine_error {
        bail!("engine reported an error: {err}");
    }
    if !status.success() {
        let mut stderr_buf = String::new();
        if let Some(mut err) = child.stderr.take() {
            use tokio::io::AsyncReadExt;
            let _ = err.read_to_string(&mut stderr_buf).await;
        }
        bail!(
            "engine exited with status {}{}",
            status,
            if stderr_buf.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", stderr_buf.trim())
            }
        );
    }

    findings.ok_or_else(|| anyhow!("engine produced no result message"))
}
