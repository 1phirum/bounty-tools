use chrono::Utc;
use serde::Serialize;
use std::sync::{Mutex, OnceLock};
use sysinfo::System;

static SYS: OnceLock<Mutex<System>> = OnceLock::new();

#[derive(Debug, Clone, Serialize)]
pub struct SystemInfo {
    pub cpu_name: String,
    pub cpu_cores: usize,
    pub cpu_usage_percent: f32,
    pub ram_total_mb: u64,
    pub ram_used_mb: u64,
    pub ram_usage_percent: f32,
    pub datetime: String,
}

#[tauri::command]
pub async fn get_system_info() -> Result<SystemInfo, String> {
    let mut sys_guard = SYS.get_or_init(|| Mutex::new(System::new())).lock().unwrap();
    sys_guard.refresh_memory();
    sys_guard.refresh_cpu_all();

    let cpu_name = sys_guard
        .cpus()
        .first()
        .map(|c| c.brand().trim().to_string())
        .unwrap_or_else(|| "Unknown CPU".to_string());

    let cpu_cores = sys_guard.cpus().len();
    
    let cpu_usage_sum: f32 = sys_guard.cpus().iter().map(|c| c.cpu_usage()).sum();
    let cpu_usage_percent = if cpu_cores > 0 {
        cpu_usage_sum / (cpu_cores as f32)
    } else {
        0.0
    };

    let ram_total_mb = sys_guard.total_memory() / (1024 * 1024);
    let ram_used_mb = sys_guard.used_memory() / (1024 * 1024);
    let ram_usage_percent = if ram_total_mb > 0 {
        (ram_used_mb as f32 / ram_total_mb as f32) * 100.0
    } else {
        0.0
    };

    Ok(SystemInfo {
        cpu_name,
        cpu_cores,
        cpu_usage_percent,
        ram_total_mb,
        ram_used_mb,
        ram_usage_percent,
        datetime: Utc::now().to_rfc3339(),
    })
}

