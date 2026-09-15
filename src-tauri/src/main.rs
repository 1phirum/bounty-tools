// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod process;
mod state;

use bugtools_storage::Database;
use state::AppState;
use std::path::PathBuf;
use tauri::Emitter;

fn main() {
    let db_path = std::env::var("BUGTOOLS_DB_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("../workspace/projects/bugtools.db"));

    if let Some(parent) = db_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let db = Database::open(&db_path).expect("Failed to initialize SQLite database");
    let app_state = AppState::new(db);
    let app_state_clone = app_state.clone();

    tauri::Builder::default()
        .manage(app_state)
        .setup(move |app| {
            let handle = app.handle().clone();
            let mut rx = app_state_clone.event_bus.subscribe();
            tauri::async_runtime::spawn(async move {
                while let Ok(evt) = rx.recv().await {
                    let _ = handle.emit("bugtools-event", evt);
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::project::create_project,
            commands::project::list_projects,
            commands::project::set_active_project,
            commands::project::get_active_project,
            commands::scope::get_scope_rules,
            commands::scope::add_scope_rule,
            commands::scope::evaluate_target,
            commands::jobs::list_jobs,
            commands::jobs::start_test_job,
            commands::jobs::cancel_job,
            commands::findings::list_findings,
            commands::findings::create_finding,
            commands::traffic::get_traffic_page,
            commands::traffic::get_traffic_entry,
            commands::traffic::clear_traffic,
            commands::traffic::send_request,
            commands::traffic::repeater_send,
            commands::fuzzer::fuzzer_run,
            commands::sql_research::sql_analyze_endpoint,
            commands::sql_research::sql_get_clause_map,
            commands::sql_research::sql_get_dialect_variants,
            commands::system::get_system_info,
            commands::settings::get_settings,
            commands::settings::update_settings,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
