use crate::state::AppState;
use bugtools_core::settings::Settings;
use tauri::State;

#[tauri::command]
pub async fn get_settings(state: State<'_, AppState>) -> Result<Settings, String> {
    state.db.get_settings().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn update_settings(settings: Settings, state: State<'_, AppState>) -> Result<(), String> {
    state.db.update_settings(&settings).map_err(|e| e.to_string())
}
