use crate::state::AppState;
use bugtools_core::settings::Settings;

pub async fn get_settings(state: &AppState) -> Result<Settings, String> {
    state.db.get_settings().map_err(|e| e.to_string())
}

pub async fn update_settings(settings: Settings, state: &AppState) -> Result<(), String> {
    state.db.update_settings(&settings).map_err(|e| e.to_string())
}
