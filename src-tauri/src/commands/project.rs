use crate::state::AppState;
use bugtools_core::project::Project;
use tauri::State;
use uuid::Uuid;

#[tauri::command]
pub async fn create_project(
    name: String,
    description: String,
    state: State<'_, AppState>,
) -> Result<Project, String> {
    let project = Project::new(name, description);
    state
        .db
        .insert_project(&project)
        .map_err(|e| e.to_string())?;

    let mut active = state.active_project_id.write().await;
    *active = Some(project.id);

    Ok(project)
}

#[tauri::command]
pub async fn list_projects(state: State<'_, AppState>) -> Result<Vec<Project>, String> {
    state.db.get_projects().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn set_active_project(project_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let id = Uuid::parse_str(&project_id).map_err(|e| e.to_string())?;
    let mut active = state.active_project_id.write().await;
    *active = Some(id);

    // Sync scope engine with this project's rules
    if let Ok(rules) = state.db.get_scope_rules(id) {
        state.scope.set_rules(rules);
    }

    Ok(())
}

#[tauri::command]
pub async fn get_active_project(state: State<'_, AppState>) -> Result<Option<String>, String> {
    let active = state.active_project_id.read().await;
    Ok(active.map(|id| id.to_string()))
}
