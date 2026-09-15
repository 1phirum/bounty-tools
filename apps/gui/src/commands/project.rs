use crate::state::AppState;
use bugtools_core::project::Project;
use uuid::Uuid;

pub async fn create_project(
    name: String,
    description: String,
    state: &AppState,
) -> Result<Project, String> {
    let project = Project::new(name, description);
    // A new project must never inherit the previously selected project's scope.
    // Clear both pieces of state before database work, including on failure.
    {
        let mut active = state.active_project_id.write().await;
        *active = None;
        state.scope.set_rules(Vec::new());
        state
            .db
            .insert_project(&project)
            .map_err(|e| e.to_string())?;
    }
    set_active_project(project.id.to_string(), state).await?;

    Ok(project)
}

pub async fn list_projects(state: &AppState) -> Result<Vec<Project>, String> {
    state.db.get_projects().map_err(|e| e.to_string())
}

pub async fn set_active_project(project_id: String, state: &AppState) -> Result<(), String> {
    let mut active = state.active_project_id.write().await;
    // Fail closed: parsing, existence, or scope-query failures leave no active
    // project and no stale permissions. Bridge actions are also serialized.
    *active = None;
    state.scope.set_rules(Vec::new());
    let id = Uuid::parse_str(&project_id).map_err(|e| e.to_string())?;
    let projects = state.db.get_projects().map_err(|e| e.to_string())?;
    if !projects.iter().any(|project| project.id == id) {
        return Err(format!("Project {id} does not exist"));
    }
    let rules = state.db.get_scope_rules(id).map_err(|e| e.to_string())?;
    state.scope.set_rules(rules);
    *active = Some(id);

    Ok(())
}

pub async fn get_active_project(state: &AppState) -> Result<Option<String>, String> {
    let active = state.active_project_id.read().await;
    Ok(active.map(|id| id.to_string()))
}
