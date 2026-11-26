use crate::errors::{ApiError, ApiResult};
use crate::state::ApiAppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

pub async fn list_spaces(State(app): State<ApiAppState>) -> Json<serde_json::Value> {
    let state = app.backend.state_snapshot().await;
    let spaces: Vec<_> = state.spaces.values().collect();
    Json(serde_json::json!({ "spaces": spaces, "count": spaces.len() }))
}

pub async fn get_space(
    State(app): State<ApiAppState>,
    Path(space_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let state = app.backend.state_snapshot().await;
    let space = state
        .spaces
        .get(&space_id)
        .or_else(|| state.spaces.values().find(|s| s.name.eq_ignore_ascii_case(&space_id)))
        .cloned()
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "SPACE_NOT_FOUND", "space not found"))?;
    Ok(Json(serde_json::to_value(space).unwrap_or_default()))
}
