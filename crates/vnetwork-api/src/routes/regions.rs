use crate::errors::{ApiError, ApiResult};
use crate::state::ApiAppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

pub async fn list_regions(State(app): State<ApiAppState>) -> Json<serde_json::Value> {
    let state = app.backend.state_snapshot().await;
    let regions: Vec<_> = state.regions.values().collect();
    Json(serde_json::json!({ "regions": regions, "count": regions.len() }))
}

pub async fn get_region(
    State(app): State<ApiAppState>,
    Path(region_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let state = app.backend.state_snapshot().await;
    let reg = state
        .regions
        .get(&region_id)
        .or_else(|| {
            state
                .regions
                .values()
                .find(|r| r.name.eq_ignore_ascii_case(&region_id))
        })
        .cloned()
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "REGION_NOT_FOUND",
                "region not found",
            )
        })?;
    serde_json::to_value(reg).map(Json).map_err(|e| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SERIALIZATION_ERROR",
            e.to_string(),
        )
    })
}
