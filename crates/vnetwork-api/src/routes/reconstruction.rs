use crate::errors::ApiResult;
use crate::state::ApiAppState;
use axum::extract::State;
use axum::Json;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ReconstructRequest {
    pub entity_kind: String,
    pub entity_id: String,
}

pub async fn verify_reconstruction(
    State(app): State<ApiAppState>,
    Json(req): Json<ReconstructRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let report = app
        .backend
        .verify_reconstruction(&req.entity_kind, &req.entity_id)
        .await?;
    Ok(Json(serde_json::to_value(report).unwrap_or_default()))
}
