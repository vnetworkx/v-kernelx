use crate::errors::ApiResult;
use crate::state::ApiAppState;
use axum::extract::State;
use axum::Json;

pub async fn list_events(State(app): State<ApiAppState>) -> Json<serde_json::Value> {
    let state = app.backend.state_snapshot().await;
    Json(serde_json::json!({
        "network_id": state.network_id,
        "height": state.height,
        "count": state.events.len(),
        "event_history_root": state.event_history_root,
        "events": state.events,
    }))
}

pub async fn ledger_proofs(State(app): State<ApiAppState>) -> ApiResult<Json<serde_json::Value>> {
    let report = app.backend.verify_ledger_proofs().await?;
    Ok(Json(serde_json::to_value(report).unwrap_or_default()))
}

pub async fn verify_replay(State(app): State<ApiAppState>) -> ApiResult<Json<serde_json::Value>> {
    let report = app.backend.verify_replay().await?;
    Ok(Json(serde_json::to_value(report).unwrap_or_default()))
}
