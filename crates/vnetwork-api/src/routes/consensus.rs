use crate::state::ApiAppState;
use axum::extract::State;
use axum::Json;

pub async fn consensus_status(State(app): State<ApiAppState>) -> Json<serde_json::Value> {
    Json(app.backend.consensus_status().await)
}

pub async fn list_certificates(State(app): State<ApiAppState>) -> Json<serde_json::Value> {
    let state = app.backend.state_snapshot().await;
    let certs: Vec<_> = state.certificates.values().collect();
    Json(serde_json::json!({
        "count": certs.len(),
        "certificates": certs,
    }))
}
