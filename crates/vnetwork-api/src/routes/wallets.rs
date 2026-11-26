use crate::errors::{ApiError, ApiResult};
use crate::state::ApiAppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

pub async fn list_wallets(State(app): State<ApiAppState>) -> Json<serde_json::Value> {
    let state = app.backend.state_snapshot().await;
    let wallets: Vec<_> = state.wallets.values().collect();
    Json(serde_json::json!({ "wallets": wallets, "count": wallets.len() }))
}

pub async fn get_wallet(
    State(app): State<ApiAppState>,
    Path(wallet_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let state = app.backend.state_snapshot().await;
    let w = state
        .wallets
        .get(&wallet_id)
        .or_else(|| state.wallets.values().find(|w| w.name.eq_ignore_ascii_case(&wallet_id)))
        .cloned()
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "WALLET_NOT_FOUND", "wallet not found"))?;
    let balances: Vec<_> = state
        .balances
        .values()
        .filter(|b| b.wallet_id == w.wallet_id)
        .cloned()
        .collect();
    Ok(Json(serde_json::json!({
        "wallet": w,
        "balances": balances,
    })))
}
