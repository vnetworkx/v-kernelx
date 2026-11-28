use crate::errors::{ApiError, ApiResult};
use crate::state::ApiAppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

pub async fn list_tokens(State(app): State<ApiAppState>) -> Json<serde_json::Value> {
    let state = app.backend.state_snapshot().await;
    let tokens: Vec<_> = state.tokens.values().collect();
    Json(serde_json::json!({ "tokens": tokens, "count": tokens.len() }))
}

pub async fn get_token(
    State(app): State<ApiAppState>,
    Path(token_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let state = app.backend.state_snapshot().await;
    let t = state
        .tokens
        .get(&token_id)
        .or_else(|| {
            state.tokens.values().find(|t| {
                t.symbol.eq_ignore_ascii_case(&token_id) || t.name.eq_ignore_ascii_case(&token_id)
            })
        })
        .cloned()
        .ok_or_else(|| {
            ApiError::new(StatusCode::NOT_FOUND, "TOKEN_NOT_FOUND", "token not found")
        })?;
    let balances: Vec<_> = state
        .balances
        .values()
        .filter(|b| b.token_id == t.token_id)
        .cloned()
        .collect();
    let supply_breakdown = app.backend.verify_token_supply(&t.token_id).await?;
    Ok(Json(serde_json::json!({
        "token": t,
        "balances": balances,
        "supply_breakdown": supply_breakdown,
    })))
}

pub async fn token_supply(
    State(app): State<ApiAppState>,
    Path(token_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let breakdown = app.backend.verify_token_supply(&token_id).await?;
    serde_json::to_value(breakdown).map(Json).map_err(|e| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SERIALIZATION_ERROR",
            e.to_string(),
        )
    })
}
