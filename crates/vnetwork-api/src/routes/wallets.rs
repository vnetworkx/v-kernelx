use crate::authentication::SignedOperationHttpRequest;
use crate::errors::{ApiError, ApiResult};
use crate::state::ApiAppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use vnetwork_core::state::TransactionReceipt;
use vnetwork_types::NetworkOperation;

pub async fn list_wallets(State(app): State<ApiAppState>) -> Json<serde_json::Value> {
    let state = app.backend.state_snapshot().await;
    let wallets: Vec<_> = state.wallets.values().collect();
    Json(serde_json::json!({ "wallets": wallets, "count": wallets.len() }))
}

pub async fn manage_wallet_key(
    State(app): State<ApiAppState>,
    Json(req): Json<SignedOperationHttpRequest>,
) -> ApiResult<Json<TransactionReceipt>> {
    match &req.operation {
        NetworkOperation::AuthorizeWalletKey { .. }
        | NetworkOperation::RevokeWalletKey { .. }
        | NetworkOperation::RotateWalletKey { .. } => {}
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "INVALID_WALLET_KEY_OP",
                "endpoint requires AuthorizeWalletKey, RevokeWalletKey, or RotateWalletKey operation",
            ));
        }
    }
    let receipt = app.backend.submit_signed_operation(req).await?;
    Ok(Json(receipt))
}

pub async fn update_wallet_receive_policy(
    State(app): State<ApiAppState>,
    Json(req): Json<SignedOperationHttpRequest>,
) -> ApiResult<Json<TransactionReceipt>> {
    if !matches!(
        &req.operation,
        NetworkOperation::UpdateWalletReceivePolicy { .. }
    ) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "INVALID_WALLET_POLICY_OP",
            "endpoint requires UpdateWalletReceivePolicy operation",
        ));
    }
    let receipt = app.backend.submit_signed_operation(req).await?;
    Ok(Json(receipt))
}

pub async fn get_wallet(
    State(app): State<ApiAppState>,
    Path(wallet_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let state = app.backend.state_snapshot().await;
    let w = state
        .wallets
        .get(&wallet_id)
        .or_else(|| {
            state
                .wallets
                .values()
                .find(|w| w.name.eq_ignore_ascii_case(&wallet_id))
        })
        .cloned()
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "WALLET_NOT_FOUND",
                "wallet not found",
            )
        })?;
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
