use crate::authentication::SignedOperationHttpRequest;
use crate::errors::{ApiError, ApiResult};
use crate::state::ApiAppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use vnetwork_core::state::TransactionReceipt;

pub async fn submit_transaction(
    State(app): State<ApiAppState>,
    Json(req): Json<SignedOperationHttpRequest>,
) -> ApiResult<Json<TransactionReceipt>> {
    let receipt = app.backend.submit_signed_operation(req).await?;
    Ok(Json(receipt))
}

pub async fn get_transaction(
    State(app): State<ApiAppState>,
    Path(transaction_id): Path<String>,
) -> ApiResult<Json<TransactionReceipt>> {
    let state = app.backend.state_snapshot().await;
    let tx = state
        .transactions
        .get(&transaction_id)
        .cloned()
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "TRANSACTION_NOT_FOUND",
                format!("transaction `{transaction_id}` not found"),
            )
        })?;
    Ok(Json(tx))
}
