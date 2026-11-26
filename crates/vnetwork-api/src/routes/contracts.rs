use crate::authentication::SignedOperationHttpRequest;
use crate::errors::{ApiError, ApiResult};
use crate::state::ApiAppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use vnetwork_core::state::TransactionReceipt;
use vnetwork_types::NetworkOperation;

pub async fn list_contracts(State(app): State<ApiAppState>) -> Json<serde_json::Value> {
    let state = app.backend.state_snapshot().await;
    let contracts: Vec<_> = state.contracts.values().collect();
    Json(serde_json::json!({ "contracts": contracts, "count": contracts.len() }))
}

pub async fn create_or_execute_contract(
    State(app): State<ApiAppState>,
    Json(req): Json<SignedOperationHttpRequest>,
) -> ApiResult<Json<TransactionReceipt>> {
    match &req.operation {
        NetworkOperation::CreateContract { .. } | NetworkOperation::ExecuteContract { .. } => {}
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "INVALID_CONTRACT_OP",
                "endpoint requires CreateContract or ExecuteContract operation",
            ));
        }
    }
    let receipt = app.backend.submit_signed_operation(req).await?;
    Ok(Json(receipt))
}

pub async fn get_contract(
    State(app): State<ApiAppState>,
    Path(contract_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let state = app.backend.state_snapshot().await;
    let c = state
        .contracts
        .get(&contract_id)
        .or_else(|| {
            state
                .contracts
                .values()
                .find(|c| c.name.eq_ignore_ascii_case(&contract_id))
        })
        .cloned()
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "CONTRACT_NOT_FOUND", "contract not found"))?;
    serde_json::to_value(c).map(Json).map_err(|e| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SERIALIZATION_ERROR",
            e.to_string(),
        )
    })
}
