use crate::authentication::SignedOperationHttpRequest;
use crate::errors::{ApiError, ApiResult};
use crate::state::ApiAppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use vnetwork_core::state::TransactionReceipt;
use vnetwork_types::NetworkOperation;

pub async fn list_loans(State(app): State<ApiAppState>) -> Json<serde_json::Value> {
    let state = app.backend.state_snapshot().await;
    let loans: Vec<_> = state.loans.values().collect();
    Json(serde_json::json!({ "loans": loans, "count": loans.len() }))
}

pub async fn create_or_execute_loan(
    State(app): State<ApiAppState>,
    Json(req): Json<SignedOperationHttpRequest>,
) -> ApiResult<Json<TransactionReceipt>> {
    match &req.operation {
        NetworkOperation::CreateLoan { .. } | NetworkOperation::ExecuteLoan { .. } => {}
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "INVALID_LOAN_OP",
                "endpoint requires CreateLoan or ExecuteLoan operation",
            ));
        }
    }
    let receipt = app.backend.submit_signed_operation(req).await?;
    Ok(Json(receipt))
}

pub async fn get_loan(
    State(app): State<ApiAppState>,
    Path(loan_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let state = app.backend.state_snapshot().await;
    let l = state
        .loans
        .get(&loan_id)
        .or_else(|| {
            state
                .loans
                .values()
                .find(|l| l.name.eq_ignore_ascii_case(&loan_id))
        })
        .cloned()
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "LOAN_NOT_FOUND", "loan not found"))?;
    serde_json::to_value(l).map(Json).map_err(|e| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SERIALIZATION_ERROR",
            e.to_string(),
        )
    })
}
