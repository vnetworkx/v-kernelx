use crate::authentication::SignedOperationHttpRequest;
use crate::errors::{ApiError, ApiResult};
use crate::state::ApiAppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use vnetwork_core::identity::JoinNetworkRequest;
use vnetwork_core::state::TransactionReceipt;
use vnetwork_types::{NetworkOperation, ParticipantChallenge};

pub async fn challenge(State(app): State<ApiAppState>) -> ApiResult<Json<ParticipantChallenge>> {
    let ch = app.backend.issue_challenge().await?;
    Ok(Json(ch))
}

pub async fn join(
    State(app): State<ApiAppState>,
    Json(req): Json<JoinNetworkRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let res = app.backend.join_participant(req).await?;
    Ok(Json(res))
}

pub async fn manage_scope(
    State(app): State<ApiAppState>,
    Json(req): Json<SignedOperationHttpRequest>,
) -> ApiResult<Json<TransactionReceipt>> {
    match &req.operation {
        NetworkOperation::GrantParticipantScope { .. }
        | NetworkOperation::RevokeParticipantScope { .. } => {}
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "INVALID_SCOPE_OP",
                "endpoint requires GrantParticipantScope or RevokeParticipantScope operation",
            ));
        }
    }
    let receipt = app.backend.submit_signed_operation(req).await?;
    Ok(Json(receipt))
}

pub async fn get_participant(
    State(app): State<ApiAppState>,
    Path(participant_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let state = app.backend.state_snapshot().await;
    let p = state
        .participants
        .get(&participant_id)
        .or_else(|| {
            state
                .participants
                .values()
                .find(|p| p.public_key_hex == participant_id)
        })
        .cloned()
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "PARTICIPANT_NOT_FOUND",
                format!("participant `{participant_id}` not found"),
            )
        })?;
    serde_json::to_value(p).map(Json).map_err(|e| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SERIALIZATION_ERROR",
            e.to_string(),
        )
    })
}

pub async fn get_participant_scope(
    State(app): State<ApiAppState>,
    Path(participant_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let state = app.backend.state_snapshot().await;
    let p = state
        .participants
        .get(&participant_id)
        .or_else(|| {
            state
                .participants
                .values()
                .find(|p| p.public_key_hex == participant_id)
        })
        .cloned()
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "PARTICIPANT_NOT_FOUND",
                format!("participant `{participant_id}` not found"),
            )
        })?;
    Ok(Json(serde_json::json!({
        "participant_id": p.participant_id,
        "node_id": p.node_id,
        "status": p.status,
        "node_kind": p.node_kind,
        "scope": p.scope,
    })))
}
