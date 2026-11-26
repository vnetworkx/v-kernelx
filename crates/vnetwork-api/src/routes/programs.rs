use crate::authentication::verify_program_submission_auth;
use crate::errors::{ApiError, ApiResult};
use crate::state::ApiAppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use vnetwork_core::language::SubmitProgramRequest;
use vnetwork_types::ProgramSubmission;

pub async fn submit_program(
    State(app): State<ApiAppState>,
    Json(req): Json<SubmitProgramRequest>,
) -> ApiResult<Json<ProgramSubmission>> {
    verify_program_submission_auth(&req)?;
    let sub = app.backend.submit_program(req).await?;
    Ok(Json(sub))
}

pub async fn get_program(
    State(app): State<ApiAppState>,
    Path(program_id): Path<String>,
) -> ApiResult<Json<ProgramSubmission>> {
    let state = app.backend.state_snapshot().await;
    let sub = state.programs.get(&program_id).cloned().ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "PROGRAM_NOT_FOUND",
            format!("program `{program_id}` not found"),
        )
    })?;
    Ok(Json(sub))
}

pub async fn get_program_status(
    State(app): State<ApiAppState>,
    Path(program_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let state = app.backend.state_snapshot().await;
    let sub = state.programs.get(&program_id).cloned().ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "PROGRAM_NOT_FOUND",
            format!("program `{program_id}` not found"),
        )
    })?;
    Ok(Json(serde_json::json!({
        "program_id": sub.program_id,
        "file_name": sub.file_name,
        "status": sub.status,
        "source_hash": sub.source_hash,
        "compiled_program_hash": sub.compiled_program_hash,
        "failed_operation_index": sub.failed_operation_index,
        "error_message": sub.error_message,
        "resulting_event_ids": sub.resulting_event_ids,
        "created_entities": sub.created_entities,
        "outputs": sub.outputs,
        "final_state_root": sub.final_state_root,
        "consensus_certificate": sub.consensus_certificate,
    })))
}
