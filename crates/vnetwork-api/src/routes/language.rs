use crate::errors::{ApiError, ApiResult};
use crate::state::ApiAppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use std::collections::BTreeMap;
use vnetwork_core::language::{compile_vx_source, parse_vx_source};

#[derive(Debug, Deserialize)]
pub struct LanguageSourceRequest {
    #[serde(default = "default_file_name")]
    pub file_name: String,
    pub source_bytes: String,
    #[serde(default)]
    pub modules: BTreeMap<String, String>,
}

fn default_file_name() -> String {
    "program.vx".to_string()
}

pub async fn parse_source(
    Json(req): Json<LanguageSourceRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let res = parse_vx_source(&req.source_bytes)?;
    Ok(Json(res))
}

pub async fn compile_source(
    Json(req): Json<LanguageSourceRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let compiled = compile_vx_source(&req.source_bytes, &req.file_name, &req.modules, None)?;
    serde_json::to_value(compiled).map(Json).map_err(|e| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SERIALIZATION_ERROR",
            e.to_string(),
        )
    })
}

pub async fn validate_source(
    State(app): State<ApiAppState>,
    Json(req): Json<LanguageSourceRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let compiled = compile_vx_source(&req.source_bytes, &req.file_name, &req.modules, None)?;
    let state = app.backend.state_snapshot().await;
    Ok(Json(serde_json::json!({
        "valid": true,
        "network_id": state.network_id,
        "language_version": compiled.language_version,
        "compiler_version": compiled.compiler_version,
        "source_hash": compiled.source_hash,
        "program_hash": compiled.program_hash,
        "imported_modules": compiled.imported_modules,
        "op_count": compiled.ops.len(),
        "ops": compiled.ops,
        "diagnostics": compiled.diagnostics,
    })))
}
