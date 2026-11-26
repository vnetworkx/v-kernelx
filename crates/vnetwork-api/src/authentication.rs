use crate::errors::ApiError;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use vnetwork_core::language::SubmitProgramRequest;
use vnetwork_types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedOperationHttpRequest {
    pub request_id: String,
    pub network_id: String,
    pub actor_pubkey: String,
    pub nonce: u64,
    pub timestamp_ms: u64,
    pub signature: String,
    pub operation: NetworkOperation,
}

impl SignedOperationHttpRequest {
    pub fn verify_and_extract_envelope(&self) -> Result<SignedRequestEnvelope, ApiError> {
        let payload_hash = blake3_hex(
            &canonical_json_bytes(&self.operation)
                .map_err(ApiError::from)?,
        );
        let env = SignedRequestEnvelope {
            request_id: self.request_id.clone(),
            network_id: self.network_id.clone(),
            actor_pubkey: self.actor_pubkey.clone(),
            nonce: self.nonce,
            timestamp_ms: self.timestamp_ms,
            signature: self.signature.clone(),
            payload_hash,
        };
        env.verify().map_err(ApiError::from)?;
        Ok(env)
    }
}

pub fn verify_program_submission_auth(req: &SubmitProgramRequest) -> Result<(), ApiError> {
    if req.source_bytes.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "EMPTY_SOURCE",
            "Vector Language source_bytes cannot be empty",
        ));
    }
    req.verify_signature().map_err(ApiError::from)?;
    Ok(())
}
