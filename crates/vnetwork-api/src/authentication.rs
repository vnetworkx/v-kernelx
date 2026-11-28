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
        let payload_hash =
            blake3_hex(&canonical_json_bytes(&self.operation).map_err(ApiError::from)?);
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

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn configured_admin_token() -> Option<String> {
    for name in ["NETWORK_ADMIN_TOKEN", "ATLAS_ADMIN_TOKEN"] {
        if let Ok(raw) = std::env::var(name) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() && trimmed != "null" && trimmed != "undefined" {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn extract_admin_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    if let Some(val) = headers.get("x-admin-token").and_then(|v| v.to_str().ok()) {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }
    if let Some(auth) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let trimmed = auth.trim();
        if let Some(rest) = trimmed
            .strip_prefix("Bearer ")
            .or_else(|| trimmed.strip_prefix("bearer "))
        {
            let tok = rest.trim();
            if !tok.is_empty() {
                return Some(tok);
            }
        }
    }
    None
}

pub fn require_admin_token(headers: &axum::http::HeaderMap) -> Result<(), ApiError> {
    let expected = configured_admin_token().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "ADMIN_TOKEN_UNCONFIGURED",
            "administrative endpoint requires NETWORK_ADMIN_TOKEN or ATLAS_ADMIN_TOKEN to be configured",
        )
    })?;
    let provided = extract_admin_token(headers).ok_or_else(|| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "MISSING_ADMIN_TOKEN",
            "missing X-Admin-Token or Authorization: Bearer <token> header",
        )
    })?;
    if !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "INVALID_ADMIN_TOKEN",
            "invalid administrative token",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn test_constant_time_eq_behavior() {
        assert!(constant_time_eq(b"secret-123", b"secret-123"));
        assert!(!constant_time_eq(b"secret-123", b"secret-124"));
        assert!(!constant_time_eq(b"secret-123", b"secret-1234"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_extract_admin_token_headers() {
        let mut h = HeaderMap::new();
        assert_eq!(extract_admin_token(&h), None);
        h.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer tok-bearer-1"),
        );
        assert_eq!(extract_admin_token(&h), Some("tok-bearer-1"));
        h.insert("x-admin-token", HeaderValue::from_static("tok-header-2"));
        assert_eq!(extract_admin_token(&h), Some("tok-header-2"));
    }
}
