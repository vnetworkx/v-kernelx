use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use vnetwork_types::VNetworkError;

#[derive(Debug, Serialize)]
pub struct ApiErrorBody {
    pub error: String,
    pub code: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

impl From<VNetworkError> for ApiError {
    fn from(err: VNetworkError) -> Self {
        let (status, code) = match &err {
            VNetworkError::Validation(_) => (StatusCode::BAD_REQUEST, "VALIDATION_ERROR"),
            VNetworkError::Authorization(_) => (StatusCode::FORBIDDEN, "AUTHORIZATION_ERROR"),
            VNetworkError::Signature(_) => (StatusCode::UNAUTHORIZED, "SIGNATURE_INVALID"),
            VNetworkError::Hierarchy(_) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "HIERARCHY_VIOLATION")
            }
            VNetworkError::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            VNetworkError::AlreadyExists(_) => (StatusCode::CONFLICT, "ALREADY_EXISTS"),
            VNetworkError::InsufficientBalance(_) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "INSUFFICIENT_BALANCE")
            }
            VNetworkError::DimensionInvariant(_) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "DIMENSION_INVARIANT")
            }
            VNetworkError::ReplayRejected(_) => (StatusCode::CONFLICT, "REPLAY_REJECTED"),
            VNetworkError::Consensus(_) => (StatusCode::SERVICE_UNAVAILABLE, "CONSENSUS_ERROR"),
            VNetworkError::Storage(_) => (StatusCode::INTERNAL_SERVER_ERROR, "STORAGE_ERROR"),
            VNetworkError::Language(_) => (StatusCode::UNPROCESSABLE_ENTITY, "LANGUAGE_ERROR"),
            VNetworkError::ProfileMismatch(_) => (StatusCode::CONFLICT, "PROFILE_MISMATCH"),
            VNetworkError::Serialization(_) => (StatusCode::BAD_REQUEST, "SERIALIZATION_ERROR"),
        };
        Self::new(status, code, err.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status_u16 = self.status.as_u16();
        let body = ApiErrorBody {
            error: self.message,
            code: self.code,
            status: status_u16,
            details: self.details,
        };
        (self.status, Json(body)).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
