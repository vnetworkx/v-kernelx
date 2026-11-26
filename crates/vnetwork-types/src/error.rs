use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum VNetworkError {
    #[error("validation error: {0}")]
    Validation(String),

    #[error("authorization failed: {0}")]
    Authorization(String),

    #[error("signature error: {0}")]
    Signature(String),

    #[error("hierarchy violation: {0}")]
    Hierarchy(String),

    #[error("entity not found: {0}")]
    NotFound(String),

    #[error("entity already exists: {0}")]
    AlreadyExists(String),

    #[error("insufficient balance: {0}")]
    InsufficientBalance(String),

    #[error("token dimension invariant violated: {0}")]
    DimensionInvariant(String),

    #[error("replay protection rejected request: {0}")]
    ReplayRejected(String),

    #[error("consensus error: {0}")]
    Consensus(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("language compilation/verification error: {0}")]
    Language(String),

    #[error("network profile mismatch: {0}")]
    ProfileMismatch(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

pub type VResult<T> = Result<T, VNetworkError>;
