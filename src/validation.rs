use crate::error::KernelXError;
use crate::state::{validate_canonical_state, VectorStateV1};

pub fn validate_state(state: &VectorStateV1) -> Result<(), KernelXError> {
    validate_canonical_state(state)?;
    Ok(())
}

pub fn validate_signature(
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<(), KernelXError> {
    crate::wallet::verify_signature(public_key_hex, message, signature_hex)
}

pub fn validate_dimension_match(a: &VectorStateV1, b: &VectorStateV1) -> Result<(), KernelXError> {
    a.ensure_same_shape(b)
}
