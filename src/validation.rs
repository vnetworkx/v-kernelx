use crate::error::KernelXError;
use crate::event::OperationType;
use crate::hash::{canonical_event_hash, canonical_payload_hash};
use crate::region::{is_region_create_event, REGION_CREATE_OPERATION_NAME};
use crate::serialization::canonical_event_payload_bytes;
use crate::signature::{verify_event_signature, verifying_key_from_hex};
use crate::state::{validate_canonical_state, VectorStateV1};
use crate::VectorEvent;

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

/// Canonical event validation for the post-v-nodex kernel path.
pub fn validate_event(event: &VectorEvent) -> Result<(), KernelXError> {
    if event.event_id.trim().is_empty() {
        return Err(KernelXError::InvalidState(
            "event_id is required".to_string(),
        ));
    }
    if event.region_id.trim().is_empty() {
        return Err(KernelXError::InvalidState(
            "region_id is required".to_string(),
        ));
    }
    if event.entity_id.trim().is_empty() {
        return Err(KernelXError::InvalidState(
            "entity_id is required".to_string(),
        ));
    }
    if event.actor_public_key.trim().is_empty() {
        return Err(KernelXError::InvalidState(
            "actor_public_key is required".to_string(),
        ));
    }
    if !event.auth_ratio.is_finite() || event.auth_ratio < 0.0 || event.auth_ratio > 1.0 {
        return Err(KernelXError::InvalidState(
            "auth_ratio must be in [0, 1]".to_string(),
        ));
    }
    if event.vector_before.components.len() != event.vector_after.components.len() {
        return Err(KernelXError::DimensionMismatch);
    }

    let payload_bytes = canonical_event_payload_bytes(event);
    let payload_hash = canonical_payload_hash(event);
    let event_hash = canonical_event_hash(event);

    if event.payload_hash != payload_hash {
        return Err(KernelXError::InvalidState(
            "payload_hash mismatch".to_string(),
        ));
    }
    if event.event_hash != event_hash {
        return Err(KernelXError::InvalidState(
            "event_hash mismatch".to_string(),
        ));
    }

    let is_region_create = is_region_create_event(event);

    if is_region_create {
        if event.signature.trim().is_empty() {
            return Err(KernelXError::InvalidState(
                "region create event requires a signature".to_string(),
            ));
        }

        if !event.parent_hashes.is_empty() {
            return Err(KernelXError::InvalidState(
                "region create event must be a root event".to_string(),
            ));
        }

        if event.operation != OperationType::Other(REGION_CREATE_OPERATION_NAME.to_string()) {
            return Err(KernelXError::InvalidState(
                "region create event has invalid operation tag".to_string(),
            ));
        }

        return Ok(());
    }

    if !event.signature.is_empty() {
        let verifying_key =
            verifying_key_from_hex(&event.actor_public_key).map_err(KernelXError::InvalidState)?;
        let signature_ok = verify_event_signature(&verifying_key, &payload_bytes, &event.signature)
            .map_err(KernelXError::InvalidState)?;
        if !signature_ok {
            return Err(KernelXError::InvalidState(
                "event signature verification failed".to_string(),
            ));
        }
    }

    Ok(())
}

/// Convenience helper for checking a detached event payload and signature together.
pub fn validate_event_signature(
    public_key_hex: &str,
    event: &VectorEvent,
) -> Result<(), KernelXError> {
    let verifying_key =
        verifying_key_from_hex(public_key_hex).map_err(KernelXError::InvalidState)?;
    let payload_bytes = canonical_event_payload_bytes(event);
    let ok = verify_event_signature(&verifying_key, &payload_bytes, &event.signature)
        .map_err(|e| KernelXError::InvalidState(e.to_string()))?;
    if ok {
        Ok(())
    } else {
        Err(KernelXError::InvalidState(
            "event signature verification failed".to_string(),
        ))
    }
}
