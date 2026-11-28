use crate::state::NetworkLedgerState;
use vnetwork_types::*;

pub fn verify_non_replay(
    state: &NetworkLedgerState,
    request_id: &str,
    actor_pubkey: &str,
    nonce: u64,
    network_id: &str,
) -> VResult<()> {
    if network_id != state.network_id {
        return Err(VNetworkError::ProfileMismatch(format!(
            "request network_id `{network_id}` does not match node network `{}`",
            state.network_id
        )));
    }
    if request_id.trim().is_empty() {
        return Err(VNetworkError::Validation(
            "request_id cannot be empty".to_string(),
        ));
    }
    if state.seen_request_ids.contains(request_id) {
        return Err(VNetworkError::ReplayRejected(format!(
            "duplicate request_id `{request_id}`"
        )));
    }
    if let Some(&prev_nonce) = state.actor_nonces.get(actor_pubkey) {
        if nonce <= prev_nonce {
            return Err(VNetworkError::ReplayRejected(format!(
                "stale nonce {nonce} <= last accepted {prev_nonce} for actor"
            )));
        }
    } else if nonce == 0 {
        return Err(VNetworkError::ReplayRejected(
            "first request nonce must be >= 1".to_string(),
        ));
    }
    Ok(())
}

pub fn record_nonce_and_request(
    state: &mut NetworkLedgerState,
    request_id: &str,
    actor_pubkey: &str,
    nonce: u64,
) {
    state.seen_request_ids.insert(request_id.to_string());
    state.actor_nonces.insert(actor_pubkey.to_string(), nonce);
}

pub fn validate_signed_envelope(
    state: &NetworkLedgerState,
    envelope: &SignedRequestEnvelope,
) -> VResult<()> {
    envelope.verify()?;
    verify_non_replay(
        state,
        &envelope.request_id,
        &envelope.actor_pubkey,
        envelope.nonce,
        &envelope.network_id,
    )
}

/// Bind the original actor-signed operation to the proposal event stream.
/// Validators use this intent event to re-run authorization and semantic
/// preconditions from the exact pre-state before voting on the result.
pub fn commit_signed_operation_intent_event(
    state: &mut NetworkLedgerState,
    envelope: &SignedRequestEnvelope,
    operation: &NetworkOperation,
    timestamp_ms: u64,
) -> VResult<LedgerEvent> {
    validate_signed_envelope(state, envelope)?;
    let actual_payload_hash = blake3_hex(&canonical_json_bytes(operation)?);
    if actual_payload_hash != envelope.payload_hash {
        return Err(VNetworkError::Signature(
            "signed operation payload hash does not match canonical operation".to_string(),
        ));
    }

    let payload = serde_json::json!({
        "envelope": envelope,
        "operation": operation,
    });
    let before_hash = state.compute_state_root()?;
    let after_hash = blake3_hex(&canonical_json_bytes(&payload)?);
    state.logical_clock = state
        .logical_clock
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
    let sequence = (state.events.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
    let parents = state.latest_event_hash().into_iter().collect();
    let event = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "request",
        &envelope.request_id,
        "SIGNED_OPERATION_INTENT",
        &envelope.actor_pubkey,
        state.logical_clock,
        timestamp_ms,
        payload,
        before_hash,
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok(event)
}

/// Commit an accepted actor nonce as an event so replay reconstructs anti-replay
/// indexes from the ledger rather than trusting mutable live-state indexes.
pub fn commit_request_nonce_event(
    state: &mut NetworkLedgerState,
    request_id: &str,
    actor_pubkey: &str,
    nonce: u64,
    timestamp_ms: u64,
) -> VResult<LedgerEvent> {
    verify_non_replay(state, request_id, actor_pubkey, nonce, &state.network_id)?;

    let before = serde_json::json!({
        "actor_pubkey": actor_pubkey,
        "previous_nonce": state.actor_nonces.get(actor_pubkey).copied(),
    });
    let payload = serde_json::json!({
        "actor_pubkey": actor_pubkey,
        "request_id": request_id,
        "nonce": nonce,
    });
    let before_hash = blake3_hex(&canonical_json_bytes(&before)?);
    let after_hash = blake3_hex(&canonical_json_bytes(&payload)?);
    state.logical_clock = state
        .logical_clock
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
    let sequence = (state.events.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
    let parents = state.latest_event_hash().into_iter().collect();
    let event = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "request",
        request_id,
        "REQUEST_NONCE_COMMIT",
        actor_pubkey,
        state.logical_clock,
        timestamp_ms,
        payload,
        before_hash,
        after_hash,
    )?;
    record_nonce_and_request(state, request_id, actor_pubkey, nonce);
    state.events.push(event.clone());
    Ok(event)
}
