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
        return Err(VNetworkError::Validation("request_id cannot be empty".to_string()));
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
