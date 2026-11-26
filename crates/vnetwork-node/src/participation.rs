use vnetwork_core::state::NetworkLedgerState;
use vnetwork_types::*;

pub fn verify_participant_scope_query(
    state: &NetworkLedgerState,
    participant_id: &str,
) -> VResult<ParticipantRecord> {
    state
        .participants
        .get(participant_id)
        .or_else(|| {
            state
                .participants
                .values()
                .find(|p| p.public_key_hex == participant_id)
        })
        .cloned()
        .ok_or_else(|| VNetworkError::NotFound(format!("participant `{participant_id}` not found")))
}

pub fn list_active_nodes(state: &NetworkLedgerState) -> Vec<NodeRecord> {
    state.nodes.values().cloned().collect()
}
