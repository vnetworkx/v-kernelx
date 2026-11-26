use crate::state::NetworkLedgerState;
use vnetwork_types::*;

pub fn list_ghost_entities(state: &NetworkLedgerState) -> serde_json::Value {
    let spaces: Vec<&SpaceEntity> = state.spaces.values().filter(|s| s.ghost).collect();
    let regions: Vec<&RegionEntity> = state.regions.values().filter(|r| r.ghost).collect();
    let wallets: Vec<&WalletEntity> = state.wallets.values().filter(|w| w.ghost).collect();
    let tokens: Vec<&TokenEntity> = state.tokens.values().filter(|t| t.ghost).collect();
    serde_json::json!({
        "spaces": spaces,
        "regions": regions,
        "wallets": wallets,
        "tokens": tokens,
    })
}

pub fn validate_ghost_permissions(
    state: &NetworkLedgerState,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<()> {
    crate::identity::require_participant_scope_at(
        state,
        actor_pubkey,
        ParticipationLevel::Network,
        None,
        timestamp_ms,
    )
}
