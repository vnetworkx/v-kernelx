use crate::state::NetworkLedgerState;
use serde::{Deserialize, Serialize};
use vnetwork_types::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhostRiskAssessment {
    pub network_id: String,
    pub total_ghost_entities: usize,
    pub ghost_spaces: Vec<String>,
    pub ghost_regions: Vec<String>,
    pub parentless_regions: Vec<String>,
    pub ghost_wallets: Vec<String>,
    pub parentless_wallets: Vec<String>,
    pub ghost_tokens: Vec<String>,
    pub parentless_tokens: Vec<String>,
    pub risk_flags: Vec<String>,
    pub ghost_ledger_commitment: String,
}

pub fn inspect_ghost_entities(state: &NetworkLedgerState) -> VResult<GhostRiskAssessment> {
    let mut ghost_spaces: Vec<String> = state
        .spaces
        .values()
        .filter(|s| s.ghost)
        .map(|s| s.space_id.clone())
        .collect();
    ghost_spaces.sort();

    let mut ghost_regions = Vec::new();
    let mut parentless_regions = Vec::new();
    for r in state.regions.values().filter(|r| r.ghost) {
        ghost_regions.push(r.region_id.clone());
        if r.space_id.is_empty() {
            parentless_regions.push(r.region_id.clone());
        }
    }
    ghost_regions.sort();
    parentless_regions.sort();

    let mut ghost_wallets = Vec::new();
    let mut parentless_wallets = Vec::new();
    for w in state.wallets.values().filter(|w| w.ghost) {
        ghost_wallets.push(w.wallet_id.clone());
        if w.region_id.is_empty() {
            parentless_wallets.push(w.wallet_id.clone());
        }
    }
    ghost_wallets.sort();
    parentless_wallets.sort();

    let mut ghost_tokens = Vec::new();
    let mut parentless_tokens = Vec::new();
    for t in state.tokens.values().filter(|t| t.ghost) {
        ghost_tokens.push(t.token_id.clone());
        if t.wallet_id.is_empty() {
            parentless_tokens.push(t.token_id.clone());
        }
    }
    ghost_tokens.sort();
    parentless_tokens.sort();

    let mut risk_flags = Vec::new();
    if !ghost_spaces.is_empty() {
        risk_flags.push("GHOST_SPACE_PRESENT".to_string());
    }
    if !parentless_regions.is_empty() {
        risk_flags.push("PARENTLESS_GHOST_REGION_UNDER_NETWORK".to_string());
    }
    if !parentless_wallets.is_empty() {
        risk_flags.push("PARENTLESS_GHOST_WALLET_UNDER_NETWORK".to_string());
    }
    if !parentless_tokens.is_empty() {
        risk_flags.push("UNPARENTED_GHOST_TOKEN_CUSTODY".to_string());
    }

    let total_ghost_entities =
        ghost_spaces.len() + ghost_regions.len() + ghost_wallets.len() + ghost_tokens.len();

    let commit_obj = serde_json::json!({
        "domain": "vnetwork/ghost-ledger-v1",
        "genesis_commitment": state.genesis_commitment,
        "ghost_regions": ghost_regions,
        "ghost_spaces": ghost_spaces,
        "ghost_tokens": ghost_tokens,
        "ghost_wallets": ghost_wallets,
        "network_id": state.network_id,
        "parentless_regions": parentless_regions,
        "parentless_tokens": parentless_tokens,
        "parentless_wallets": parentless_wallets,
    });
    let ghost_ledger_commitment = blake3_hex(&canonical_json_bytes(&commit_obj)?);

    Ok(GhostRiskAssessment {
        network_id: state.network_id.clone(),
        total_ghost_entities,
        ghost_spaces,
        ghost_regions,
        parentless_regions,
        ghost_wallets,
        parentless_wallets,
        ghost_tokens,
        parentless_tokens,
        risk_flags,
        ghost_ledger_commitment,
    })
}

pub fn list_ghost_entities(state: &NetworkLedgerState) -> serde_json::Value {
    let spaces: Vec<&SpaceEntity> = state.spaces.values().filter(|s| s.ghost).collect();
    let regions: Vec<&RegionEntity> = state.regions.values().filter(|r| r.ghost).collect();
    let wallets: Vec<&WalletEntity> = state.wallets.values().filter(|w| w.ghost).collect();
    let tokens: Vec<&TokenEntity> = state.tokens.values().filter(|t| t.ghost).collect();
    let assessment = inspect_ghost_entities(state).ok();
    serde_json::json!({
        "spaces": spaces,
        "regions": regions,
        "wallets": wallets,
        "tokens": tokens,
        "assessment": assessment,
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
