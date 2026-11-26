use crate::events::verify_event_chain;
use crate::state::NetworkLedgerState;
use crate::supply::verify_token_supply_conservation;
use serde::{Deserialize, Serialize};
use vnetwork_types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerProofReport {
    pub network_id: String,
    pub height: u64,
    pub logical_clock: u64,
    pub event_count: usize,
    pub chain_valid: bool,
    pub state_root: String,
    pub replay_hash: String,
    pub certificate_count: usize,
    pub token_conservation: Vec<TokenConservationSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConservationSummary {
    pub token_id: String,
    pub symbol: String,
    pub total_supply: u128,
    pub max_supply: u128,
    pub conserved: bool,
}

pub fn build_ledger_proof_report(state: &NetworkLedgerState) -> VResult<LedgerProofReport> {
    let chain_valid = verify_event_chain(&state.events)?;
    let state_root = state.compute_state_root()?;
    let replay_hash = state.compute_replay_hash();
    let mut token_conservation = Vec::new();
    for token in state.tokens.values() {
        let conserved = verify_token_supply_conservation(state, &token.token_id)?;
        token_conservation.push(TokenConservationSummary {
            token_id: token.token_id.clone(),
            symbol: token.symbol.clone(),
            total_supply: token.total_supply,
            max_supply: token.max_supply,
            conserved,
        });
    }
    Ok(LedgerProofReport {
        network_id: state.network_id.clone(),
        height: state.height,
        logical_clock: state.logical_clock,
        event_count: state.events.len(),
        chain_valid,
        state_root,
        replay_hash,
        certificate_count: state.certificates.len(),
        token_conservation,
    })
}
