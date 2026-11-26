use crate::events::verify_event_chain;
use crate::state::NetworkLedgerState;
use crate::supply::{compute_token_supply_breakdown, SupplyConservationBreakdown};
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
    pub wallet_balances_total: u128,
    pub escrow_balances_total: u128,
    pub burned_or_drained_total: u128,
    pub conserved: bool,
}

impl From<SupplyConservationBreakdown> for TokenConservationSummary {
    fn from(b: SupplyConservationBreakdown) -> Self {
        Self {
            token_id: b.token_id,
            symbol: b.symbol,
            total_supply: b.recorded_total_supply,
            max_supply: b.max_supply,
            wallet_balances_total: b.wallet_balances_total,
            escrow_balances_total: b.escrow_balances_total,
            burned_or_drained_total: b.burned_or_drained_total,
            conserved: b.conserved,
        }
    }
}

pub fn build_ledger_proof_report(state: &NetworkLedgerState) -> VResult<LedgerProofReport> {
    let chain_valid = verify_event_chain(&state.events)?;
    let state_root = state.compute_state_root()?;
    let replay_hash = state.compute_replay_hash();
    let mut token_conservation = Vec::new();
    for token in state.tokens.values() {
        let breakdown = compute_token_supply_breakdown(state, &token.token_id)?;
        token_conservation.push(breakdown.into());
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
