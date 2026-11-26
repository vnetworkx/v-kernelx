use crate::state::NetworkLedgerState;
use serde::{Deserialize, Serialize};
use vnetwork_types::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyConservationBreakdown {
    pub token_id: String,
    pub symbol: String,
    pub wallet_balances_total: u128,
    pub escrow_balances_total: u128,
    pub unknown_account_balances_total: u128,
    pub circulating_and_escrow_total: u128,
    pub recorded_total_supply: u128,
    pub burned_or_drained_total: u128,
    pub max_supply: u128,
    pub unlimited_supply: bool,
    pub conserved: bool,
}

pub fn compute_token_supply_breakdown(
    state: &NetworkLedgerState,
    token_id: &str,
) -> VResult<SupplyConservationBreakdown> {
    let token = state
        .tokens
        .get(token_id)
        .ok_or_else(|| VNetworkError::NotFound(format!("token `{token_id}`")))?;

    let mut wallet_balances_total: u128 = 0;
    let mut escrow_balances_total: u128 = 0;
    let mut unknown_account_balances_total: u128 = 0;

    for bal in state.balances.values() {
        if bal.token_id != token_id {
            continue;
        }
        if bal.wallet_id.starts_with("escrow::") {
            escrow_balances_total = escrow_balances_total
                .checked_add(bal.vector.token)
                .ok_or_else(|| VNetworkError::Validation("escrow supply sum overflow".to_string()))?;
        } else if state.wallets.contains_key(&bal.wallet_id) {
            wallet_balances_total = wallet_balances_total
                .checked_add(bal.vector.token)
                .ok_or_else(|| VNetworkError::Validation("wallet supply sum overflow".to_string()))?;
        } else {
            unknown_account_balances_total = unknown_account_balances_total
                .checked_add(bal.vector.token)
                .ok_or_else(|| VNetworkError::Validation("unknown balance supply sum overflow".to_string()))?;
        }
    }

    let circulating_and_escrow_total = wallet_balances_total
        .checked_add(escrow_balances_total)
        .and_then(|v| v.checked_add(unknown_account_balances_total))
        .ok_or_else(|| VNetworkError::Validation("total supply sum overflow".to_string()))?;

    let burned_or_drained_total = token
        .initial_vector
        .token
        .saturating_sub(token.total_supply);
    let cap_ok = token.unlimited_supply || token.total_supply <= token.max_supply;
    let conserved = circulating_and_escrow_total == token.total_supply
        && unknown_account_balances_total == 0
        && cap_ok;

    Ok(SupplyConservationBreakdown {
        token_id: token.token_id.clone(),
        symbol: token.symbol.clone(),
        wallet_balances_total,
        escrow_balances_total,
        unknown_account_balances_total,
        circulating_and_escrow_total,
        recorded_total_supply: token.total_supply,
        burned_or_drained_total,
        max_supply: token.max_supply,
        unlimited_supply: token.unlimited_supply,
        conserved,
    })
}

pub fn verify_token_supply_conservation(
    state: &NetworkLedgerState,
    token_id: &str,
) -> VResult<bool> {
    Ok(compute_token_supply_breakdown(state, token_id)?.conserved)
}
