use crate::state::NetworkLedgerState;
use vnetwork_types::*;

pub fn verify_token_supply_conservation(
    state: &NetworkLedgerState,
    token_id: &str,
) -> VResult<bool> {
    let token = state
        .tokens
        .get(token_id)
        .ok_or_else(|| VNetworkError::NotFound(format!("token `{token_id}`")))?;
    let mut sum: u128 = 0;
    for bal in state.balances.values() {
        if bal.token_id == token_id {
            sum = sum
                .checked_add(bal.vector.token)
                .ok_or_else(|| VNetworkError::Validation("supply sum overflow".to_string()))?;
        }
    }
    Ok(sum == token.total_supply && token.total_supply <= token.max_supply)
}
