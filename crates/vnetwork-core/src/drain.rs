use vnetwork_types::*;

pub fn calculate_drain_fee(amount: u128, drain_bps: u16) -> VResult<(u128, u128)> {
    if drain_bps > 10_000 {
        return Err(VNetworkError::Validation(
            "drain_bps cannot exceed 10000".to_string(),
        ));
    }
    if amount == 0 {
        return Err(VNetworkError::Validation(
            "amount must be positive".to_string(),
        ));
    }
    let fee = amount
        .checked_mul(drain_bps as u128)
        .ok_or_else(|| VNetworkError::Validation("drain fee overflow".to_string()))?
        / 10_000;
    let net = amount
        .checked_sub(fee)
        .ok_or_else(|| VNetworkError::Validation("drain net underflow".to_string()))?;
    Ok((fee, net))
}
