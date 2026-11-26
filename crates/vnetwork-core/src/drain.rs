use vnetwork_types::*;

pub fn derive_transfer_scope(
    from_wallet: &WalletEntity,
    to_wallet: &WalletEntity,
) -> TransferScope {
    if from_wallet.wallet_id == to_wallet.wallet_id {
        TransferScope::SameWallet
    } else if !from_wallet.region_id.is_empty() && from_wallet.region_id == to_wallet.region_id {
        TransferScope::DifferentWalletsSameRegion
    } else if !from_wallet.space_id.is_empty() && from_wallet.space_id == to_wallet.space_id {
        TransferScope::DifferentRegionsSameSpace
    } else {
        TransferScope::DifferentSpaces
    }
}

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

pub fn compute_scope_drain(
    policy: &DrainPolicy,
    from_wallet: &WalletEntity,
    to_wallet: &WalletEntity,
    amount: u128,
) -> VResult<(TransferScope, u16, u128, u128)> {
    let scope = derive_transfer_scope(from_wallet, to_wallet);
    let (bps, fee, net) = policy.compute_drain(scope, amount)?;
    Ok((scope, bps, fee, net))
}
