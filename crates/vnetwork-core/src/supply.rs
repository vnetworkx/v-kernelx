use crate::state::NetworkLedgerState;
use serde::{Deserialize, Serialize};
use vnetwork_types::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyConservationBreakdown {
    pub token_id: String,
    pub symbol: String,
    pub wallet_balances_total: u128,
    pub escrow_balances_total: u128,
    pub locked_collateral_total: u128,
    pub reserve_balances_total: u128,
    pub unknown_account_balances_total: u128,
    pub circulating_and_escrow_total: u128,
    pub recorded_total_supply: u128,
    pub burned_supply: u128,
    pub drained_fees_total: u128,
    pub burned_or_drained_total: u128,
    pub max_supply: u128,
    pub unlimited_supply: bool,
    pub verification_status: VerificationStatus,
    pub verification_reason: Option<String>,
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
    let mut locked_collateral_total: u128 = 0;
    let mut reserve_balances_total: u128 = 0;
    let mut unknown_account_balances_total: u128 = 0;

    for bal in state.balances.values() {
        if bal.token_id != token_id {
            continue;
        }
        if bal.wallet_id.starts_with("escrow::loan_") {
            locked_collateral_total = locked_collateral_total
                .checked_add(bal.vector.token)
                .ok_or_else(|| {
                    VNetworkError::Validation("locked collateral supply sum overflow".to_string())
                })?;
        } else if bal.wallet_id.starts_with("escrow::") {
            escrow_balances_total = escrow_balances_total
                .checked_add(bal.vector.token)
                .ok_or_else(|| {
                    VNetworkError::Validation("escrow supply sum overflow".to_string())
                })?;
        } else if bal.wallet_id.starts_with("reserve::") {
            reserve_balances_total = reserve_balances_total
                .checked_add(bal.vector.token)
                .ok_or_else(|| {
                    VNetworkError::Validation("reserve supply sum overflow".to_string())
                })?;
        } else if state.wallets.contains_key(&bal.wallet_id) {
            wallet_balances_total = wallet_balances_total
                .checked_add(bal.vector.token)
                .ok_or_else(|| {
                    VNetworkError::Validation("wallet supply sum overflow".to_string())
                })?;
        } else {
            unknown_account_balances_total = unknown_account_balances_total
                .checked_add(bal.vector.token)
                .ok_or_else(|| {
                    VNetworkError::Validation("unknown balance supply sum overflow".to_string())
                })?;
        }
    }

    let circulating_and_escrow_total = wallet_balances_total
        .checked_add(escrow_balances_total)
        .and_then(|v| v.checked_add(locked_collateral_total))
        .and_then(|v| v.checked_add(reserve_balances_total))
        .and_then(|v| v.checked_add(unknown_account_balances_total))
        .ok_or_else(|| VNetworkError::Validation("total supply sum overflow".to_string()))?;

    let mut burned_supply: u128 = 0;
    let mut drained_fees_total: u128 = 0;
    for ev in &state.events {
        if ev.payload.get("token_id").and_then(|v| v.as_str()) != Some(token_id) {
            continue;
        }
        match ev.operation.as_str() {
            "TOKEN_TRANSFER" => {
                if let Some(fee_str) = ev.payload.get("drain_fee").and_then(|v| v.as_str()) {
                    let fee: u128 = fee_str.parse().map_err(|e| {
                        VNetworkError::Validation(format!(
                            "invalid drain_fee `{fee_str}` in event `{}`: {e}",
                            ev.event_id
                        ))
                    })?;
                    drained_fees_total = drained_fees_total
                        .checked_add(fee)
                        .ok_or_else(|| VNetworkError::Validation("drained fees overflow".to_string()))?;
                }
            }
            "TOKEN_DRAIN" => {
                let amt_str = ev
                    .payload
                    .get("amount")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        VNetworkError::Validation(format!(
                            "missing amount in TOKEN_DRAIN event `{}`",
                            ev.event_id
                        ))
                    })?;
                let amt: u128 = amt_str.parse().map_err(|e| {
                    VNetworkError::Validation(format!(
                        "invalid amount `{amt_str}` in TOKEN_DRAIN event `{}`: {e}",
                        ev.event_id
                    ))
                })?;
                drained_fees_total = drained_fees_total
                    .checked_add(amt)
                    .ok_or_else(|| VNetworkError::Validation("drained fees overflow".to_string()))?;
            }
            "TOKEN_BURN" => {
                let amt_str = ev
                    .payload
                    .get("amount")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        VNetworkError::Validation(format!(
                            "missing amount in TOKEN_BURN event `{}`",
                            ev.event_id
                        ))
                    })?;
                let amt: u128 = amt_str.parse().map_err(|e| {
                    VNetworkError::Validation(format!(
                        "invalid amount `{amt_str}` in TOKEN_BURN event `{}`: {e}",
                        ev.event_id
                    ))
                })?;
                burned_supply = burned_supply
                    .checked_add(amt)
                    .ok_or_else(|| VNetworkError::Validation("burned supply overflow".to_string()))?;
            }
            _ => {}
        }
    }

    let burned_or_drained_total = burned_supply
        .checked_add(drained_fees_total)
        .ok_or_else(|| VNetworkError::Validation("burned_or_drained_total overflow".to_string()))?;

    let supply_reduction = token.initial_vector.token.checked_sub(token.total_supply);
    let cap_ok = token.unlimited_supply || token.total_supply <= token.max_supply;

    let (verification_status, verification_reason) = if circulating_and_escrow_total
        != token.total_supply
    {
        (
            VerificationStatus::Invalid,
            Some(format!(
                "account balances sum ({circulating_and_escrow_total}) != recorded total_supply ({})",
                token.total_supply
            )),
        )
    } else if !cap_ok {
        (
            VerificationStatus::Invalid,
            Some(format!(
                "recorded total_supply ({}) exceeds max_supply ({})",
                token.total_supply, token.max_supply
            )),
        )
    } else if supply_reduction != Some(burned_or_drained_total) {
        (
            VerificationStatus::Invalid,
            Some(format!(
                "supply delta from initial ({}) does not match burned ({burned_supply}) + drained ({drained_fees_total})",
                token.initial_vector.token
            )),
        )
    } else if unknown_account_balances_total > 0 {
        (
            VerificationStatus::Unverified,
            Some(format!(
                "unknown or unsupported account categories hold {unknown_account_balances_total} units"
            )),
        )
    } else {
        (VerificationStatus::Verified, None)
    };

    let conserved = verification_status == VerificationStatus::Verified;

    Ok(SupplyConservationBreakdown {
        token_id: token.token_id.clone(),
        symbol: token.symbol.clone(),
        wallet_balances_total,
        escrow_balances_total,
        locked_collateral_total,
        reserve_balances_total,
        unknown_account_balances_total,
        circulating_and_escrow_total,
        recorded_total_supply: token.total_supply,
        burned_supply,
        drained_fees_total,
        burned_or_drained_total,
        max_supply: token.max_supply,
        unlimited_supply: token.unlimited_supply,
        verification_status,
        verification_reason,
        conserved,
    })
}

pub fn verify_token_supply_conservation(
    state: &NetworkLedgerState,
    token_id: &str,
) -> VResult<bool> {
    Ok(compute_token_supply_breakdown(state, token_id)?.conserved)
}
