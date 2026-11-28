use crate::state::NetworkLedgerState;
use vnetwork_types::*;

pub fn verify_space_exists<'a>(
    state: &'a NetworkLedgerState,
    space_id_or_name: &str,
) -> VResult<&'a SpaceEntity> {
    state
        .spaces
        .get(space_id_or_name)
        .or_else(|| {
            state
                .spaces
                .values()
                .find(|s| s.name.eq_ignore_ascii_case(space_id_or_name))
        })
        .ok_or_else(|| {
            VNetworkError::Hierarchy(format!("parent Space `{space_id_or_name}` does not exist"))
        })
}

pub fn verify_region_exists<'a>(
    state: &'a NetworkLedgerState,
    region_id_or_name: &str,
) -> VResult<&'a RegionEntity> {
    state
        .regions
        .get(region_id_or_name)
        .or_else(|| {
            state.regions.values().find(|r| {
                r.name.eq_ignore_ascii_case(region_id_or_name)
                    || r.prefix
                        .as_ref()
                        .is_some_and(|p| p.eq_ignore_ascii_case(region_id_or_name))
            })
        })
        .ok_or_else(|| {
            VNetworkError::Hierarchy(format!(
                "parent Region `{region_id_or_name}` does not exist"
            ))
        })
}

pub fn verify_wallet_exists<'a>(
    state: &'a NetworkLedgerState,
    wallet_id_or_name: &str,
) -> VResult<&'a WalletEntity> {
    state
        .wallets
        .get(wallet_id_or_name)
        .or_else(|| {
            state
                .wallets
                .values()
                .find(|w| w.name.eq_ignore_ascii_case(wallet_id_or_name))
        })
        .ok_or_else(|| {
            VNetworkError::Hierarchy(format!(
                "parent Wallet `{wallet_id_or_name}` does not exist"
            ))
        })
}

pub fn verify_token_exists<'a>(
    state: &'a NetworkLedgerState,
    token_id_or_symbol: &str,
) -> VResult<&'a TokenEntity> {
    state
        .tokens
        .get(token_id_or_symbol)
        .or_else(|| {
            state.tokens.values().find(|t| {
                t.symbol.eq_ignore_ascii_case(token_id_or_symbol)
                    || t.name.eq_ignore_ascii_case(token_id_or_symbol)
            })
        })
        .ok_or_else(|| {
            VNetworkError::NotFound(format!("Token `{token_id_or_symbol}` does not exist"))
        })
}
