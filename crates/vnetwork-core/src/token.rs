use crate::drain::calculate_drain_fee;
use crate::hierarchy::{verify_token_exists, verify_wallet_exists};
use crate::identity::require_participant_scope;
use crate::state::NetworkLedgerState;
use crate::supply::verify_token_supply_conservation;
use vnetwork_types::*;

#[allow(clippy::too_many_arguments)]
pub fn apply_create_token(
    state: &mut NetworkLedgerState,
    wallet_ref: &str,
    name: &str,
    symbol: &str,
    dimensions: usize,
    initial_vector: TokenVector,
    max_supply: u128,
    drain_bps: u16,
    purpose: &str,
    external_monetary_value: &str,
    ghost: bool,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(TokenEntity, LedgerEvent)> {
    require_participant_scope(state, actor_pubkey, ParticipationLevel::Token)?;

    if dimensions != TOKEN_VECTOR_DIMENSIONS {
        return Err(VNetworkError::DimensionInvariant(format!(
            "token dimensions must be exactly 3 [token, authratio(au), energy], got {dimensions}"
        )));
    }
    if drain_bps > 10_000 {
        return Err(VNetworkError::Validation("drain_bps must be <= 10000".to_string()));
    }

    let wallet = verify_wallet_exists(state, wallet_ref)?.clone();
    if !wallet.is_authorized_signer(actor_pubkey) {
        return Err(VNetworkError::Authorization(format!(
            "actor `{actor_pubkey}` cannot authorize creation in wallet `{}`",
            wallet.name
        )));
    }

    let clean_name = name.trim();
    let clean_symbol = symbol.trim().to_ascii_uppercase();
    if clean_name.is_empty() || clean_symbol.is_empty() {
        return Err(VNetworkError::Validation(
            "token name and symbol are required".to_string(),
        ));
    }

    let eff_max = max_supply.max(initial_vector.token);
    if initial_vector.token > eff_max {
        return Err(VNetworkError::Validation(
            "initial token supply exceeds max_supply".to_string(),
        ));
    }

    let token_id = derive_token_id(&wallet.wallet_id, &clean_symbol);
    if state.tokens.contains_key(&token_id)
        || state
            .tokens
            .values()
            .any(|t| t.symbol.eq_ignore_ascii_case(&clean_symbol))
    {
        return Err(VNetworkError::AlreadyExists(format!(
            "token symbol `{clean_symbol}` already exists"
        )));
    }

    let token = TokenEntity {
        token_id: token_id.clone(),
        name: clean_name.to_string(),
        symbol: clean_symbol,
        wallet_id: wallet.wallet_id.clone(),
        region_id: wallet.region_id.clone(),
        space_id: wallet.space_id.clone(),
        ghost,
        dimensions: TOKEN_VECTOR_DIMENSIONS,
        initial_vector,
        total_supply: initial_vector.token,
        max_supply: eff_max,
        drain_bps,
        purpose: purpose.trim().to_string(),
        external_monetary_value: external_monetary_value.trim().to_string(),
        authority_pubkey: actor_pubkey.to_string(),
        created_at_ms: timestamp_ms,
        version: 1,
    };

    let bal_key = NetworkLedgerState::balance_key(&token_id, &wallet.wallet_id);
    let balance = TokenBalanceRecord {
        token_id: token_id.clone(),
        wallet_id: wallet.wallet_id.clone(),
        vector: initial_vector,
        updated_at_ms: timestamp_ms,
        version: 1,
    };

    state.tokens.insert(token_id.clone(), token.clone());
    state.balances.insert(bal_key, balance);

    state.logical_clock += 1;
    let sequence = (state.events.len() as u64) + 1;
    let parents = state.latest_event_hash().into_iter().collect();
    let after_hash = blake3_hex(&canonical_json_bytes(&token)?);
    let event = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "token",
        &token_id,
        if ghost { "GHOST_TOKEN_CREATE" } else { "TOKEN_CREATE" },
        actor_pubkey,
        state.logical_clock,
        timestamp_ms,
        serde_json::to_value(&token).unwrap_or_default(),
        "",
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((token, event))
}

#[allow(clippy::too_many_arguments)]
pub fn apply_transfer_token(
    state: &mut NetworkLedgerState,
    token_ref: &str,
    from_wallet_ref: &str,
    to_wallet_ref: &str,
    amount: u128,
    override_drain_bps: Option<u16>,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(TokenBalanceRecord, TokenBalanceRecord, u128, LedgerEvent)> {
    if amount == 0 {
        return Err(VNetworkError::Validation(
            "transfer amount must be positive".to_string(),
        ));
    }

    let token = verify_token_exists(state, token_ref)?.clone();
    let from_wallet = verify_wallet_exists(state, from_wallet_ref)?.clone();
    let to_wallet = verify_wallet_exists(state, to_wallet_ref)?.clone();

    if from_wallet.wallet_id == to_wallet.wallet_id {
        return Err(VNetworkError::Validation(
            "source and destination wallets must differ".to_string(),
        ));
    }

    if !from_wallet.is_authorized_signer(actor_pubkey) {
        return Err(VNetworkError::Authorization(format!(
            "actor `{actor_pubkey}` is not an authorized signer for source wallet `{}`",
            from_wallet.name
        )));
    }

    let from_key = NetworkLedgerState::balance_key(&token.token_id, &from_wallet.wallet_id);
    let to_key = NetworkLedgerState::balance_key(&token.token_id, &to_wallet.wallet_id);

    let before_from = state
        .balances
        .get(&from_key)
        .cloned()
        .ok_or_else(|| VNetworkError::InsufficientBalance("source wallet holds 0 balance".to_string()))?;

    let before_to = state.balances.get(&to_key).cloned().unwrap_or(TokenBalanceRecord {
        token_id: token.token_id.clone(),
        wallet_id: to_wallet.wallet_id.clone(),
        vector: TokenVector::new(0, 1000, 0),
        updated_at_ms: timestamp_ms,
        version: 0,
    });

    if before_from.vector.token < amount {
        return Err(VNetworkError::InsufficientBalance(format!(
            "wallet `{}` has {} {}, requested {}",
            from_wallet.name, before_from.vector.token, token.symbol, amount
        )));
    }

    let drain_bps = override_drain_bps.unwrap_or(token.drain_bps);
    let (drain_fee, net_received) = if drain_bps > 0 {
        calculate_drain_fee(amount, drain_bps)?
    } else {
        (0, amount)
    };

    // Token-only dimension rule: ONLY dimension 0 (`token`) changes.
    // AuthRatio (dim 1) and Energy (dim 2) remain strictly untouched.
    let mut after_from = before_from.clone();
    after_from.vector.token -= amount;
    after_from.updated_at_ms = timestamp_ms;
    after_from.version += 1;

    let mut after_to = before_to.clone();
    after_to.vector.token = after_to
        .vector
        .token
        .checked_add(net_received)
        .ok_or_else(|| VNetworkError::Validation("recipient balance overflow".to_string()))?;
    after_to.updated_at_ms = timestamp_ms;
    after_to.version += 1;

    TokenVector::verify_transfer_invariant(
        &before_from.vector,
        &after_from.vector,
        &before_to.vector,
        &after_to.vector,
    )?;

    let before_hash = blake3_hex(&canonical_json_bytes(&(&before_from, &before_to))?);

    state.balances.insert(from_key, after_from.clone());
    state.balances.insert(to_key, after_to.clone());

    if drain_fee > 0 {
        let mut t = token.clone();
        t.total_supply = t.total_supply.saturating_sub(drain_fee);
        t.version += 1;
        state.tokens.insert(t.token_id.clone(), t);
    }

    if !verify_token_supply_conservation(state, &token.token_id)? {
        return Err(VNetworkError::Validation(
            "token supply conservation check failed".to_string(),
        ));
    }

    let after_hash = blake3_hex(&canonical_json_bytes(&(&after_from, &after_to))?);

    state.logical_clock += 1;
    let sequence = (state.events.len() as u64) + 1;
    let parents = state.latest_event_hash().into_iter().collect();
    let event = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "token_transfer",
        &token.token_id,
        "TOKEN_TRANSFER",
        actor_pubkey,
        state.logical_clock,
        timestamp_ms,
        serde_json::json!({
            "token_id": token.token_id,
            "symbol": token.symbol,
            "from_wallet_id": from_wallet.wallet_id,
            "to_wallet_id": to_wallet.wallet_id,
            "amount": amount.to_string(),
            "drain_fee": drain_fee.to_string(),
            "net_received": net_received.to_string(),
            "from_vector_after": after_from.vector.as_array(),
            "to_vector_after": after_to.vector.as_array(),
        }),
        before_hash,
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((after_from, after_to, drain_fee, event))
}

pub fn apply_drain_token(
    state: &mut NetworkLedgerState,
    token_ref: &str,
    wallet_ref: &str,
    amount: u128,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(TokenBalanceRecord, LedgerEvent)> {
    if amount == 0 {
        return Err(VNetworkError::Validation("drain amount must be positive".to_string()));
    }
    let token = verify_token_exists(state, token_ref)?.clone();
    let wallet = verify_wallet_exists(state, wallet_ref)?.clone();
    if !wallet.is_authorized_signer(actor_pubkey) {
        return Err(VNetworkError::Authorization(
            "actor not authorized to drain wallet".to_string(),
        ));
    }
    let key = NetworkLedgerState::balance_key(&token.token_id, &wallet.wallet_id);
    let before = state
        .balances
        .get(&key)
        .cloned()
        .ok_or_else(|| VNetworkError::InsufficientBalance("wallet balance not found".to_string()))?;
    if before.vector.token < amount {
        return Err(VNetworkError::InsufficientBalance(
            "drain exceeds wallet token balance".to_string(),
        ));
    }
    let before_hash = blake3_hex(&canonical_json_bytes(&before)?);
    let mut after = before;
    after.vector.token -= amount;
    after.updated_at_ms = timestamp_ms;
    after.version += 1;
    state.balances.insert(key, after.clone());

    let mut t = token;
    t.total_supply = t.total_supply.saturating_sub(amount);
    t.version += 1;
    state.tokens.insert(t.token_id.clone(), t.clone());

    state.logical_clock += 1;
    let sequence = (state.events.len() as u64) + 1;
    let parents = state.latest_event_hash().into_iter().collect();
    let after_hash = blake3_hex(&canonical_json_bytes(&after)?);
    let event = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "token_drain",
        &t.token_id,
        "TOKEN_DRAIN",
        actor_pubkey,
        state.logical_clock,
        timestamp_ms,
        serde_json::json!({
            "token_id": t.token_id,
            "wallet_id": wallet.wallet_id,
            "amount": amount.to_string(),
            "vector_after": after.vector.as_array(),
        }),
        before_hash,
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((after, event))
}
