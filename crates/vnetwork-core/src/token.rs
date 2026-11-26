use crate::drain::compute_scope_drain;
use crate::hierarchy::{verify_token_exists, verify_wallet_exists};
use crate::identity::require_participant_scope_at;
use crate::state::NetworkLedgerState;
use crate::supply::verify_token_supply_conservation;
use std::collections::BTreeSet;
use vnetwork_types::*;

pub fn canonical_transfer_approval_bytes(
    network_id: &str,
    protocol_version: &str,
    token_id: &str,
    from_wallet_id: &str,
    to_wallet_id: &str,
    amount: u128,
) -> VResult<Vec<u8>> {
    let obj = serde_json::json!({
        "amount": amount.to_string(),
        "domain": DOM_TRANSFER_APPROVAL_V1,
        "from_wallet_id": from_wallet_id,
        "network_id": network_id,
        "protocol_version": protocol_version,
        "to_wallet_id": to_wallet_id,
        "token_id": token_id,
    });
    canonical_json_bytes(&obj)
}

#[allow(clippy::too_many_arguments)]
pub fn apply_create_token(
    state: &mut NetworkLedgerState,
    wallet_ref: &str,
    name: &str,
    symbol: &str,
    dimensions: usize,
    initial_vector: TokenVector,
    max_supply: u128,
    unlimited_supply: bool,
    drain_bps: u16,
    purpose: &str,
    external_monetary_value: &str,
    ghost: bool,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(TokenEntity, LedgerEvent)> {
    if dimensions != TOKEN_VECTOR_DIMENSIONS {
        return Err(VNetworkError::DimensionInvariant(format!(
            "token dimensions must be exactly 3 [token, authratio(au), energy], got {dimensions}"
        )));
    }
    if drain_bps > 10_000 {
        return Err(VNetworkError::Validation("drain_bps must be <= 10000".to_string()));
    }

    let clean_name = name.trim();
    let clean_symbol = symbol.trim().to_ascii_uppercase();
    if clean_name.is_empty() || clean_symbol.is_empty() {
        return Err(VNetworkError::Validation(
            "token name and symbol are required".to_string(),
        ));
    }

    if !unlimited_supply {
        if max_supply == 0 {
            return Err(VNetworkError::Validation(
                "max_supply must be > 0 unless unlimited_supply is explicitly true".to_string(),
            ));
        }
        if initial_vector.token > max_supply {
            return Err(VNetworkError::Validation(format!(
                "initial token supply {} exceeds max_supply {}",
                initial_vector.token, max_supply
            )));
        }
    }

    let (token_id, wallet_id, region_id, space_id, bal_wallet_id) = if ghost
        && wallet_ref.trim().is_empty()
    {
        require_participant_scope_at(
            state,
            actor_pubkey,
            ParticipationLevel::Network,
            None,
            timestamp_ms,
        )?;
        let tid = derive_token_id("__network_ghost__", &clean_symbol);
        let custody_id = format!("ghost_custody::{tid}");
        (tid, String::new(), String::new(), String::new(), custody_id)
    } else {
        let wallet = verify_wallet_exists(state, wallet_ref)?.clone();
        wallet.verify_permission(
            actor_pubkey,
            WalletPermission::ManageKeys,
            None,
            None,
            timestamp_ms,
        )?;

        let has_token_scope = require_participant_scope_at(
            state,
            actor_pubkey,
            ParticipationLevel::Token,
            Some(&wallet.wallet_id),
            timestamp_ms,
        )
        .is_ok();
        let is_authorized_wallet_owner = wallet.owner_pubkey == actor_pubkey
            && (require_participant_scope_at(
                state,
                actor_pubkey,
                ParticipationLevel::Wallet,
                Some(&wallet.region_id),
                timestamp_ms,
            )
            .is_ok()
                || state
                    .regions
                    .get(&wallet.region_id)
                    .map_or(false, |r| r.creator_pubkey == actor_pubkey)
                || (wallet.ghost
                    && wallet.region_id.is_empty()
                    && require_participant_scope_at(
                        state,
                        actor_pubkey,
                        ParticipationLevel::Network,
                        None,
                        timestamp_ms,
                    )
                    .is_ok()));
        if !has_token_scope && !is_authorized_wallet_owner {
            return Err(VNetworkError::Authorization(format!(
                "actor `{actor_pubkey}` lacks TOKEN scope or authorized ownership of wallet `{}`",
                wallet.name
            )));
        }
        let tid = derive_token_id(&wallet.wallet_id, &clean_symbol);
        (
            tid,
            wallet.wallet_id.clone(),
            wallet.region_id.clone(),
            wallet.space_id.clone(),
            wallet.wallet_id,
        )
    };

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
        wallet_id,
        region_id,
        space_id,
        ghost,
        dimensions: TOKEN_VECTOR_DIMENSIONS,
        schema_version: TOKEN_SCHEMA_VERSION,
        initial_vector,
        total_supply: initial_vector.token,
        max_supply,
        unlimited_supply,
        drain_bps,
        purpose: purpose.trim().to_string(),
        external_monetary_value: external_monetary_value.trim().to_string(),
        authority_pubkey: actor_pubkey.to_string(),
        created_at_ms: timestamp_ms,
        version: 1,
    };

    let bal_key = NetworkLedgerState::balance_key(&token_id, &bal_wallet_id);
    let balance = TokenBalanceRecord {
        token_id: token_id.clone(),
        wallet_id: bal_wallet_id,
        vector: initial_vector,
        updated_at_ms: timestamp_ms,
        version: 1,
    };

    state.tokens.insert(token_id.clone(), token.clone());
    state.balances.insert(bal_key, balance);

    state.logical_clock = state
        .logical_clock
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
    let sequence = (state.events.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
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
        serde_json::to_value(&token).map_err(|e| VNetworkError::Serialization(e.to_string()))?,
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
    cosignatures: &[(String, String)],
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(TokenBalanceRecord, TokenBalanceRecord, u128, LedgerEvent)> {
    execute_transfer_internal(
        state,
        token_ref,
        from_wallet_ref,
        to_wallet_ref,
        amount,
        cosignatures,
        actor_pubkey,
        timestamp_ms,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_protocol_settlement_transfer(
    state: &mut NetworkLedgerState,
    token_ref: &str,
    from_wallet_ref: &str,
    to_wallet_ref: &str,
    amount: u128,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(TokenBalanceRecord, TokenBalanceRecord, u128, LedgerEvent)> {
    execute_transfer_internal(
        state,
        token_ref,
        from_wallet_ref,
        to_wallet_ref,
        amount,
        &[],
        actor_pubkey,
        timestamp_ms,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_transfer_internal(
    state: &mut NetworkLedgerState,
    token_ref: &str,
    from_wallet_ref: &str,
    to_wallet_ref: &str,
    amount: u128,
    cosignatures: &[(String, String)],
    actor_pubkey: &str,
    timestamp_ms: u64,
    is_protocol_settlement: bool,
) -> VResult<(TokenBalanceRecord, TokenBalanceRecord, u128, LedgerEvent)> {
    if amount == 0 {
        return Err(VNetworkError::Validation(
            "transfer amount must be positive".to_string(),
        ));
    }

    let token = verify_token_exists(state, token_ref)?.clone();
    let from_wallet = verify_wallet_exists(state, from_wallet_ref)?.clone();
    let to_wallet = verify_wallet_exists(state, to_wallet_ref)?.clone();

    let same_wallet = from_wallet.wallet_id == to_wallet.wallet_id;

    // 1. Source permission check
    if is_protocol_settlement {
        from_wallet.verify_permission(
            actor_pubkey,
            WalletPermission::LoanInteract,
            Some(&token.token_id),
            Some(amount),
            timestamp_ms,
        )?;
    } else {
        from_wallet.verify_permission(
            actor_pubkey,
            WalletPermission::Send,
            Some(&token.token_id),
            Some(amount),
            timestamp_ms,
        )?;
        if same_wallet {
            from_wallet.verify_permission(
                actor_pubkey,
                WalletPermission::Receive,
                Some(&token.token_id),
                Some(amount),
                timestamp_ms,
            )?;
        }
    }

    // 2. Multisig verification when required on source wallet
    let mut verified_cosigner_pks: Vec<String> = Vec::new();
    if from_wallet.approval_threshold > 1 && !is_protocol_settlement {
        let approval_bytes = canonical_transfer_approval_bytes(
            &state.network_id,
            &state.protocol_version,
            &token.token_id,
            &from_wallet.wallet_id,
            &to_wallet.wallet_id,
            amount,
        )?;
        let mut approvers = BTreeSet::new();
        approvers.insert(actor_pubkey.to_string());
        for (signer_pk, sig_hex) in cosignatures {
            from_wallet.verify_permission(
                signer_pk,
                WalletPermission::Send,
                Some(&token.token_id),
                Some(amount),
                timestamp_ms,
            )?;
            verify_ed25519(signer_pk, &approval_bytes, sig_hex)?;
            if approvers.insert(signer_pk.clone()) {
                verified_cosigner_pks.push(signer_pk.clone());
            }
        }
        if approvers.len() < from_wallet.approval_threshold as usize {
            return Err(VNetworkError::Authorization(format!(
                "insufficient wallet multisignature approvals: got {}, required {}",
                approvers.len(),
                from_wallet.approval_threshold
            )));
        }
    }

    // 3. Destination receive policy verification (both-side wallet authorization)
    let cosigner_refs: Vec<&str> = verified_cosigner_pks.iter().map(String::as_str).collect();
    to_wallet.verify_receive_allowed(&from_wallet.wallet_id, actor_pubkey, &cosigner_refs)?;

    // 4. Derive transfer scope strictly from verified ledger hierarchy and compute integer drain
    let (scope, drain_bps, drain_fee, net_received) = if is_protocol_settlement {
        let s = crate::drain::derive_transfer_scope(&from_wallet, &to_wallet);
        (s, 0u16, 0u128, amount)
    } else {
        compute_scope_drain(&state.drain_policy, &from_wallet, &to_wallet, amount)?
    };

    let from_key = NetworkLedgerState::balance_key(&token.token_id, &from_wallet.wallet_id);
    let to_key = NetworkLedgerState::balance_key(&token.token_id, &to_wallet.wallet_id);

    let before_from = state
        .balances
        .get(&from_key)
        .cloned()
        .ok_or_else(|| {
            VNetworkError::InsufficientBalance("source wallet holds 0 balance".to_string())
        })?;

    if before_from.vector.token < amount {
        return Err(VNetworkError::InsufficientBalance(format!(
            "wallet `{}` has {} {}, requested {}",
            from_wallet.name, before_from.vector.token, token.symbol, amount
        )));
    }

    let (before_to, after_from, after_to, before_hash, after_hash) = if same_wallet {
        let before_to = before_from.clone();
        let after_vec = before_from
            .vector
            .checked_sub_token(amount)?
            .checked_add_token(net_received)?;
        let mut after_single = before_from.clone();
        after_single.vector = after_vec;
        after_single.updated_at_ms = timestamp_ms;
        after_single.version = after_single
            .version
            .checked_add(1)
            .ok_or_else(|| VNetworkError::Validation("balance version overflow".to_string()))?;
        TokenVector::verify_transfer_invariant(
            &before_from.vector,
            &after_single.vector,
            &before_to.vector,
            &after_single.vector,
        )?;
        let b_hash = blake3_hex(&canonical_json_bytes(&(&before_from, &before_to))?);
        state.balances.insert(from_key, after_single.clone());
        let a_hash = blake3_hex(&canonical_json_bytes(&(&after_single, &after_single))?);
        (before_to, after_single.clone(), after_single, b_hash, a_hash)
    } else {
        let before_to = state
            .balances
            .get(&to_key)
            .cloned()
            .unwrap_or(TokenBalanceRecord {
                token_id: token.token_id.clone(),
                wallet_id: to_wallet.wallet_id.clone(),
                vector: TokenVector::zero(),
                updated_at_ms: timestamp_ms,
                version: 0,
            });
        let mut after_from = before_from.clone();
        after_from.vector = before_from.vector.checked_sub_token(amount)?;
        after_from.updated_at_ms = timestamp_ms;
        after_from.version = after_from
            .version
            .checked_add(1)
            .ok_or_else(|| VNetworkError::Validation("balance version overflow".to_string()))?;

        let mut after_to = before_to.clone();
        after_to.vector = before_to.vector.checked_add_token(net_received)?;
        after_to.updated_at_ms = timestamp_ms;
        after_to.version = after_to
            .version
            .checked_add(1)
            .ok_or_else(|| VNetworkError::Validation("balance version overflow".to_string()))?;

        TokenVector::verify_transfer_invariant(
            &before_from.vector,
            &after_from.vector,
            &before_to.vector,
            &after_to.vector,
        )?;
        let b_hash = blake3_hex(&canonical_json_bytes(&(&before_from, &before_to))?);
        state.balances.insert(from_key, after_from.clone());
        state.balances.insert(to_key, after_to.clone());
        let a_hash = blake3_hex(&canonical_json_bytes(&(&after_from, &after_to))?);
        (before_to, after_from, after_to, b_hash, a_hash)
    };
    let _ = before_to;

    if drain_fee > 0 {
        let mut t = token.clone();
        t.total_supply = t
            .total_supply
            .checked_sub(drain_fee)
            .ok_or_else(|| {
                VNetworkError::Validation(
                    "token total_supply underflow on drain fee".to_string(),
                )
            })?;
        t.version = t
            .version
            .checked_add(1)
            .ok_or_else(|| VNetworkError::Validation("token version overflow".to_string()))?;
        state.tokens.insert(t.token_id.clone(), t);
    }

    if !verify_token_supply_conservation(state, &token.token_id)? {
        return Err(VNetworkError::Validation(
            "token supply conservation check failed".to_string(),
        ));
    }

    state.logical_clock = state
        .logical_clock
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
    let sequence = (state.events.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
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
            "transfer_scope": scope.as_str(),
            "drain_bps": drain_bps,
            "protocol_settlement": is_protocol_settlement,
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
    let expected_ghost_custody = format!("ghost_custody::{}", token.token_id);
    let drain_wallet_id = if token.ghost
        && token.wallet_id.is_empty()
        && (wallet_ref.trim().is_empty() || wallet_ref == expected_ghost_custody)
    {
        require_participant_scope_at(
            state,
            actor_pubkey,
            ParticipationLevel::Network,
            None,
            timestamp_ms,
        )?;
        if actor_pubkey != token.authority_pubkey {
            return Err(VNetworkError::Authorization(
                "only token authority may drain parentless ghost token custody".to_string(),
            ));
        }
        expected_ghost_custody
    } else {
        let wallet = verify_wallet_exists(state, wallet_ref)?.clone();
        wallet.verify_permission(
            actor_pubkey,
            WalletPermission::Drain,
            Some(&token.token_id),
            Some(amount),
            timestamp_ms,
        )?;
        wallet.wallet_id
    };

    let key = NetworkLedgerState::balance_key(&token.token_id, &drain_wallet_id);
    let before = state
        .balances
        .get(&key)
        .cloned()
        .ok_or_else(|| VNetworkError::InsufficientBalance("wallet balance not found".to_string()))?;
    let before_hash = blake3_hex(&canonical_json_bytes(&before)?);

    let mut after = before.clone();
    after.vector = before.vector.checked_sub_token(amount)?;
    after.updated_at_ms = timestamp_ms;
    after.version = after
        .version
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("balance version overflow".to_string()))?;
    state.balances.insert(key, after.clone());

    let mut t = token;
    t.total_supply = t
        .total_supply
        .checked_sub(amount)
        .ok_or_else(|| VNetworkError::Validation("token total_supply underflow on drain".to_string()))?;
    t.version = t
        .version
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("token version overflow".to_string()))?;
    state.tokens.insert(t.token_id.clone(), t.clone());

    if !verify_token_supply_conservation(state, &t.token_id)? {
        return Err(VNetworkError::Validation(
            "token supply conservation check failed after drain".to_string(),
        ));
    }

    state.logical_clock = state
        .logical_clock
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
    let sequence = (state.events.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
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
            "wallet_id": drain_wallet_id,
            "amount": amount.to_string(),
            "vector_after": after.vector.as_array(),
        }),
        before_hash,
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((after, event))
}

#[allow(clippy::too_many_arguments)]
pub fn apply_adjust_non_transferable_dimensions(
    state: &mut NetworkLedgerState,
    token_ref: &str,
    wallet_ref: &str,
    new_auth_ratio_au: Option<u128>,
    new_energy: Option<u128>,
    reason: &str,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(TokenBalanceRecord, LedgerEvent)> {
    if new_auth_ratio_au.is_none() && new_energy.is_none() {
        return Err(VNetworkError::Validation(
            "must specify new_auth_ratio_au or new_energy".to_string(),
        ));
    }
    if reason.trim().is_empty() {
        return Err(VNetworkError::Validation(
            "dimension adjustment reason is required".to_string(),
        ));
    }

    let token = verify_token_exists(state, token_ref)?.clone();
    let expected_ghost_custody = format!("ghost_custody::{}", token.token_id);
    let target_wallet_id = if token.ghost
        && token.wallet_id.is_empty()
        && (wallet_ref.trim().is_empty() || wallet_ref == expected_ghost_custody)
    {
        expected_ghost_custody
    } else {
        verify_wallet_exists(state, wallet_ref)?.wallet_id.clone()
    };

    if actor_pubkey != token.authority_pubkey {
        return Err(VNetworkError::Authorization(
            "only token authority may adjust non-transferable dimensions"
                .to_string(),
        ));
    }

    let key = NetworkLedgerState::balance_key(&token.token_id, &target_wallet_id);
    let before = state.balances.get(&key).cloned().unwrap_or(TokenBalanceRecord {
        token_id: token.token_id.clone(),
        wallet_id: target_wallet_id.clone(),
        vector: TokenVector::zero(),
        updated_at_ms: timestamp_ms,
        version: 0,
    });
    let before_hash = blake3_hex(&canonical_json_bytes(&before)?);

    let mut after = before.clone();
    if let Some(au) = new_auth_ratio_au {
        after.vector.auth_ratio_au = au;
    }
    if let Some(en) = new_energy {
        after.vector.energy = en;
    }
    after.updated_at_ms = timestamp_ms;
    after.version = after
        .version
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("balance version overflow".to_string()))?;
    state.balances.insert(key, after.clone());

    state.logical_clock = state
        .logical_clock
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
    let sequence = (state.events.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
    let parents = state.latest_event_hash().into_iter().collect();
    let after_hash = blake3_hex(&canonical_json_bytes(&after)?);
    let event = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "token_dimensions",
        &token.token_id,
        "TOKEN_DIMENSIONS_ADJUST",
        actor_pubkey,
        state.logical_clock,
        timestamp_ms,
        serde_json::json!({
            "token_id": token.token_id,
            "wallet_id": target_wallet_id,
            "reason": reason.trim(),
            "before_vector": before.vector.as_array(),
            "after_vector": after.vector.as_array(),
            "balance": after,
        }),
        before_hash,
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((after, event))
}
