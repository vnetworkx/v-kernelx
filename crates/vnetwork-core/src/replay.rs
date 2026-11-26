use crate::events::verify_event_chain;
use crate::loans::{loan_escrow_wallet_id, move_loan_escrow_balance};
use crate::state::{GenesisConfig, NetworkLedgerState};
use serde::{Deserialize, Serialize};
use vnetwork_types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayVerificationReport {
    pub valid: bool,
    pub events_replayed: usize,
    pub replayed_state_root: String,
    pub live_state_root: String,
    pub replayed_replay_hash: String,
    pub live_replay_hash: String,
}

pub fn replay_from_events(
    genesis: &GenesisConfig,
    events: &[LedgerEvent],
) -> VResult<NetworkLedgerState> {
    verify_event_chain(events)?;
    let mut state = NetworkLedgerState::try_new(genesis)?;

    for ev in events {
        apply_event_to_state(&mut state, ev)?;
    }
    state.event_history_root = state.compute_event_history_root();

    Ok(state)
}

pub fn apply_event_to_state(state: &mut NetworkLedgerState, ev: &LedgerEvent) -> VResult<()> {
    match ev.operation.as_str() {
        "PARTICIPANT_JOIN" | "PARTICIPANT_SCOPE_GRANT" | "PARTICIPANT_SCOPE_REVOKE" => {
            if let Some(p_val) = ev.payload.get("participant") {
                let participant: ParticipantRecord = serde_json::from_value(p_val.clone())
                    .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
                state
                    .participants
                    .insert(participant.participant_id.clone(), participant);
            }
            if let Some(n_val) = ev.payload.get("node") {
                if !n_val.is_null() {
                    let node: NodeRecord = serde_json::from_value(n_val.clone())
                        .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
                    state.nodes.insert(node.node_id.clone(), node);
                }
            }
        }
        "SPACE_CREATE" | "GHOST_SPACE_CREATE" => {
            let space: SpaceEntity = serde_json::from_value(ev.payload.clone())
                .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
            state.spaces.insert(space.space_id.clone(), space);
        }
        "REGION_CREATE" | "GHOST_REGION_CREATE" => {
            let region: RegionEntity = serde_json::from_value(ev.payload.clone())
                .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
            state.regions.insert(region.region_id.clone(), region);
        }
        "WALLET_CREATE" | "GHOST_WALLET_CREATE" | "WALLET_KEY_AUTHORIZE"
        | "WALLET_KEY_REVOKE" | "WALLET_KEY_ROTATE" | "WALLET_RECEIVE_POLICY_UPDATE" => {
            let wallet: WalletEntity = serde_json::from_value(ev.payload.clone())
                .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
            if let Some(binding) = wallet
                .authorized_keys
                .values()
                .find(|b| b.pop_nonce.is_some() && !b.revoked)
            {
                if let Some(nonce) = &binding.pop_nonce {
                    state.used_wallet_pop_nonces.insert(format!(
                        "{}::{}::{nonce}",
                        wallet.wallet_id, binding.public_key_hex
                    ));
                }
            }
            state.wallets.insert(wallet.wallet_id.clone(), wallet);
        }
        "TOKEN_CREATE" | "GHOST_TOKEN_CREATE" => {
            let token: TokenEntity = serde_json::from_value(ev.payload.clone())
                .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
            let bal_key = NetworkLedgerState::balance_key(&token.token_id, &token.wallet_id);
            let bal = TokenBalanceRecord {
                token_id: token.token_id.clone(),
                wallet_id: token.wallet_id.clone(),
                vector: token.initial_vector,
                updated_at_ms: token.created_at_ms,
                version: 1,
            };
            state.tokens.insert(token.token_id.clone(), token);
            state.balances.insert(bal_key, bal);
        }
        "TOKEN_TRANSFER" => {
            let token_id = ev
                .payload
                .get("token_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| VNetworkError::Serialization("missing token_id".to_string()))?;
            let from_wallet_id = ev
                .payload
                .get("from_wallet_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| VNetworkError::Serialization("missing from_wallet_id".to_string()))?;
            let to_wallet_id = ev
                .payload
                .get("to_wallet_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| VNetworkError::Serialization("missing to_wallet_id".to_string()))?;
            let amount: u128 = ev
                .payload
                .get("amount")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| VNetworkError::Serialization("missing amount".to_string()))?;
            let drain_fee: u128 = match ev.payload.get("drain_fee") {
                None | Some(serde_json::Value::Null) => 0,
                Some(v) => v
                    .as_str()
                    .ok_or_else(|| VNetworkError::Serialization("invalid drain_fee type".to_string()))?
                    .parse()
                    .map_err(|_| VNetworkError::Serialization("invalid drain_fee u128".to_string()))?,
            };
            let net_received = amount.checked_sub(drain_fee).ok_or_else(|| {
                VNetworkError::Validation("drain_fee exceeds transfer amount in event".to_string())
            })?;

            let from_key = NetworkLedgerState::balance_key(token_id, from_wallet_id);
            let to_key = NetworkLedgerState::balance_key(token_id, to_wallet_id);

            let mut from_bal = state
                .balances
                .get(&from_key)
                .cloned()
                .ok_or_else(|| VNetworkError::InsufficientBalance("missing from balance".to_string()))?;

            if from_wallet_id == to_wallet_id {
                from_bal.vector = from_bal
                    .vector
                    .checked_sub_token(amount)?
                    .checked_add_token(net_received)?;
                from_bal.updated_at_ms = ev.timestamp_ms;
                from_bal.version = from_bal
                    .version
                    .checked_add(1)
                    .ok_or_else(|| VNetworkError::Validation("balance version overflow".to_string()))?;
                state.balances.insert(from_key, from_bal);
            } else {
                let mut to_bal = state.balances.get(&to_key).cloned().unwrap_or(TokenBalanceRecord {
                    token_id: token_id.to_string(),
                    wallet_id: to_wallet_id.to_string(),
                    vector: TokenVector::zero(),
                    updated_at_ms: ev.timestamp_ms,
                    version: 0,
                });

                from_bal.vector = from_bal.vector.checked_sub_token(amount)?;
                from_bal.updated_at_ms = ev.timestamp_ms;
                from_bal.version = from_bal
                    .version
                    .checked_add(1)
                    .ok_or_else(|| VNetworkError::Validation("balance version overflow".to_string()))?;

                to_bal.vector = to_bal.vector.checked_add_token(net_received)?;
                to_bal.updated_at_ms = ev.timestamp_ms;
                to_bal.version = to_bal
                    .version
                    .checked_add(1)
                    .ok_or_else(|| VNetworkError::Validation("balance version overflow".to_string()))?;

                state.balances.insert(from_key, from_bal);
                state.balances.insert(to_key, to_bal);
            }
            if drain_fee > 0 {
                let t = state.tokens.get_mut(token_id).ok_or_else(|| {
                    VNetworkError::NotFound(format!("token `{token_id}` missing during transfer replay"))
                })?;
                t.total_supply = t.total_supply.checked_sub(drain_fee).ok_or_else(|| {
                    VNetworkError::Validation("total_supply underflow on replay".to_string())
                })?;
                t.version = t
                    .version
                    .checked_add(1)
                    .ok_or_else(|| VNetworkError::Validation("token version overflow".to_string()))?;
            }
        }
        "TOKEN_DRAIN" => {
            let token_id = ev
                .payload
                .get("token_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| VNetworkError::Serialization("missing token_id".to_string()))?;
            let wallet_id = ev
                .payload
                .get("wallet_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| VNetworkError::Serialization("missing wallet_id".to_string()))?;
            let amount: u128 = ev
                .payload
                .get("amount")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| VNetworkError::Serialization("missing amount".to_string()))?;
            let key = NetworkLedgerState::balance_key(token_id, wallet_id);
            let bal = state
                .balances
                .get_mut(&key)
                .ok_or_else(|| VNetworkError::InsufficientBalance("missing drain balance".to_string()))?;
            bal.vector = bal.vector.checked_sub_token(amount)?;
            bal.updated_at_ms = ev.timestamp_ms;
            bal.version = bal
                .version
                .checked_add(1)
                .ok_or_else(|| VNetworkError::Validation("balance version overflow".to_string()))?;
            let t = state.tokens.get_mut(token_id).ok_or_else(|| {
                VNetworkError::NotFound(format!("token `{token_id}` missing during drain replay"))
            })?;
            t.total_supply = t.total_supply.checked_sub(amount).ok_or_else(|| {
                VNetworkError::Validation("total_supply underflow on drain replay".to_string())
            })?;
            t.version = t
                .version
                .checked_add(1)
                .ok_or_else(|| VNetworkError::Validation("token version overflow".to_string()))?;
        }
        "TOKEN_DIMENSIONS_ADJUST" => {
            let bal_val = ev.payload.get("balance").ok_or_else(|| {
                VNetworkError::Serialization("missing balance in TOKEN_DIMENSIONS_ADJUST".to_string())
            })?;
            let bal: TokenBalanceRecord = serde_json::from_value(bal_val.clone())
                .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
            let key = NetworkLedgerState::balance_key(&bal.token_id, &bal.wallet_id);
            state.balances.insert(key, bal);
        }
        "CONTRACT_CREATE" => {
            let contract: VContractEntity = serde_json::from_value(ev.payload.clone())
                .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
            state.contracts.insert(contract.contract_id.clone(), contract);
        }
        "CONTRACT_EXECUTE" => {
            if let Some(c_val) = ev.payload.get("contract") {
                let contract: VContractEntity = serde_json::from_value(c_val.clone())
                    .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
                state.contracts.insert(contract.contract_id.clone(), contract);
            } else if let Some(c) = state.contracts.get_mut(&ev.entity_id) {
                c.execution_count = match ev.payload.get("execution_count") {
                    None | Some(serde_json::Value::Null) => c
                        .execution_count
                        .checked_add(1)
                        .ok_or_else(|| VNetworkError::Validation("contract execution_count overflow".to_string()))?,
                    Some(v) => v.as_u64().ok_or_else(|| {
                        VNetworkError::Serialization("invalid contract execution_count".to_string())
                    })?,
                };
                c.version = c
                    .version
                    .checked_add(1)
                    .ok_or_else(|| VNetworkError::Validation("contract version overflow".to_string()))?;
            }
        }
        "LOAN_CREATE" | "LOAN_FUND" | "LOAN_DRAW" | "LOAN_REPAY" | "LOAN_LIQUIDATE" => {
            let loan: VLoanEntity = serde_json::from_value(ev.payload.clone())
                .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
            let c_token = if loan.collateral_token_id.is_empty() {
                loan.token_id.as_str()
            } else {
                loan.collateral_token_id.as_str()
            };
            let escrow_id = loan_escrow_wallet_id(&loan.loan_id);
            let prev_collateral = state
                .loans
                .get(&loan.loan_id)
                .map(|p| p.collateral_locked)
                .unwrap_or(0);

            if ev.operation == "LOAN_CREATE" && loan.collateral_locked > 0 {
                move_loan_escrow_balance(
                    state,
                    c_token,
                    &loan.borrower_wallet_id,
                    &escrow_id,
                    loan.collateral_locked,
                    ev.timestamp_ms,
                )?;
            } else if ev.operation == "LOAN_REPAY"
                && loan.status == LoanStatus::Repaid
                && prev_collateral > 0
                && loan.collateral_locked == 0
            {
                move_loan_escrow_balance(
                    state,
                    c_token,
                    &escrow_id,
                    &loan.borrower_wallet_id,
                    prev_collateral,
                    ev.timestamp_ms,
                )?;
            } else if ev.operation == "LOAN_LIQUIDATE"
                && prev_collateral > 0
                && loan.collateral_locked == 0
            {
                move_loan_escrow_balance(
                    state,
                    c_token,
                    &escrow_id,
                    &loan.lender_wallet_id,
                    prev_collateral,
                    ev.timestamp_ms,
                )?;
            }
            state.loans.insert(loan.loan_id.clone(), loan);
        }
        "CONSENSUS_HEIGHT_COMMIT" => {
            if let Some(h) = ev.payload.get("height").and_then(|v| v.as_u64()) {
                state.height = h;
            }
        }
        _ => {}
    }

    state.logical_clock = ev.logical_clock;
    state.events.push(ev.clone());
    Ok(())
}

pub fn verify_replay_equivalence(
    live_state: &NetworkLedgerState,
    genesis: &GenesisConfig,
) -> VResult<ReplayVerificationReport> {
    let mut replayed = replay_from_events(genesis, &live_state.events)?;
    replayed.height = live_state.height;
    replayed.actor_nonces = live_state.actor_nonces.clone();
    replayed.seen_request_ids = live_state.seen_request_ids.clone();
    replayed.used_wallet_pop_nonces = live_state.used_wallet_pop_nonces.clone();
    if !live_state.validator_membership_history.is_empty()
        || live_state.validator_epoch != genesis.genesis_epoch
    {
        let ctx = genesis.consensus_context_for_epoch(live_state.validator_epoch)?;
        let proven = crate::consensus_gate::verify_membership_chain_from_genesis(
            &genesis.initial_validators,
            genesis.genesis_epoch,
            &ctx,
            &live_state.validator_membership_history,
            live_state.validator_epoch,
            &validate_validator_set(&live_state.validators)?,
            &live_state.validators,
        )?;
        replayed.validator_epoch = live_state.validator_epoch;
        replayed.validators = proven;
        replayed.validator_membership_history = live_state.validator_membership_history.clone();
    }
    let replayed_state_root = replayed.compute_state_root()?;
    let live_state_root = live_state.compute_state_root()?;
    let replayed_replay_hash = replayed.compute_replay_hash();
    let live_replay_hash = live_state.compute_replay_hash();
    Ok(ReplayVerificationReport {
        valid: replayed_state_root == live_state_root && replayed_replay_hash == live_replay_hash,
        events_replayed: replayed.events.len(),
        replayed_state_root,
        live_state_root,
        replayed_replay_hash,
        live_replay_hash,
    })
}
