use crate::events::verify_event_chain;
use crate::state::{GenesisConfig, NetworkLedgerState};
use crate::token::apply_transfer_token;
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
    let mut state = NetworkLedgerState::new(genesis);

    for ev in events {
        apply_event_to_state(&mut state, ev)?;
    }

    Ok(state)
}

pub fn apply_event_to_state(state: &mut NetworkLedgerState, ev: &LedgerEvent) -> VResult<()> {
    match ev.operation.as_str() {
        "PARTICIPANT_JOIN" => {
            if let Some(p_val) = ev.payload.get("participant") {
                let participant: ParticipantRecord = serde_json::from_value(p_val.clone())
                    .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
                state
                    .participants
                    .insert(participant.participant_id.clone(), participant);
            }
            if let Some(n_val) = ev.payload.get("node") {
                let node: NodeRecord = serde_json::from_value(n_val.clone())
                    .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
                state.nodes.insert(node.node_id.clone(), node);
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
        "WALLET_CREATE" | "GHOST_WALLET_CREATE" | "WALLET_KEY_AUTHORIZE" => {
            let wallet: WalletEntity = serde_json::from_value(ev.payload.clone())
                .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
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
            let drain_fee: u128 = ev
                .payload
                .get("drain_fee")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            // Derive exact drain bps or replay balance adjustment directly matching exact values
            let drain_bps = if drain_fee == 0 {
                Some(0)
            } else {
                // Reconstruct using stored post-transfer vector amounts when fee rounded
                None
            };
            if let Some(bps) = drain_bps {
                let mut shadow = state.clone();
                let _ = apply_transfer_token(
                    &mut shadow,
                    token_id,
                    from_wallet_id,
                    to_wallet_id,
                    amount,
                    Some(bps),
                    &ev.actor_pubkey,
                    ev.timestamp_ms,
                )?;
                state.balances = shadow.balances;
                state.tokens = shadow.tokens;
            } else {
                let from_key = NetworkLedgerState::balance_key(token_id, from_wallet_id);
                let to_key = NetworkLedgerState::balance_key(token_id, to_wallet_id);
                let mut from_bal = state
                    .balances
                    .get(&from_key)
                    .cloned()
                    .ok_or_else(|| VNetworkError::InsufficientBalance("missing from balance".to_string()))?;
                let mut to_bal = state.balances.get(&to_key).cloned().unwrap_or(TokenBalanceRecord {
                    token_id: token_id.to_string(),
                    wallet_id: to_wallet_id.to_string(),
                    vector: TokenVector::new(0, 1000, 0),
                    updated_at_ms: ev.timestamp_ms,
                    version: 0,
                });
                let net_received = amount.saturating_sub(drain_fee);
                from_bal.vector.token -= amount;
                from_bal.updated_at_ms = ev.timestamp_ms;
                from_bal.version += 1;
                to_bal.vector.token += net_received;
                to_bal.updated_at_ms = ev.timestamp_ms;
                to_bal.version += 1;
                state.balances.insert(from_key, from_bal);
                state.balances.insert(to_key, to_bal);
                if let Some(t) = state.tokens.get_mut(token_id) {
                    t.total_supply = t.total_supply.saturating_sub(drain_fee);
                    t.version += 1;
                }
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
            if let Some(bal) = state.balances.get_mut(&key) {
                bal.vector.token = bal.vector.token.saturating_sub(amount);
                bal.updated_at_ms = ev.timestamp_ms;
                bal.version += 1;
            }
            if let Some(t) = state.tokens.get_mut(token_id) {
                t.total_supply = t.total_supply.saturating_sub(amount);
                t.version += 1;
            }
        }
        "CONTRACT_CREATE" => {
            let contract: VContractEntity = serde_json::from_value(ev.payload.clone())
                .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
            state.contracts.insert(contract.contract_id.clone(), contract);
        }
        "CONTRACT_EXECUTE" => {
            if let Some(c) = state.contracts.get_mut(&ev.entity_id) {
                c.execution_count = ev
                    .payload
                    .get("execution_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(c.execution_count + 1);
                c.version += 1;
            }
        }
        "LOAN_CREATE" | "LOAN_FUND" | "LOAN_DRAW" | "LOAN_REPAY" | "LOAN_LIQUIDATE" => {
            let loan: VLoanEntity = serde_json::from_value(ev.payload.clone())
                .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
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
