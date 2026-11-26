use crate::replay::replay_from_events;
use crate::state::{GenesisConfig, NetworkLedgerState};
use serde::{Deserialize, Serialize};
use vnetwork_types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructionReport {
    pub entity_kind: String,
    pub entity_id: String,
    pub verified: bool,
    pub live_hash: String,
    pub reconstructed_hash: String,
    pub total_events_replayed: usize,
    pub entity_event_count: usize,
    pub reconstructed_state: serde_json::Value,
    pub state_root: String,
}

pub fn reconstruct_entity(
    live_state: &NetworkLedgerState,
    genesis: &GenesisConfig,
    entity_kind: &str,
    entity_id_or_name: &str,
) -> VResult<ReconstructionReport> {
    let replayed = replay_from_events(genesis, &live_state.events)?;
    let norm_kind = entity_kind.trim().to_ascii_lowercase();

    let (resolved_id, live_val, reconstructed_val) = match norm_kind.as_str() {
        "space" => {
            let live = live_state
                .spaces
                .get(entity_id_or_name)
                .or_else(|| {
                    live_state
                        .spaces
                        .values()
                        .find(|s| s.name.eq_ignore_ascii_case(entity_id_or_name))
                })
                .ok_or_else(|| VNetworkError::NotFound(format!("space `{entity_id_or_name}`")))?;
            let rec = replayed
                .spaces
                .get(&live.space_id)
                .ok_or_else(|| VNetworkError::NotFound("reconstructed space missing".to_string()))?;
            (
                live.space_id.clone(),
                serde_json::to_value(live).unwrap_or_default(),
                serde_json::to_value(rec).unwrap_or_default(),
            )
        }
        "region" => {
            let live = live_state
                .regions
                .get(entity_id_or_name)
                .or_else(|| {
                    live_state
                        .regions
                        .values()
                        .find(|r| r.name.eq_ignore_ascii_case(entity_id_or_name))
                })
                .ok_or_else(|| VNetworkError::NotFound(format!("region `{entity_id_or_name}`")))?;
            let rec = replayed
                .regions
                .get(&live.region_id)
                .ok_or_else(|| VNetworkError::NotFound("reconstructed region missing".to_string()))?;
            (
                live.region_id.clone(),
                serde_json::to_value(live).unwrap_or_default(),
                serde_json::to_value(rec).unwrap_or_default(),
            )
        }
        "wallet" => {
            let live = live_state
                .wallets
                .get(entity_id_or_name)
                .or_else(|| {
                    live_state
                        .wallets
                        .values()
                        .find(|w| w.name.eq_ignore_ascii_case(entity_id_or_name))
                })
                .ok_or_else(|| VNetworkError::NotFound(format!("wallet `{entity_id_or_name}`")))?;
            let rec = replayed
                .wallets
                .get(&live.wallet_id)
                .ok_or_else(|| VNetworkError::NotFound("reconstructed wallet missing".to_string()))?;
            (
                live.wallet_id.clone(),
                serde_json::to_value(live).unwrap_or_default(),
                serde_json::to_value(rec).unwrap_or_default(),
            )
        }
        "token" => {
            let live = live_state
                .tokens
                .get(entity_id_or_name)
                .or_else(|| {
                    live_state.tokens.values().find(|t| {
                        t.symbol.eq_ignore_ascii_case(entity_id_or_name)
                            || t.name.eq_ignore_ascii_case(entity_id_or_name)
                    })
                })
                .ok_or_else(|| VNetworkError::NotFound(format!("token `{entity_id_or_name}`")))?;
            let rec = replayed
                .tokens
                .get(&live.token_id)
                .ok_or_else(|| VNetworkError::NotFound("reconstructed token missing".to_string()))?;
            let live_bals: Vec<_> = live_state
                .balances
                .values()
                .filter(|b| b.token_id == live.token_id)
                .collect();
            let rec_bals: Vec<_> = replayed
                .balances
                .values()
                .filter(|b| b.token_id == rec.token_id)
                .collect();
            (
                live.token_id.clone(),
                serde_json::json!({ "token": live, "balances": live_bals }),
                serde_json::json!({ "token": rec, "balances": rec_bals }),
            )
        }
        "contract" => {
            let live = live_state
                .contracts
                .get(entity_id_or_name)
                .or_else(|| {
                    live_state
                        .contracts
                        .values()
                        .find(|c| c.name.eq_ignore_ascii_case(entity_id_or_name))
                })
                .ok_or_else(|| VNetworkError::NotFound(format!("contract `{entity_id_or_name}`")))?;
            let rec = replayed
                .contracts
                .get(&live.contract_id)
                .ok_or_else(|| {
                    VNetworkError::NotFound("reconstructed contract missing".to_string())
                })?;
            (
                live.contract_id.clone(),
                serde_json::to_value(live).unwrap_or_default(),
                serde_json::to_value(rec).unwrap_or_default(),
            )
        }
        "loan" => {
            let live = live_state
                .loans
                .get(entity_id_or_name)
                .or_else(|| {
                    live_state
                        .loans
                        .values()
                        .find(|l| l.name.eq_ignore_ascii_case(entity_id_or_name))
                })
                .ok_or_else(|| VNetworkError::NotFound(format!("loan `{entity_id_or_name}`")))?;
            let rec = replayed
                .loans
                .get(&live.loan_id)
                .ok_or_else(|| VNetworkError::NotFound("reconstructed loan missing".to_string()))?;
            (
                live.loan_id.clone(),
                serde_json::to_value(live).unwrap_or_default(),
                serde_json::to_value(rec).unwrap_or_default(),
            )
        }
        other => {
            return Err(VNetworkError::Validation(format!(
                "unsupported reconstruction entity_kind `{other}`"
            )));
        }
    };

    let live_hash = blake3_hex(&canonical_json_bytes(&live_val)?);
    let reconstructed_hash = blake3_hex(&canonical_json_bytes(&reconstructed_val)?);
    let entity_event_count = live_state
        .events
        .iter()
        .filter(|e| e.entity_id == resolved_id)
        .count();

    Ok(ReconstructionReport {
        entity_kind: norm_kind,
        entity_id: resolved_id,
        verified: live_hash == reconstructed_hash,
        live_hash,
        reconstructed_hash,
        total_events_replayed: replayed.events.len(),
        entity_event_count,
        reconstructed_state: reconstructed_val,
        state_root: replayed.compute_state_root()?,
    })
}
