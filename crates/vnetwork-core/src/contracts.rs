use crate::hierarchy::verify_region_exists;
use crate::identity::require_participant_scope_at;
use crate::state::NetworkLedgerState;
use std::collections::{BTreeMap, BTreeSet};
use vnetwork_types::*;

pub fn apply_create_contract(
    state: &mut NetworkLedgerState,
    name: &str,
    region_ref: Option<&str>,
    rules: BTreeMap<String, serde_json::Value>,
    actions: Vec<serde_json::Value>,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(VContractEntity, LedgerEvent)> {
    require_participant_scope_at(
        state,
        actor_pubkey,
        ParticipationLevel::Network,
        None,
        timestamp_ms,
    )?;

    let clean_name = name.trim();
    if clean_name.is_empty() {
        return Err(VNetworkError::Validation("contract name cannot be empty".to_string()));
    }
    if state
        .contracts
        .values()
        .any(|c| c.name.eq_ignore_ascii_case(clean_name))
    {
        return Err(VNetworkError::AlreadyExists(format!(
            "contract `{clean_name}` already exists"
        )));
    }

    let (space_id, region_id) = match region_ref {
        Some(r) => {
            let reg = verify_region_exists(state, r)?;
            (Some(reg.space_id.clone()), Some(reg.region_id.clone()))
        }
        None => (None, None),
    };

    let mut authorized_actors = BTreeSet::new();
    if let Some(arr) = rules.get("authorized_actors").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(pk) = item.as_str() {
                if !pk.trim().is_empty() {
                    authorized_actors.insert(pk.trim().to_string());
                }
            }
        }
    }
    let max_executions = rules
        .get("max_executions")
        .and_then(|v| v.as_u64());
    let expires_at_ms = rules
        .get("expires_at_ms")
        .and_then(|v| v.as_u64());
    if let Some(exp) = expires_at_ms {
        if timestamp_ms >= exp {
            return Err(VNetworkError::Validation(
                "contract expires_at_ms must be in the future".to_string(),
            ));
        }
    }
    let min_auth_ratio_bps = rules
        .get("min_auth_ratio_bps")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let nonce = (state.contracts.len() as u64) + 1;
    let contract_id = derive_contract_id(clean_name, actor_pubkey, nonce);
    let contract = VContractEntity {
        contract_id: contract_id.clone(),
        name: clean_name.to_string(),
        space_id,
        region_id,
        creator_pubkey: actor_pubkey.to_string(),
        rules,
        actions,
        authorized_actors,
        max_executions,
        expires_at_ms,
        min_auth_ratio_bps,
        execution_history: Vec::new(),
        execution_count: 0,
        active: true,
        created_at_ms: timestamp_ms,
        version: 1,
    };

    state.contracts.insert(contract_id.clone(), contract.clone());
    state.logical_clock += 1;
    let sequence = (state.events.len() as u64) + 1;
    let parents = state.latest_event_hash().into_iter().collect();
    let after_hash = blake3_hex(&canonical_json_bytes(&contract)?);
    let event = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "contract",
        &contract_id,
        "CONTRACT_CREATE",
        actor_pubkey,
        state.logical_clock,
        timestamp_ms,
        serde_json::to_value(&contract).unwrap_or_default(),
        "",
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((contract, event))
}

pub fn apply_execute_contract(
    state: &mut NetworkLedgerState,
    contract_ref: &str,
    action: &str,
    args: serde_json::Value,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(VContractEntity, LedgerEvent)> {
    require_participant_scope_at(
        state,
        actor_pubkey,
        ParticipationLevel::Network,
        None,
        timestamp_ms,
    )?;

    let mut contract = state
        .contracts
        .get(contract_ref)
        .or_else(|| {
            state
                .contracts
                .values()
                .find(|c| c.name.eq_ignore_ascii_case(contract_ref))
        })
        .cloned()
        .ok_or_else(|| VNetworkError::NotFound(format!("contract `{contract_ref}` not found")))?;

    if !contract.active {
        return Err(VNetworkError::Validation("contract is inactive".to_string()));
    }
    if let Some(exp) = contract.expires_at_ms {
        if timestamp_ms >= exp {
            return Err(VNetworkError::Validation(format!(
                "contract `{}` expired at {exp}",
                contract.name
            )));
        }
    }
    if let Some(max_exec) = contract.max_executions {
        if contract.execution_count >= max_exec {
            return Err(VNetworkError::Validation(format!(
                "contract `{}` reached max_executions ({max_exec})",
                contract.name
            )));
        }
    }
    let allow_public = contract
        .rules
        .get("allow_public_execution")
        .and_then(|v| v.as_bool())
        == Some(true);
    let is_creator = contract.creator_pubkey == actor_pubkey;
    let is_listed = contract.authorized_actors.contains(actor_pubkey);
    if !allow_public && !is_creator && !is_listed {
        return Err(VNetworkError::Authorization(format!(
            "actor `{actor_pubkey}` is not authorized to execute contract `{}`",
            contract.name
        )));
    }
    if contract.min_auth_ratio_bps > 0 {
        if let Some(reg_id) = &contract.region_id {
            let reg = verify_region_exists(state, reg_id)?;
            if reg.auth_ratio_bps < contract.min_auth_ratio_bps {
                return Err(VNetworkError::Authorization(format!(
                    "region auth_ratio_bps {} < required {}",
                    reg.auth_ratio_bps, contract.min_auth_ratio_bps
                )));
            }
        }
    }

    if !contract.actions.is_empty() {
        let declared = contract
            .actions
            .iter()
            .any(|a| a.get("name").and_then(|v| v.as_str()) == Some(action));
        if !declared {
            return Err(VNetworkError::Validation(format!(
                "action `{action}` is not declared on contract `{}`",
                contract.name
            )));
        }
    }

    let before_hash = blake3_hex(&canonical_json_bytes(&contract)?);
    contract.execution_count = contract
        .execution_count
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("contract execution_count overflow".to_string()))?;
    let exec_entry = format!("{}:{}@{}", contract.execution_count, action, timestamp_ms);
    contract.execution_history.push(exec_entry);
    contract.version = contract
        .version
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("contract version overflow".to_string()))?;
    state
        .contracts
        .insert(contract.contract_id.clone(), contract.clone());

    state.logical_clock += 1;
    let sequence = (state.events.len() as u64) + 1;
    let parents = state.latest_event_hash().into_iter().collect();
    let after_hash = blake3_hex(&canonical_json_bytes(&contract)?);
    let event = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "contract",
        &contract.contract_id,
        "CONTRACT_EXECUTE",
        actor_pubkey,
        state.logical_clock,
        timestamp_ms,
        serde_json::json!({
            "contract_id": contract.contract_id,
            "name": contract.name,
            "action": action,
            "args": args,
            "execution_count": contract.execution_count,
            "contract": contract,
        }),
        before_hash,
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((contract, event))
}
