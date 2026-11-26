use crate::hierarchy::verify_region_exists;
use crate::identity::require_participant_scope;
use crate::state::NetworkLedgerState;
use std::collections::BTreeMap;
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
    require_participant_scope(state, actor_pubkey, ParticipationLevel::Network)?;

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
    require_participant_scope(state, actor_pubkey, ParticipationLevel::Network)?;

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
    contract.execution_count += 1;
    contract.version += 1;
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
        }),
        before_hash,
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((contract, event))
}
