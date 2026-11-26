use crate::hierarchy::{verify_region_exists, verify_token_exists, verify_wallet_exists};
use crate::identity::require_participant_scope_at;
use crate::loans::move_loan_escrow_balance;
use crate::state::NetworkLedgerState;
use crate::supply::verify_token_supply_conservation;
use std::collections::{BTreeMap, BTreeSet};
use vnetwork_types::*;

pub fn contract_escrow_wallet_id(contract_id: &str) -> String {
    format!("escrow::contract::{contract_id}")
}

fn reject_nondeterministic_keys(val: &serde_json::Value) -> VResult<()> {
    const DISALLOWED: &[&str] = &[
        "host_fs",
        "fs_path",
        "fs_access",
        "http_call",
        "http_url",
        "network_call",
        "external_call",
        "external_http",
        "shell_cmd",
        "system_exec",
        "random",
        "rng_seed",
        "wall_clock",
    ];
    match val {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let low = k.trim().to_ascii_lowercase();
                if DISALLOWED.contains(&low.as_str()) {
                    return Err(VNetworkError::Validation(format!(
                        "nondeterministic host operation `{k}` is forbidden in vContracts"
                    )));
                }
                if low == "nondeterministic" && v.as_bool() == Some(true) {
                    return Err(VNetworkError::Validation(
                        "nondeterministic vContract execution is forbidden".to_string(),
                    ));
                }
                reject_nondeterministic_keys(v)?;
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                reject_nondeterministic_keys(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_u128_arg(val: &serde_json::Value, field: &str) -> VResult<u128> {
    if let Some(u) = val.as_u64() {
        return Ok(u as u128);
    }
    if let Some(s) = val.as_str() {
        return s.trim().replace('_', "").parse::<u128>().map_err(|_| {
            VNetworkError::Validation(format!("invalid unsigned integer `{s}` for `{field}`"))
        });
    }
    Err(VNetworkError::Validation(format!(
        "expected unsigned integer for `{field}`"
    )))
}

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

    for v in rules.values() {
        reject_nondeterministic_keys(v)?;
    }
    for (k, _) in &rules {
        let low = k.trim().to_ascii_lowercase();
        if matches!(
            low.as_str(),
            "host_fs" | "http_call" | "network_call" | "external_call" | "system_exec" | "random"
        ) {
            return Err(VNetworkError::Validation(format!(
                "nondeterministic host operation `{k}` is forbidden in vContracts"
            )));
        }
    }
    for act in &actions {
        reject_nondeterministic_keys(act)?;
    }

    let (space_id, region_id) = match region_ref {
        Some(r) if !r.trim().is_empty() => {
            let reg = verify_region_exists(state, r)?;
            (Some(reg.space_id.clone()), Some(reg.region_id.clone()))
        }
        _ => (None, None),
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
    let max_executions = match rules.get("max_executions") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(v.as_u64().ok_or_else(|| {
            VNetworkError::Validation("contract max_executions must be unsigned integer".to_string())
        })?),
    };
    let expires_at_ms = match rules.get("expires_at_ms") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(v.as_u64().ok_or_else(|| {
            VNetworkError::Validation("contract expires_at_ms must be unsigned integer".to_string())
        })?),
    };
    if let Some(exp) = expires_at_ms {
        if timestamp_ms >= exp {
            return Err(VNetworkError::Validation(
                "contract expires_at_ms must be in the future".to_string(),
            ));
        }
    }
    let min_auth_ratio_bps = match rules.get("min_auth_ratio_bps") {
        None | Some(serde_json::Value::Null) => 0,
        Some(v) => v.as_u64().ok_or_else(|| {
            VNetworkError::Validation("contract min_auth_ratio_bps must be unsigned integer".to_string())
        })?,
    };
    if min_auth_ratio_bps > 10_000 {
        return Err(VNetworkError::Validation(
            "contract min_auth_ratio_bps must be <= 10000".to_string(),
        ));
    }

    let mut state_data = BTreeMap::new();
    if let Some(obj) = rules.get("initial_state").and_then(|v| v.as_object()) {
        for (k, v) in obj {
            state_data.insert(k.clone(), v.clone());
        }
    }

    let nonce = (state.contracts.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("contract nonce overflow".to_string()))?;
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
        state_data,
        escrow_balances: BTreeMap::new(),
        execution_history: Vec::new(),
        execution_count: 0,
        active: true,
        created_at_ms: timestamp_ms,
        version: 1,
    };

    state.contracts.insert(contract_id.clone(), contract.clone());
    state.logical_clock = state
        .logical_clock
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
    let sequence = (state.events.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
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
        serde_json::to_value(&contract).map_err(|e| VNetworkError::Serialization(e.to_string()))?,
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
    reject_nondeterministic_keys(&args)?;

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

    let declared_action = if !contract.actions.is_empty() {
        let found = contract
            .actions
            .iter()
            .find(|a| a.get("name").and_then(|v| v.as_str()) == Some(action));
        if found.is_none() {
            return Err(VNetworkError::Validation(format!(
                "action `{action}` is not declared on contract `{}`",
                contract.name
            )));
        }
        found.cloned()
    } else {
        None
    };

    if let Some(req_args) = declared_action
        .as_ref()
        .and_then(|a| a.get("required_args"))
        .and_then(|v| v.as_array())
    {
        let args_obj = args.as_object().ok_or_else(|| {
            VNetworkError::Validation("contract action arguments must be an object".to_string())
        })?;
        for r in req_args {
            if let Some(key) = r.as_str() {
                if !args_obj.contains_key(key) {
                    return Err(VNetworkError::Validation(format!(
                        "missing required argument `{key}` for contract action `{action}`"
                    )));
                }
            }
        }
    }

    if let Some(rule_tok) = contract.rules.get("token").and_then(|v| v.as_str()) {
        if let Some(arg_tok) = args
            .get("token")
            .or_else(|| args.get("token_id"))
            .and_then(|v| v.as_str())
        {
            let expected = verify_token_exists(state, rule_tok)?.token_id.clone();
            let actual = verify_token_exists(state, arg_tok)?.token_id.clone();
            if expected != actual {
                return Err(VNetworkError::Validation(format!(
                    "contract `{}` restricts token to `{expected}`, got `{actual}`",
                    contract.name
                )));
            }
        }
    }

    let max_amt_rule = contract
        .rules
        .get("max_amount_per_op")
        .map(|v| parse_u128_arg(v, "max_amount_per_op"))
        .transpose()?;

    let norm_action = action.trim().to_ascii_lowercase();
    let escrow_id = contract_escrow_wallet_id(&contract.contract_id);
    let mut escrow_moves: Vec<serde_json::Value> = Vec::new();
    let mut touched_tokens: Vec<String> = Vec::new();

    // Work on cloned snapshot of balances to preserve strict atomicity on any failure
    let balances_backup = state.balances.clone();
    let exec_result: VResult<()> = (|| {
        let is_deposit = matches!(
            norm_action.as_str(),
            "deposit" | "fund" | "lock" | "escrow_deposit"
        ) || args.get("escrow_deposit").is_some_and(|v| !v.is_null());

        let is_release = matches!(
            norm_action.as_str(),
            "release" | "payout" | "withdraw" | "settle" | "escrow_release"
        ) || args.get("escrow_payout").is_some_and(|v| !v.is_null());

        if is_deposit {
            let dep_obj = args.get("escrow_deposit").unwrap_or(&args);
            let token_ref = dep_obj
                .get("token")
                .or_else(|| dep_obj.get("token_id"))
                .or_else(|| contract.rules.get("token"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    VNetworkError::Validation("contract escrow deposit requires `token`".to_string())
                })?;
            let from_ref = dep_obj
                .get("from_wallet")
                .or_else(|| dep_obj.get("from_wallet_id"))
                .or_else(|| dep_obj.get("wallet"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    VNetworkError::Validation(
                        "contract escrow deposit requires `from_wallet`".to_string(),
                    )
                })?;
            let amt_val = dep_obj
                .get("amount")
                .or_else(|| dep_obj.get("arg_0"))
                .ok_or_else(|| {
                    VNetworkError::Validation(
                        "contract escrow deposit requires `amount`".to_string(),
                    )
                })?;
            let amount = parse_u128_arg(amt_val, "amount")?;
            if amount == 0 {
                return Err(VNetworkError::Validation(
                    "contract escrow deposit amount must be > 0".to_string(),
                ));
            }
            if let Some(cap) = max_amt_rule {
                if amount > cap {
                    return Err(VNetworkError::Validation(format!(
                        "contract deposit amount {amount} exceeds max_amount_per_op {cap}"
                    )));
                }
            }
            let token = verify_token_exists(state, token_ref)?.clone();
            let from_wallet = verify_wallet_exists(state, from_ref)?.clone();
            if contract.rules.get("restrict_to_region").and_then(|v| v.as_bool()) == Some(true) {
                if let Some(ref rid) = contract.region_id {
                    if &from_wallet.region_id != rid {
                        return Err(VNetworkError::Authorization(format!(
                            "wallet `{}` outside contract region `{rid}`",
                            from_wallet.wallet_id
                        )));
                    }
                }
            }
            from_wallet.verify_permission(
                actor_pubkey,
                WalletPermission::ContractInteract,
                Some(&token.token_id),
                Some(amount),
                timestamp_ms,
            )?;
            from_wallet.verify_permission(
                actor_pubkey,
                WalletPermission::Send,
                Some(&token.token_id),
                Some(amount),
                timestamp_ms,
            )?;

            move_loan_escrow_balance(
                state,
                &token.token_id,
                &from_wallet.wallet_id,
                &escrow_id,
                amount,
                timestamp_ms,
            )?;
            let prev_escrow = contract
                .escrow_balances
                .get(&token.token_id)
                .copied()
                .unwrap_or(0);
            let next_escrow = prev_escrow.checked_add(amount).ok_or_else(|| {
                VNetworkError::Validation("contract escrow balance overflow".to_string())
            })?;
            contract
                .escrow_balances
                .insert(token.token_id.clone(), next_escrow);
            touched_tokens.push(token.token_id.clone());
            escrow_moves.push(serde_json::json!({
                "token_id": token.token_id,
                "from_wallet_id": from_wallet.wallet_id,
                "to_wallet_id": escrow_id,
                "amount": amount.to_string(),
            }));
        } else if is_release {
            let rel_obj = args.get("escrow_payout").unwrap_or(&args);
            let token_ref = rel_obj
                .get("token")
                .or_else(|| rel_obj.get("token_id"))
                .or_else(|| contract.rules.get("token"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    VNetworkError::Validation("contract escrow release requires `token`".to_string())
                })?;
            let to_ref = rel_obj
                .get("to_wallet")
                .or_else(|| rel_obj.get("to_wallet_id"))
                .or_else(|| rel_obj.get("wallet"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    VNetworkError::Validation(
                        "contract escrow release requires `to_wallet`".to_string(),
                    )
                })?;
            let token = verify_token_exists(state, token_ref)?.clone();
            let to_wallet = verify_wallet_exists(state, to_ref)?.clone();
            let avail = contract
                .escrow_balances
                .get(&token.token_id)
                .copied()
                .unwrap_or(0);
            let amount = match rel_obj.get("amount").or_else(|| rel_obj.get("arg_0")) {
                Some(v) => parse_u128_arg(v, "amount")?,
                None if norm_action == "settle" => avail,
                None => {
                    return Err(VNetworkError::Validation(
                        "contract escrow release requires `amount`".to_string(),
                    ))
                }
            };
            if amount == 0 {
                return Err(VNetworkError::Validation(
                    "contract escrow release amount must be > 0".to_string(),
                ));
            }
            if amount > avail {
                return Err(VNetworkError::InsufficientBalance(format!(
                    "contract `{}` escrow for `{}` has {avail}, requested {amount}",
                    contract.name, token.symbol
                )));
            }
            if let Some(cap) = max_amt_rule {
                if amount > cap {
                    return Err(VNetworkError::Validation(format!(
                        "contract release amount {amount} exceeds max_amount_per_op {cap}"
                    )));
                }
            }
            if contract.rules.get("restrict_to_region").and_then(|v| v.as_bool()) == Some(true) {
                if let Some(ref rid) = contract.region_id {
                    if &to_wallet.region_id != rid {
                        return Err(VNetworkError::Authorization(format!(
                            "destination wallet `{}` outside contract region `{rid}`",
                            to_wallet.wallet_id
                        )));
                    }
                }
            }
            to_wallet.verify_receive_allowed(&escrow_id, actor_pubkey, &[])?;

            move_loan_escrow_balance(
                state,
                &token.token_id,
                &escrow_id,
                &to_wallet.wallet_id,
                amount,
                timestamp_ms,
            )?;
            let next_escrow = avail - amount;
            if next_escrow == 0 {
                contract.escrow_balances.remove(&token.token_id);
            } else {
                contract
                    .escrow_balances
                    .insert(token.token_id.clone(), next_escrow);
            }
            touched_tokens.push(token.token_id.clone());
            escrow_moves.push(serde_json::json!({
                "token_id": token.token_id,
                "from_wallet_id": escrow_id,
                "to_wallet_id": to_wallet.wallet_id,
                "amount": amount.to_string(),
            }));
        } else if matches!(norm_action.as_str(), "deactivate" | "close") {
            let nonzero_escrow: u128 = contract.escrow_balances.values().copied().sum();
            if nonzero_escrow > 0 {
                return Err(VNetworkError::Validation(
                    "cannot close contract while escrow balances remain non-zero".to_string(),
                ));
            }
            contract.active = false;
        }

        // Apply explicit deterministic state transitions on state_data
        if let Some(updates) = args.get("state_updates").and_then(|v| v.as_object()) {
            for (k, v) in updates {
                contract.state_data.insert(k.clone(), v.clone());
            }
        } else if norm_action == "increment" {
            let key = args
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or("counter")
                .to_string();
            let delta = args
                .get("delta")
                .or_else(|| args.get("amount"))
                .map(|v| parse_u128_arg(v, "delta"))
                .transpose()?
                .unwrap_or(1);
            let cur = contract
                .state_data
                .get(&key)
                .map(|v| parse_u128_arg(v, &key))
                .transpose()?
                .unwrap_or(0);
            let next = cur
                .checked_add(delta)
                .ok_or_else(|| VNetworkError::Validation("contract state counter overflow".to_string()))?;
            contract
                .state_data
                .insert(key, serde_json::json!(next.to_string()));
        } else if matches!(norm_action.as_str(), "set_state" | "update_state") {
            let obj = args.as_object().ok_or_else(|| {
                VNetworkError::Validation("set_state requires object arguments".to_string())
            })?;
            if obj.is_empty() {
                return Err(VNetworkError::Validation(
                    "set_state requires at least one state field".to_string(),
                ));
            }
            for (k, v) in obj {
                contract.state_data.insert(k.clone(), v.clone());
            }
        } else if let Some(obj) = args.as_object() {
            for (k, v) in obj {
                if !matches!(k.as_str(), "escrow_deposit" | "escrow_payout" | "state_updates") {
                    contract.state_data.insert(k.clone(), v.clone());
                }
            }
        }

        contract
            .state_data
            .insert("last_action".to_string(), serde_json::json!(action));
        contract.state_data.insert(
            "last_executed_at_ms".to_string(),
            serde_json::json!(timestamp_ms),
        );

        for tid in &touched_tokens {
            if !verify_token_supply_conservation(state, tid)? {
                return Err(VNetworkError::Validation(
                    "token supply conservation check failed in contract execution".to_string(),
                ));
            }
        }
        Ok(())
    })();

    if let Err(err) = exec_result {
        state.balances = balances_backup;
        return Err(err);
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

    state.logical_clock = state
        .logical_clock
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
    let sequence = (state.events.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
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
            "escrow_moves": escrow_moves,
            "execution_count": contract.execution_count,
            "contract": contract,
        }),
        before_hash,
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((contract, event))
}
