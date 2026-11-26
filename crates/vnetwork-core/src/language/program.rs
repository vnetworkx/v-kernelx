use crate::authorization::record_nonce_and_request;
use crate::events::events_for_entity;
use crate::ledger::build_ledger_proof_report;
use crate::reconstruction::reconstruct_entity;
use crate::state::{GenesisConfig, NetworkLedgerState};
use crate::transition::apply_network_operation_with_genesis;
use std::collections::BTreeMap;
use v_langx::compiler::{CompiledOp, CompiledProgram};
use vnetwork_types::*;

#[derive(Debug, Clone)]
pub struct StagedProgramExecution {
    pub staged_state: NetworkLedgerState,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub generated_events: Vec<LedgerEvent>,
    pub created_entities: Vec<CreatedEntitySummary>,
    pub outputs: Vec<String>,
    pub ops_executed: usize,
}

#[derive(Debug, Clone)]
pub struct ProgramFailure {
    pub failed_operation_index: usize,
    pub error: VNetworkError,
    pub lifecycle_status: ProgramLifecycleStatus,
}

pub fn execute_compiled_program_staged(
    base_state: &NetworkLedgerState,
    genesis: &GenesisConfig,
    compiled: &CompiledProgram,
    actor_pubkey: &str,
    timestamp_ms: u64,
    nonce_binding: Option<(&str, &str, u64)>,
) -> Result<StagedProgramExecution, ProgramFailure> {
    let pre_state_root = base_state.compute_state_root().map_err(|e| ProgramFailure {
        failed_operation_index: 0,
        error: e,
        lifecycle_status: ProgramLifecycleStatus::Failed,
    })?;

    let mut staged = base_state.clone();
    let mut aliases: BTreeMap<String, String> = BTreeMap::new();
    let mut generated_events = Vec::new();
    let mut created_entities = Vec::new();
    let mut outputs = Vec::new();

    for (idx, op) in compiled.ops.iter().enumerate() {
        match execute_single_compiled_op(
            &mut staged,
            genesis,
            op,
            &mut aliases,
            actor_pubkey,
            timestamp_ms,
        ) {
            Ok((mut evs, mut created, mut outs)) => {
                generated_events.append(&mut evs);
                created_entities.append(&mut created);
                outputs.append(&mut outs);
            }
            Err(err) => {
                let status = match &err {
                    VNetworkError::Authorization(_) | VNetworkError::Signature(_) => {
                        ProgramLifecycleStatus::Rejected
                    }
                    VNetworkError::DimensionInvariant(_)
                    | VNetworkError::ProfileMismatch(_) => ProgramLifecycleStatus::Rejected,
                    _ => ProgramLifecycleStatus::Failed,
                };
                return Err(ProgramFailure {
                    failed_operation_index: idx,
                    error: err,
                    lifecycle_status: status,
                });
            }
        }
    }

    if let Some((actor, req_id, nonce)) = nonce_binding {
        record_nonce_and_request(&mut staged, req_id, actor, nonce);
    }

    staged.height = base_state.height.checked_add(1).ok_or_else(|| ProgramFailure {
        failed_operation_index: compiled.ops.len().saturating_sub(1),
        error: VNetworkError::Validation("height overflow".to_string()),
        lifecycle_status: ProgramLifecycleStatus::Failed,
    })?;
    let post_state_root = staged.compute_state_root().map_err(|e| ProgramFailure {
        failed_operation_index: compiled.ops.len().saturating_sub(1),
        error: e,
        lifecycle_status: ProgramLifecycleStatus::Failed,
    })?;

    Ok(StagedProgramExecution {
        staged_state: staged,
        pre_state_root,
        post_state_root,
        generated_events,
        created_entities,
        outputs,
        ops_executed: compiled.ops.len(),
    })
}

fn resolve_alias(aliases: &BTreeMap<String, String>, key: &str) -> String {
    aliases.get(key).cloned().unwrap_or_else(|| key.to_string())
}

fn field_str(fields: &serde_json::Value, key: &str) -> Option<String> {
    fields.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

fn field_u128(fields: &serde_json::Value, key: &str) -> Option<u128> {
    match fields.get(key) {
        Some(serde_json::Value::Number(n)) => n.as_u64().map(|u| u as u128),
        Some(serde_json::Value::String(s)) => s.replace('_', "").parse::<u128>().ok(),
        _ => None,
    }
}

fn parse_u128_str(s: &str) -> VResult<u128> {
    s.trim()
        .replace('_', "")
        .parse::<u128>()
        .map_err(|_| VNetworkError::Validation(format!("expected positive integer, got `{s}`")))
}

fn execute_single_compiled_op(
    state: &mut NetworkLedgerState,
    genesis: &GenesisConfig,
    op: &CompiledOp,
    aliases: &mut BTreeMap<String, String>,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(Vec<LedgerEvent>, Vec<CreatedEntitySummary>, Vec<String>)> {
    let mut events = Vec::new();
    let mut created = Vec::new();
    let mut outs = Vec::new();

    match op.op_kind.as_str() {
        "NETWORK_CONNECT" | "NETWORK_TARGET" => {
            let target_net = op
                .params
                .get("network_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if target_net != state.network_id {
                return Err(VNetworkError::ProfileMismatch(format!(
                    "program targets network `{target_net}`, connected node is `{}`",
                    state.network_id
                )));
            }
            outs.push(format!("network verified: {}", state.network_id));
        }
        "PARTICIPANT_JOIN" => {
            crate::identity::require_participant_scope_at(
                state,
                actor_pubkey,
                ParticipationLevel::Network,
                None,
                timestamp_ms,
            )?;
            let pname = op
                .params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("participant");
            outs.push(format!("participant scope verified: {pname}"));
        }
        "SPACE_CREATE" => {
            let sym = op
                .params
                .get("space_name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| VNetworkError::Validation("missing space_name".to_string()))?;
            let ghost = op
                .params
                .get("ghost")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let fields = op.params.get("fields").cloned().unwrap_or_default();
            let display_name = field_str(&fields, "name").unwrap_or_else(|| sym.to_string());
            let visibility = field_str(&fields, "visibility").unwrap_or_else(|| "public".to_string());

            let net_op = NetworkOperation::CreateSpace {
                name: display_name,
                visibility,
                ghost,
            };
            let outcome = apply_network_operation_with_genesis(state, genesis, &net_op, actor_pubkey, timestamp_ms)?;
            if let Some(ent) = outcome.created_entities.first() {
                aliases.insert(sym.to_string(), ent.id.clone());
            }
            events.extend(outcome.events);
            created.extend(outcome.created_entities);
            outs.extend(outcome.outputs);
        }
        "REGION_CREATE" => {
            let sym = op
                .params
                .get("region_symbol")
                .and_then(|v| v.as_str())
                .ok_or_else(|| VNetworkError::Validation("missing region_symbol".to_string()))?;
            let space_ref = op
                .params
                .get("space")
                .and_then(|v| v.as_str())
                .ok_or_else(|| VNetworkError::Validation("missing parent space".to_string()))?;
            let space_id = resolve_alias(aliases, space_ref);
            let ghost = op
                .params
                .get("ghost")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let fields = op.params.get("fields").cloned().unwrap_or_default();
            let name = field_str(&fields, "name").unwrap_or_else(|| sym.to_string());
            let prefix = field_str(&fields, "prefix");
            let title = field_str(&fields, "title");
            let visibility = field_str(&fields, "visibility").unwrap_or_else(|| "public".to_string());
            let section = field_u128(&fields, "section").unwrap_or(1) as u64;

            let net_op = NetworkOperation::CreateRegion {
                space_id,
                name,
                prefix,
                title,
                visibility,
                section,
                ghost,
            };
            let outcome = apply_network_operation_with_genesis(state, genesis, &net_op, actor_pubkey, timestamp_ms)?;
            if let Some(ent) = outcome.created_entities.first() {
                aliases.insert(sym.to_string(), ent.id.clone());
            }
            events.extend(outcome.events);
            created.extend(outcome.created_entities);
            outs.extend(outcome.outputs);
        }
        "WALLET_CREATE" => {
            let sym = op
                .params
                .get("wallet_symbol")
                .and_then(|v| v.as_str())
                .ok_or_else(|| VNetworkError::Validation("missing wallet_symbol".to_string()))?;
            let region_ref = op
                .params
                .get("region")
                .and_then(|v| v.as_str())
                .ok_or_else(|| VNetworkError::Validation("missing parent region".to_string()))?;
            let region_id = resolve_alias(aliases, region_ref);
            let ghost = op
                .params
                .get("ghost")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let fields = op.params.get("fields").cloned().unwrap_or_default();
            let name = field_str(&fields, "name").unwrap_or_else(|| sym.to_string());
            let approval_threshold = field_u128(&fields, "approval_threshold").map(|v| v as u16);

            let net_op = NetworkOperation::CreateWallet {
                region_id,
                name,
                ghost,
                approval_threshold,
            };
            let outcome = apply_network_operation_with_genesis(state, genesis, &net_op, actor_pubkey, timestamp_ms)?;
            if let Some(ent) = outcome.created_entities.first() {
                aliases.insert(sym.to_string(), ent.id.clone());
            }
            events.extend(outcome.events);
            created.extend(outcome.created_entities);
            outs.extend(outcome.outputs);
        }
        "WALLET_AUTHORIZE" | "WALLET_BIND" => {
            let wallet_ref = op
                .params
                .get("wallet")
                .or_else(|| op.params.get("name"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| VNetworkError::Validation("missing wallet reference".to_string()))?;
            let wallet_id = resolve_alias(aliases, wallet_ref);
            let pubkey = op
                .params
                .get("public_key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| VNetworkError::Validation("missing public_key".to_string()))?
                .to_string();
            let role = op
                .params
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("signer")
                .to_string();
            let fields = op.params.get("fields").cloned().unwrap_or_default();
            let permissions = fields
                .get("permissions")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let allowed_token_ids = fields
                .get("allowed_token_ids")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let max_amount_per_op = field_u128(&fields, "max_amount_per_op");
            let expires_at_ms = field_u128(&fields, "expires_at_ms").map(|v| v as u64);
            let pop_nonce = field_str(&fields, "pop_nonce");
            let pop_signature = field_str(&fields, "pop_signature");
            let participant_identity = field_str(&fields, "participant_identity");

            let net_op = NetworkOperation::AuthorizeWalletKey {
                wallet_id,
                authorized_pubkey: pubkey,
                role,
                permissions,
                allowed_token_ids,
                max_amount_per_op,
                expires_at_ms,
                pop_nonce,
                pop_signature,
                participant_identity,
            };
            let outcome = apply_network_operation_with_genesis(state, genesis, &net_op, actor_pubkey, timestamp_ms)?;
            events.extend(outcome.events);
            outs.extend(outcome.outputs);
        }
        "TOKEN_CREATE" => {
            let sym = op
                .params
                .get("token_symbol")
                .and_then(|v| v.as_str())
                .ok_or_else(|| VNetworkError::Validation("missing token_symbol".to_string()))?;
            let wallet_ref = op
                .params
                .get("wallet")
                .and_then(|v| v.as_str())
                .ok_or_else(|| VNetworkError::Validation("missing parent wallet".to_string()))?;
            let wallet_id = resolve_alias(aliases, wallet_ref);
            let ghost = op
                .params
                .get("ghost")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let fields = op.params.get("fields").cloned().unwrap_or_default();
            let name = field_str(&fields, "name").unwrap_or_else(|| sym.to_string());
            let symbol = field_str(&fields, "symbol").unwrap_or_else(|| sym.to_ascii_uppercase());
            let dims = field_u128(&fields, "dimensions").unwrap_or(3) as usize;
            if dims != 3 {
                return Err(VNetworkError::DimensionInvariant(format!(
                    "token dimensions must be 3, got {dims}"
                )));
            }

            let (initial_supply, auth_ratio_au, energy) =
                if let Some(arr) = fields.get("vector").and_then(|v| v.as_array()) {
                    if arr.len() != 3 {
                        return Err(VNetworkError::DimensionInvariant(
                            "token vector must have 3 elements [token, authratio(au), energy]"
                                .to_string(),
                        ));
                    }
                    let parse_elem = |val: &serde_json::Value, idx: usize| -> VResult<u128> {
                        val.as_str()
                            .and_then(|s| s.replace('_', "").parse::<u128>().ok())
                            .or_else(|| val.as_u64().map(|u| u as u128))
                            .ok_or_else(|| {
                                VNetworkError::Validation(format!(
                                    "invalid token vector integer at dimension {idx}"
                                ))
                            })
                    };
                    (
                        parse_elem(&arr[0], 0)?,
                        parse_elem(&arr[1], 1)?,
                        parse_elem(&arr[2], 2)?,
                    )
                } else {
                    let s = field_u128(&fields, "supply")
                        .or_else(|| field_u128(&fields, "initial_supply"))
                        .ok_or_else(|| {
                            VNetworkError::Validation(
                                "token create requires explicit `vector = [token, authratio, energy]` or `initial_supply`"
                                    .to_string(),
                            )
                        })?;
                    let au = field_u128(&fields, "authratio")
                        .or_else(|| field_u128(&fields, "auth_ratio_au"))
                        .unwrap_or(0);
                    let en = field_u128(&fields, "energy").unwrap_or(0);
                    (s, au, en)
                };

            let unlimited_supply = fields
                .get("unlimited_supply")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let max_supply = if let Some(m) = field_u128(&fields, "max_supply") {
                m
            } else if unlimited_supply {
                0
            } else {
                initial_supply
            };
            let drain_bps = field_u128(&fields, "drain_bps").unwrap_or(0) as u16;
            let purpose = field_str(&fields, "purpose").unwrap_or_else(|| "network".to_string());
            let external_monetary_value =
                field_str(&fields, "external_monetary_value").unwrap_or_else(|| "None".to_string());

            let net_op = NetworkOperation::CreateToken {
                wallet_id,
                name,
                symbol,
                initial_supply,
                max_supply,
                unlimited_supply,
                auth_ratio_au,
                energy,
                drain_bps,
                purpose,
                external_monetary_value,
                ghost,
            };
            let outcome = apply_network_operation_with_genesis(state, genesis, &net_op, actor_pubkey, timestamp_ms)?;
            if let Some(ent) = outcome.created_entities.first() {
                aliases.insert(sym.to_string(), ent.id.clone());
            }
            events.extend(outcome.events);
            created.extend(outcome.created_entities);
            outs.extend(outcome.outputs);
        }
        "TOKEN_TRANSFER" => {
            let token_ref = op
                .params
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if token_ref.trim().is_empty() {
                return Err(VNetworkError::Validation(
                    "transfer requires explicit non-empty token identifier".to_string(),
                ));
            }
            let from_ref = op
                .params
                .get("from")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let to_ref = op
                .params
                .get("to")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let amt_str = op
                .params
                .get("amount")
                .and_then(|v| v.as_str())
                .unwrap_or("0");
            let amount = parse_u128_str(amt_str)?;
            if op.params.get("drain").is_some_and(|v| !v.is_null()) {
                return Err(VNetworkError::Validation(
                    "sender-supplied `drain` override on `TOKEN_TRANSFER` is forbidden; drain is strictly protocol-determined from transfer scope"
                        .to_string(),
                ));
            }
            let token_id = resolve_alias(aliases, token_ref);
            let from_wallet_id = resolve_alias(aliases, from_ref);
            let to_wallet_id = resolve_alias(aliases, to_ref);

            let net_op = NetworkOperation::TransferToken {
                token_id,
                from_wallet_id,
                to_wallet_id,
                amount,
                cosignatures: Vec::new(),
            };
            let outcome = apply_network_operation_with_genesis(state, genesis, &net_op, actor_pubkey, timestamp_ms)?;
            events.extend(outcome.events);
            outs.extend(outcome.outputs);
        }
        "TOKEN_RECEIVE" => {
            let token_ref = op.params.get("token").and_then(|v| v.as_str()).unwrap_or("");
            let wallet_ref = op.params.get("wallet").and_then(|v| v.as_str()).unwrap_or("");
            let source_ref = op.params.get("source").and_then(|v| v.as_str());
            let amount = parse_u128_str(op.params.get("amount").and_then(|v| v.as_str()).unwrap_or("0"))?;
            let token_id = resolve_alias(aliases, token_ref);
            let to_wallet_id = resolve_alias(aliases, wallet_ref);
            if let Some(src) = source_ref {
                let from_wallet_id = resolve_alias(aliases, src);
                let net_op = NetworkOperation::TransferToken {
                    token_id,
                    from_wallet_id,
                    to_wallet_id,
                    amount,
                    cosignatures: Vec::new(),
                };
                let outcome = apply_network_operation_with_genesis(state, genesis, &net_op, actor_pubkey, timestamp_ms)?;
                events.extend(outcome.events);
                outs.extend(outcome.outputs);
            } else {
                let tok = crate::hierarchy::verify_token_exists(state, &token_id)?;
                let wal = crate::hierarchy::verify_wallet_exists(state, &to_wallet_id)?;
                let bal = state
                    .get_balance(&tok.token_id, &wal.wallet_id)
                    .map(|b| b.vector.token)
                    .unwrap_or(0);
                outs.push(format!(
                    "receive verified: wallet={} token={} balance={} expected_at_least={}",
                    wal.name, tok.symbol, bal, amount
                ));
            }
        }
        "TOKEN_DRAIN" => {
            let token_ref = op.params.get("target").and_then(|v| v.as_str()).unwrap_or("");
            let wallet_ref = op.params.get("wallet").and_then(|v| v.as_str()).unwrap_or("");
            let amount = parse_u128_str(op.params.get("amount").and_then(|v| v.as_str()).unwrap_or("0"))?;
            let token_id = resolve_alias(aliases, token_ref);
            let wallet_id = if wallet_ref.trim().is_empty() {
                crate::hierarchy::verify_token_exists(state, &token_id)?
                    .wallet_id
                    .clone()
            } else {
                resolve_alias(aliases, wallet_ref)
            };
            let net_op = NetworkOperation::DrainToken {
                token_id,
                wallet_id,
                amount,
            };
            let outcome = apply_network_operation_with_genesis(state, genesis, &net_op, actor_pubkey, timestamp_ms)?;
            events.extend(outcome.events);
            outs.extend(outcome.outputs);
        }
        "CONTRACT_CREATE" => {
            let name = op
                .params
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| VNetworkError::Validation("missing contract name".to_string()))?;
            let fields = op.params.get("fields").cloned().unwrap_or_default();
            let region_id = field_str(&fields, "region").map(|r| resolve_alias(aliases, &r));
            let actions = op
                .params
                .get("actions")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let net_op = NetworkOperation::CreateContract {
                name: name.to_string(),
                region_id,
                rules: fields,
                actions,
            };
            let outcome = apply_network_operation_with_genesis(state, genesis, &net_op, actor_pubkey, timestamp_ms)?;
            if let Some(ent) = outcome.created_entities.first() {
                aliases.insert(name.to_string(), ent.id.clone());
            }
            events.extend(outcome.events);
            created.extend(outcome.created_entities);
            outs.extend(outcome.outputs);
        }
        "CONTRACT_EXECUTE" => {
            let contract_ref = op
                .params
                .get("contract")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let action = op
                .params
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let args = op.params.get("args").cloned().unwrap_or_default();
            let contract_id = resolve_alias(aliases, contract_ref);
            let net_op = NetworkOperation::ExecuteContract {
                contract_id,
                action: action.to_string(),
                args,
            };
            let outcome = apply_network_operation_with_genesis(state, genesis, &net_op, actor_pubkey, timestamp_ms)?;
            events.extend(outcome.events);
            outs.extend(outcome.outputs);
        }
        "LOAN_CREATE" => {
            let name = op
                .params
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| VNetworkError::Validation("missing loan name".to_string()))?;
            let fields = op.params.get("fields").cloned().unwrap_or_default();
            let token_ref = field_str(&fields, "token")
                .ok_or_else(|| VNetworkError::Validation("loan requires `token` field".to_string()))?;
            let lender_ref = field_str(&fields, "lender")
                .ok_or_else(|| VNetworkError::Validation("loan requires `lender` field".to_string()))?;
            let borrower_ref = field_str(&fields, "borrower")
                .ok_or_else(|| VNetworkError::Validation("loan requires `borrower` field".to_string()))?;
            let principal = field_u128(&fields, "principal").unwrap_or(0);
            let collateral = field_u128(&fields, "collateral").unwrap_or(0);
            let interest_bps = field_u128(&fields, "interest_bps").unwrap_or(0) as u16;
            let maturity_at_ms = field_u128(&fields, "maturity_at_ms").map(|v| v as u64);

            let net_op = NetworkOperation::CreateLoan {
                name: name.to_string(),
                token_id: resolve_alias(aliases, &token_ref),
                lender_wallet_id: resolve_alias(aliases, &lender_ref),
                borrower_wallet_id: resolve_alias(aliases, &borrower_ref),
                principal,
                collateral,
                interest_bps,
                maturity_at_ms,
            };
            let outcome = apply_network_operation_with_genesis(state, genesis, &net_op, actor_pubkey, timestamp_ms)?;
            if let Some(ent) = outcome.created_entities.first() {
                aliases.insert(name.to_string(), ent.id.clone());
            }
            events.extend(outcome.events);
            created.extend(outcome.created_entities);
            outs.extend(outcome.outputs);
        }
        "LOAN_EXECUTE" => {
            let loan_ref = op.params.get("loan").and_then(|v| v.as_str()).unwrap_or("");
            let action = op.params.get("action").and_then(|v| v.as_str()).unwrap_or("");
            let args = op.params.get("args").cloned().unwrap_or_default();
            let amount = field_u128(&args, "amount")
                .or_else(|| field_u128(&args, "arg_0"))
                .unwrap_or(0);
            let net_op = NetworkOperation::ExecuteLoan {
                loan_id: resolve_alias(aliases, loan_ref),
                action: action.to_string(),
                amount,
            };
            let outcome = apply_network_operation_with_genesis(state, genesis, &net_op, actor_pubkey, timestamp_ms)?;
            events.extend(outcome.events);
            outs.extend(outcome.outputs);
        }
        "QUERY" => {
            let expr = op.params.get("expr").and_then(|v| v.as_str()).unwrap_or("network");
            let root = state.compute_state_root()?;
            outs.push(format!(
                "query({expr}): height={} spaces={} regions={} wallets={} tokens={} root={root}",
                state.height,
                state.spaces.len(),
                state.regions.len(),
                state.wallets.len(),
                state.tokens.len()
            ));
        }
        "HISTORY_INSPECT" => {
            let target = op.params.get("expr").and_then(|v| v.as_str()).unwrap_or("");
            let resolved = resolve_alias(aliases, target);
            let evs = events_for_entity(state, None, &resolved);
            outs.push(format!("history({resolved}): {} events", evs.len()));
        }
        "PROOF_VERIFY" => {
            let report = build_ledger_proof_report(state)?;
            outs.push(format!(
                "proof verified: chain_valid={} events={} state_root={}",
                report.chain_valid, report.event_count, report.state_root
            ));
        }
        "RECONSTRUCT" => {
            let target = op.params.get("target").and_then(|v| v.as_str()).unwrap_or("");
            let resolved = resolve_alias(aliases, target);
            let kind = if state.spaces.contains_key(&resolved) {
                "space"
            } else if state.regions.contains_key(&resolved) {
                "region"
            } else if state.wallets.contains_key(&resolved) {
                "wallet"
            } else if state.tokens.contains_key(&resolved) {
                "token"
            } else if state.contracts.contains_key(&resolved) {
                "contract"
            } else if state.loans.contains_key(&resolved) {
                "loan"
            } else {
                return Err(VNetworkError::NotFound(format!(
                    "reconstruct target `{resolved}` not found in spaces, regions, wallets, tokens, contracts, or loans"
                )));
            };
            let report = reconstruct_entity(state, genesis, kind, &resolved)?;
            outs.push(format!(
                "reconstruct({kind}:{resolved}): verified={} hash={}",
                report.verified, report.reconstructed_hash
            ));
        }
        "CERTIFY" => {
            let target = op.params.get("target").and_then(|v| v.as_str()).unwrap_or("");
            let ratio = op
                .params
                .get("auth_ratio")
                .and_then(|v| v.as_str())
                .unwrap_or("0.8000");
            outs.push(format!("certify({target}): auth_ratio={ratio}"));
        }
        "EVENT_RECORD" => {
            let expr = op.params.get("expr").and_then(|v| v.as_str()).unwrap_or("record");
            state.logical_clock = state
                .logical_clock
                .checked_add(1)
                .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
            let sequence = (state.events.len() as u64)
                .checked_add(1)
                .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
            let parents = state.latest_event_hash().into_iter().collect();
            let ev = LedgerEvent::build(
                sequence,
                parents,
                &state.network_id,
                "record",
                format!("rec_{sequence}"),
                "VX_RECORD",
                actor_pubkey,
                state.logical_clock,
                timestamp_ms,
                serde_json::json!({ "expr": expr }),
                "",
                blake3_hex(expr.as_bytes()),
            )?;
            state.events.push(ev.clone());
            events.push(ev);
            outs.push(format!("event recorded: {expr}"));
        }
        other => {
            return Err(VNetworkError::Validation(format!(
                "compiled op `{other}` is not executable in authoritative kernel"
            )));
        }
    }

    Ok((events, created, outs))
}
