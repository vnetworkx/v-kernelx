use crate::ast::VectorType;
use crate::error::{RuntimeError, RuntimeErrorKind};
use crate::event::{canonical_event_payload, derive_event_hash, derive_signature, derive_timestamp, Event};
use crate::state::{CertificationState, ContractState, NetworkState, ProjectionState, VectorState, WalletState};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelOp {
    CreateVector {
        name: String,
        vector_type: VectorType,
        components: Vec<u128>,
    },
    BindWallet {
        name: String,
        public_key: String,
    },
    Certify {
        target: String,
        context: String,
        auth_ratio: String,
        certified: bool,
    },
    Transfer {
        source: String,
        destination: String,
        amount: u128,
        drain: u128,
        policy: Option<String>,
    },
    Drain {
        target: String,
        amount: u128,
    },
    Project {
        source: String,
        environment: String,
        amount: u128,
        policy: Option<String>,
        projection_id: String,
    },
    Reconstruct {
        target: String,
        projection_id: String,
    },
    Query {
        expr: String,
    },
    Record {
        expr: String,
    },
    Contract {
        name: String,
        actions: Vec<String>,
    },
    ContractAction {
        contract: String,
        action: String,
        args: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelResult {
    pub output: Option<String>,
    pub record: Option<Event>,
}

pub fn type_compatible_for_transfer(source: VectorType, destination: VectorType) -> bool {
    matches!(
        (source, destination),
        (VectorType::Free, _)
            | (VectorType::Position, VectorType::Position)
            | (VectorType::Bound, VectorType::Bound)
            | (VectorType::Spatial, VectorType::Spatial)
            | (VectorType::Unit, VectorType::Unit)
            | (VectorType::Zero, VectorType::Zero)
    )
}

fn component_allocation(components: &[u128], amount: u128) -> Vec<u128> {
    let total: u128 = components.iter().copied().sum();
    if total == 0 || amount == 0 {
        return vec![0; components.len()];
    }

    let mut floors = Vec::with_capacity(components.len());
    let mut remainders = Vec::with_capacity(components.len());

    let mut allocated = 0u128;
    for (idx, &component) in components.iter().enumerate() {
        let numerator = amount.saturating_mul(component);
        let floor = numerator / total;
        let rem = numerator % total;
        floors.push(floor);
        remainders.push((idx, rem));
        allocated = allocated.saturating_add(floor);
    }

    let mut remaining = amount.saturating_sub(allocated);
    remainders.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    for (idx, _) in remainders {
        if remaining == 0 {
            break;
        }
        floors[idx] = floors[idx].saturating_add(1);
        remaining -= 1;
    }

    floors
}

fn vector_subtract(components: &[u128], amount: u128) -> Result<Vec<u128>, RuntimeError> {
    let allocation = component_allocation(components, amount);
    let mut out = Vec::with_capacity(components.len());
    for (component, dec) in components.iter().zip(allocation.iter()) {
        if component < dec {
            return Err(RuntimeError::new(RuntimeErrorKind::InvalidOperation(
                "allocation exceeded source balance".to_string(),
            )));
        }
        out.push(component - dec);
    }
    Ok(out)
}

fn vector_add_strict(components: &[u128], addition: &[u128]) -> Result<Vec<u128>, RuntimeError> {
    if components.len() != addition.len() {
        return Err(RuntimeError::new(RuntimeErrorKind::InvalidOperation(
            "vector dimensions must match".to_string(),
        )));
    }
    Ok(components
        .iter()
        .zip(addition.iter())
        .map(|(a, b)| a.saturating_add(*b))
        .collect())
}

fn canonical_record(
    state: &mut NetworkState,
    entity_id: &str,
    region_id: &str,
    operation: &str,
    v_before: &[u128],
    v_after: &[u128],
    params: &str,
    auth_ratio: &str,
    certified: bool,
    actor_pk: &str,
    proof: &str,
) -> Event {
    let eid = format!("evt_{:016x}", state.events.len() + 1);
    let logical_clock = state.next_clock();
    let timestamp = derive_timestamp(logical_clock);
    let parent_hashes = state.last_event_hash.clone().into_iter().collect::<Vec<_>>();
    let provisional_signature = derive_signature(
        &format!("{eid}:{actor_pk}:{logical_clock}"),
        actor_pk,
        logical_clock,
    );
    let payload = canonical_event_payload(
        &eid,
        &parent_hashes,
        region_id,
        entity_id,
        v_before,
        v_after,
        operation,
        params,
        auth_ratio,
        certified,
        actor_pk,
        proof,
        logical_clock,
        timestamp,
        &provisional_signature,
    );
    let event_hash = derive_event_hash(&payload);
    let signature = derive_signature(&event_hash, actor_pk, logical_clock);
    let final_payload = canonical_event_payload(
        &eid,
        &parent_hashes,
        region_id,
        entity_id,
        v_before,
        v_after,
        operation,
        params,
        auth_ratio,
        certified,
        actor_pk,
        proof,
        logical_clock,
        timestamp,
        &signature,
    );
    let event_hash = derive_event_hash(&final_payload);

    Event {
        eid,
        parent_hashes,
        region_id: region_id.to_string(),
        entity_id: entity_id.to_string(),
        v_before: v_before.to_vec(),
        v_after: v_after.to_vec(),
        operation: operation.to_string(),
        params: params.to_string(),
        auth_ratio: auth_ratio.to_string(),
        certified,
        actor_pk: actor_pk.to_string(),
        proof: proof.to_string(),
        logical_clock,
        timestamp,
        signature,
        event_hash,
    }
}

fn push_state_event(
    state: &mut NetworkState,
    entity_id: &str,
    region_id: &str,
    operation: &str,
    v_before: &[u128],
    v_after: &[u128],
    params: &str,
    auth_ratio: &str,
    certified: bool,
    actor_pk: &str,
    proof: &str,
) -> Event {
    let event = canonical_record(
        state,
        entity_id,
        region_id,
        operation,
        v_before,
        v_after,
        params,
        auth_ratio,
        certified,
        actor_pk,
        proof,
    );
    state.push_event(event.clone());
    event
}

pub fn execute_kernel_op(state: &mut NetworkState, op: KernelOp) -> Result<KernelResult, RuntimeError> {
    match op {
        KernelOp::CreateVector { name, vector_type, components } => {
            if state.vectors.contains_key(&name) {
                return Err(RuntimeError::new(RuntimeErrorKind::DuplicateSymbol(name)));
            }
            let vector = VectorState {
                name: name.clone(),
                vector_type,
                components: components.clone(),
                owner: None,
                meta: BTreeMap::new(),
                certification: CertificationState::Pending,
                auth_ratio: "0.0000".to_string(),
            };
            state.vectors.insert(name.clone(), vector);
            let event = push_state_event(
                state,
                &name,
                "global",
                "CREATE",
                &[],
                &components,
                &format!("type={}", vector_type.as_str()),
                "1.0000",
                true,
                "kernel",
                "origin-proof",
            );
            Ok(KernelResult { output: Some(format!("created {name}")), record: Some(event) })
        }
        KernelOp::BindWallet { name, public_key } => {
            if state.wallets.contains_key(&name) {
                return Err(RuntimeError::new(RuntimeErrorKind::DuplicateSymbol(name)));
            }
            let wallet = WalletState { name: name.clone(), public_key: public_key.clone(), meta: BTreeMap::new() };
            state.wallets.insert(name.clone(), wallet);
            let event = push_state_event(
                state,
                &name,
                "global",
                "BIND",
                &[],
                &[],
                &format!("public_key={public_key}"),
                "1.0000",
                true,
                &public_key,
                "wallet-binding",
            );
            Ok(KernelResult { output: Some(format!("wallet {name} bound")), record: Some(event) })
        }
        KernelOp::Certify { target, context, auth_ratio, certified } => {
            let before;
            let after;
            {
                let vector = state
                    .vectors
                    .get_mut(&target)
                    .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::UnknownSymbol(target.clone())))?;
                before = vector.components.clone();
                after = vector.components.clone();
                vector.auth_ratio = auth_ratio.clone();
                vector.certification = if certified {
                    CertificationState::Certified
                } else {
                    CertificationState::Uncertified
                };
            }
            let event = push_state_event(
                state,
                &target,
                "global",
                "CERTIFY",
                &before,
                &after,
                &context,
                auth_ratio.as_str(),
                certified,
                "kernel",
                "certification-proof",
            );
            Ok(KernelResult { output: Some(format!("certify {target} -> {certified}")), record: Some(event) })
        }
        KernelOp::Transfer { source, destination, amount, drain, policy } => {
            let (source_type, dest_type, before_source, before_dest) = {
                let source_vec = state
                    .vectors
                    .get(&source)
                    .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::UnknownSymbol(source.clone())))?;
                let dest_vec = state
                    .vectors
                    .get(&destination)
                    .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::UnknownSymbol(destination.clone())))?;
                (
                    source_vec.vector_type,
                    dest_vec.vector_type,
                    source_vec.components.clone(),
                    dest_vec.components.clone(),
                )
            };

            if !type_compatible_for_transfer(source_type, dest_type) {
                return Err(RuntimeError::new(RuntimeErrorKind::TypeMismatch {
                    expected: source_type.as_str().to_string(),
                    found: dest_type.as_str().to_string(),
                }));
            }

            if before_source.len() != before_dest.len() {
                return Err(RuntimeError::new(RuntimeErrorKind::InvalidOperation(
                    "source and destination dimensions must match".to_string(),
                )));
            }

            let after_source = vector_subtract(&before_source, amount)?;
            let received_amount = amount.saturating_sub(drain);
            let received = component_allocation(&before_source, received_amount);
            let after_dest = vector_add_strict(&before_dest, &received)?;

            {
                let vec = state
                    .vectors
                    .get_mut(&source)
                    .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::UnknownSymbol(source.clone())))?;
                vec.components = after_source.clone();
            }
            {
                let vec = state
                    .vectors
                    .get_mut(&destination)
                    .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::UnknownSymbol(destination.clone())))?;
                vec.components = after_dest.clone();
            }

            let params = match policy {
                Some(p) => format!("amount={amount}, drain={drain}, policy={p}"),
                None => format!("amount={amount}, drain={drain}"),
            };

            let event = push_state_event(
                state,
                &source,
                "global",
                "TRANSFER",
                &before_source,
                &after_source,
                &params,
                "1.0000",
                true,
                "kernel",
                "transfer-proof",
            );

            let _dest_event = push_state_event(
                state,
                &destination,
                "global",
                "TRANSFER_RECEIVE",
                &before_dest,
                &after_dest,
                &params,
                "1.0000",
                true,
                "kernel",
                "transfer-proof",
            );

            Ok(KernelResult {
                output: Some(format!("transfer {source}->{destination} amount={amount} drain={drain}")),
                record: Some(event),
            })
        }
        KernelOp::Drain { target, amount } => {
            let before = {
                let vec = state
                    .vectors
                    .get(&target)
                    .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::UnknownSymbol(target.clone())))?;
                vec.components.clone()
            };
            let after = vector_subtract(&before, amount)?;
            {
                let vec = state
                    .vectors
                    .get_mut(&target)
                    .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::UnknownSymbol(target.clone())))?;
                vec.components = after.clone();
            }
            let event = push_state_event(
                state,
                &target,
                "global",
                "DRAIN",
                &before,
                &after,
                &format!("amount={amount}"),
                "1.0000",
                true,
                "kernel",
                "drain-proof",
            );
            Ok(KernelResult { output: Some(format!("drain {target} amount={amount}")), record: Some(event) })
        }
        KernelOp::Project { source, environment, amount, policy, projection_id } => {
            let before = {
                let vec = state
                    .vectors
                    .get(&source)
                    .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::UnknownSymbol(source.clone())))?;
                vec.components.clone()
            };
            let locked = component_allocation(&before, amount);
            let remainder = vector_subtract(&before, amount)?;
            {
                let vec = state
                    .vectors
                    .get_mut(&source)
                    .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::UnknownSymbol(source.clone())))?;
                vec.components = remainder.clone();
            }
            let proj = ProjectionState {
                projection_id: projection_id.clone(),
                source: source.clone(),
                environment: environment.clone(),
                locked: locked.clone(),
                remainder: remainder.clone(),
                policy: policy.clone(),
                consumed: false,
                settlement_result: None,
            };
            state.projections.insert(projection_id.clone(), proj);
            let event = push_state_event(
                state,
                &source,
                "global",
                "PROJECT",
                &before,
                &remainder,
                &format!(
                    "environment={environment}, amount={amount}, projection_id={projection_id}, policy={}",
                    policy.unwrap_or_else(|| "none".to_string())
                ),
                "1.0000",
                true,
                "kernel",
                "project-proof",
            );
            Ok(KernelResult { output: Some(format!("project {source} -> {projection_id}")), record: Some(event) })
        }
        KernelOp::Reconstruct { target, projection_id } => {
            let locked = {
                let projection = state
                    .projections
                    .get_mut(&projection_id)
                    .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::ProjectionMissing(projection_id.clone())))?;
                if projection.consumed {
                    return Err(RuntimeError::new(RuntimeErrorKind::ProjectionConsumed(projection_id)));
                }
                projection.consumed = true;
                projection.settlement_result = Some("full_return".to_string());
                projection.locked.clone()
            };

            let before = {
                let vec = state
                    .vectors
                    .get(&target)
                    .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::UnknownSymbol(target.clone())))?;
                vec.components.clone()
            };
            let after = vector_add_strict(&before, &locked)?;
            {
                let vec = state
                    .vectors
                    .get_mut(&target)
                    .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::UnknownSymbol(target.clone())))?;
                vec.components = after.clone();
            }

            let event = push_state_event(
                state,
                &target,
                "global",
                "RECONSTRUCT",
                &before,
                &after,
                &format!("projection_id={projection_id}"),
                "1.0000",
                true,
                "kernel",
                "reconstruct-proof",
            );
            Ok(KernelResult { output: Some(format!("reconstruct {target} from {projection_id}")), record: Some(event) })
        }
        KernelOp::Query { expr } => Ok(KernelResult { output: Some(expr), record: None }),
        KernelOp::Record { expr } => Ok(KernelResult { output: Some(expr), record: None }),
        KernelOp::Contract { name, actions } => {
            if state.contracts.contains_key(&name) {
                return Err(RuntimeError::new(RuntimeErrorKind::DuplicateSymbol(name)));
            }
            state.contracts.insert(
                name.clone(),
                ContractState {
                    name: name.clone(),
                    actions: actions.clone(),
                },
            );
            let event = push_state_event(
                state,
                &name,
                "global",
                "CONTRACT",
                &[],
                &[],
                &format!("actions={}", actions.join("; ")),
                "1.0000",
                true,
                "kernel",
                "contract-proof",
            );
            Ok(KernelResult { output: Some(format!("contract {name} deployed")), record: Some(event) })
        }
        KernelOp::ContractAction { contract, action, args } => {
            let contract_name = if let Some(contract_state) = state.contracts.get(&contract) {
                contract_state.name.clone()
            } else {
                return Err(RuntimeError::new(RuntimeErrorKind::ContractMissing(contract)));
            };

            let params = format!("action={action}, args={}", args.join(", "));
            let event = push_state_event(
                state,
                &contract_name,
                "global",
                "CONTRACT_ACTION",
                &[],
                &[],
                &params,
                "1.0000",
                true,
                "kernel",
                "contract-action-proof",
            );
            Ok(KernelResult {
                output: Some(format!("contract action {}::{}", contract_name, action)),
                record: Some(event),
            })
        }
    }
}
