use crate::contracts::{apply_create_contract, apply_execute_contract};
use crate::identity::{apply_grant_participant_scope, apply_reinstate_participant, apply_revoke_participant_scope};
use crate::loans::{apply_create_loan, apply_execute_loan};
use crate::region::apply_create_region;
use crate::space::apply_create_space;
use crate::state::{GenesisConfig, NetworkLedgerState};
use crate::token::{
    apply_adjust_non_transferable_dimensions, apply_create_token, apply_drain_token,
    apply_transfer_token,
};
use crate::validation::validate_operation_preconditions_with_policy;
use crate::wallet::{
    apply_authorize_wallet_key, apply_create_wallet, apply_revoke_wallet_key,
    apply_rotate_wallet_key, apply_update_wallet_receive_policy,
};
use std::collections::BTreeMap;
use vnetwork_types::*;

#[derive(Debug, Clone)]
pub struct TransitionOutcome {
    pub events: Vec<LedgerEvent>,
    pub created_entities: Vec<CreatedEntitySummary>,
    pub outputs: Vec<String>,
}

pub fn apply_network_operation(
    state: &mut NetworkLedgerState,
    op: &NetworkOperation,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<TransitionOutcome> {
    apply_network_operation_with_policy(
        state,
        state.profile.allows_dev_atlas_fixture(),
        op,
        actor_pubkey,
        timestamp_ms,
    )
}

pub fn apply_network_operation_with_genesis(
    state: &mut NetworkLedgerState,
    genesis: &GenesisConfig,
    op: &NetworkOperation,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<TransitionOutcome> {
    apply_network_operation_with_policy(
        state,
        genesis.allow_bootstrap_atlas,
        op,
        actor_pubkey,
        timestamp_ms,
    )
}

pub fn apply_network_operation_with_policy(
    state: &mut NetworkLedgerState,
    allow_bootstrap_atlas: bool,
    op: &NetworkOperation,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<TransitionOutcome> {
    // Operations may touch multiple ledgers (balances, entities, escrow, and
    // event history). Commit the working state only after every step succeeds.
    let mut staged = state.clone();
    let outcome = apply_network_operation_inner(
        &mut staged,
        allow_bootstrap_atlas,
        op,
        actor_pubkey,
        timestamp_ms,
    )?;
    *state = staged;
    Ok(outcome)
}

fn apply_network_operation_inner(
    state: &mut NetworkLedgerState,
    allow_bootstrap_atlas: bool,
    op: &NetworkOperation,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<TransitionOutcome> {
    validate_operation_preconditions_with_policy(state, allow_bootstrap_atlas, op)?;
    let mut events = Vec::new();
    let mut created_entities = Vec::new();
    let mut outputs = Vec::new();

    match op {
        NetworkOperation::CreateSpace {
            name,
            visibility,
            ghost,
        } => {
            if *ghost {
                crate::ghost::validate_ghost_permissions(state, actor_pubkey, timestamp_ms)?;
            }
            let vis = Visibility::parse(visibility).ok_or_else(|| {
                VNetworkError::Validation(format!("invalid visibility `{visibility}`"))
            })?;
            let (space, ev) = apply_create_space(
                state,
                name,
                vis,
                *ghost,
                actor_pubkey,
                BTreeMap::new(),
                timestamp_ms,
            )?;
            created_entities.push(CreatedEntitySummary {
                kind: "space".to_string(),
                id: space.space_id.clone(),
                name: space.name.clone(),
            });
            outputs.push(format!("space created: {} ({})", space.name, space.space_id));
            events.push(ev);
        }
        NetworkOperation::CreateRegion {
            space_id,
            name,
            prefix,
            title,
            visibility,
            section,
            ghost,
        } => {
            if *ghost {
                crate::ghost::validate_ghost_permissions(state, actor_pubkey, timestamp_ms)?;
            }
            let vis = Visibility::parse(visibility).ok_or_else(|| {
                VNetworkError::Validation(format!("invalid visibility `{visibility}`"))
            })?;
            let (region, ev) = apply_create_region(
                state,
                space_id,
                name,
                prefix.clone(),
                title.clone(),
                vis,
                *section,
                *ghost,
                actor_pubkey,
                BTreeMap::new(),
                timestamp_ms,
            )?;
            created_entities.push(CreatedEntitySummary {
                kind: "region".to_string(),
                id: region.region_id.clone(),
                name: region.name.clone(),
            });
            outputs.push(format!("region created: {} ({})", region.name, region.region_id));
            events.push(ev);
        }
        NetworkOperation::CreateWallet {
            region_id,
            name,
            ghost,
            approval_threshold,
        } => {
            if *ghost {
                crate::ghost::validate_ghost_permissions(state, actor_pubkey, timestamp_ms)?;
            }
            let (wallet, ev) = apply_create_wallet(
                state,
                region_id,
                name,
                *ghost,
                *approval_threshold,
                actor_pubkey,
                timestamp_ms,
            )?;
            created_entities.push(CreatedEntitySummary {
                kind: "wallet".to_string(),
                id: wallet.wallet_id.clone(),
                name: wallet.name.clone(),
            });
            outputs.push(format!("wallet created: {} ({})", wallet.name, wallet.wallet_id));
            events.push(ev);
        }
        NetworkOperation::AuthorizeWalletKey {
            wallet_id,
            authorized_pubkey,
            role,
            permissions,
            allowed_token_ids,
            max_amount_per_op,
            expires_at_ms,
            pop_nonce,
            pop_signature,
            participant_identity,
        } => {
            let (wallet, ev) = apply_authorize_wallet_key(
                state,
                wallet_id,
                authorized_pubkey,
                role,
                permissions,
                allowed_token_ids,
                *max_amount_per_op,
                *expires_at_ms,
                pop_nonce.as_deref(),
                pop_signature.as_deref(),
                participant_identity.as_deref(),
                actor_pubkey,
                timestamp_ms,
            )?;
            outputs.push(format!(
                "wallet key authorized on {} ({})",
                wallet.name, authorized_pubkey
            ));
            events.push(ev);
        }
        NetworkOperation::RevokeWalletKey {
            wallet_id,
            target_pubkey,
        } => {
            let (wallet, ev) = apply_revoke_wallet_key(
                state,
                wallet_id,
                target_pubkey,
                actor_pubkey,
                timestamp_ms,
            )?;
            outputs.push(format!(
                "wallet key revoked on {} ({})",
                wallet.name, target_pubkey
            ));
            events.push(ev);
        }
        NetworkOperation::RotateWalletKey {
            wallet_id,
            old_pubkey,
            new_pubkey,
            role,
            pop_nonce,
            pop_signature,
            participant_identity,
        } => {
            let (wallet, ev) = apply_rotate_wallet_key(
                state,
                wallet_id,
                old_pubkey,
                new_pubkey,
                role.as_deref(),
                pop_nonce.as_deref(),
                pop_signature.as_deref(),
                participant_identity.as_deref(),
                actor_pubkey,
                timestamp_ms,
            )?;
            outputs.push(format!(
                "wallet key rotated on {} ({} -> {})",
                wallet.name, old_pubkey, new_pubkey
            ));
            events.push(ev);
        }
        NetworkOperation::GrantParticipantScope {
            target_participant_id,
            level,
            target_id,
            expires_at_ms,
        } => {
            let (participant, ev) = apply_grant_participant_scope(
                state,
                target_participant_id,
                level,
                target_id.clone(),
                *expires_at_ms,
                actor_pubkey,
                timestamp_ms,
            )?;
            outputs.push(format!(
                "participant scope granted: {} level={level}",
                participant.participant_id
            ));
            events.push(ev);
        }
        NetworkOperation::RevokeParticipantScope {
            target_participant_id,
            level,
            target_id,
        } => {
            let (participant, ev) = apply_revoke_participant_scope(
                state,
                target_participant_id,
                level,
                target_id.as_deref(),
                actor_pubkey,
                timestamp_ms,
            )?;
            outputs.push(format!(
                "participant scope revoked: {} level={level}",
                participant.participant_id
            ));
            events.push(ev);
        }
        NetworkOperation::ReinstateParticipant {
            target_participant_id,
        } => {
            let (participant, node, ev) = apply_reinstate_participant(
                state,
                target_participant_id,
                actor_pubkey,
                timestamp_ms,
            )?;
            outputs.push(format!(
                "participant reinstated with Network-only membership: {} ({})",
                participant.participant_id, node.node_id
            ));
            events.push(ev);
        }
        NetworkOperation::CreateToken {
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
        } => {
            if *ghost {
                crate::ghost::validate_ghost_permissions(state, actor_pubkey, timestamp_ms)?;
            }
            let vec3 = TokenVector::new(*initial_supply, *auth_ratio_au, *energy);
            let (token, ev) = apply_create_token(
                state,
                wallet_id,
                name,
                symbol,
                TOKEN_VECTOR_DIMENSIONS,
                vec3,
                *max_supply,
                *unlimited_supply,
                *drain_bps,
                purpose,
                external_monetary_value,
                *ghost,
                actor_pubkey,
                timestamp_ms,
            )?;
            created_entities.push(CreatedEntitySummary {
                kind: "token".to_string(),
                id: token.token_id.clone(),
                name: token.symbol.clone(),
            });
            outputs.push(format!(
                "token created: {} [{}] ({}) vec=[{}, {}, {}]",
                token.name,
                token.symbol,
                token.token_id,
                token.initial_vector.token,
                token.initial_vector.auth_ratio_au,
                token.initial_vector.energy
            ));
            events.push(ev);
        }
        NetworkOperation::TransferToken {
            token_id,
            from_wallet_id,
            to_wallet_id,
            amount,
            cosignatures,
        } => {
            let (from_bal, to_bal, fee, ev) = apply_transfer_token(
                state,
                token_id,
                from_wallet_id,
                to_wallet_id,
                *amount,
                cosignatures,
                actor_pubkey,
                timestamp_ms,
            )?;
            outputs.push(format!(
                "transfer: {} -> {} amount={} fee={} from_token={} to_token={}",
                from_bal.wallet_id,
                to_bal.wallet_id,
                amount,
                fee,
                from_bal.vector.token,
                to_bal.vector.token
            ));
            events.push(ev);
        }
        NetworkOperation::UpdateWalletReceivePolicy {
            wallet_id,
            mode,
            allowed_senders,
        } => {
            let (wallet, ev) = apply_update_wallet_receive_policy(
                state,
                wallet_id,
                mode,
                allowed_senders,
                actor_pubkey,
                timestamp_ms,
            )?;
            outputs.push(format!(
                "wallet receive policy updated: {} ({:?})",
                wallet.name, wallet.receive_policy
            ));
            events.push(ev);
        }
        NetworkOperation::DrainToken {
            token_id,
            wallet_id,
            amount,
        } => {
            let (bal, ev) =
                apply_drain_token(state, token_id, wallet_id, *amount, actor_pubkey, timestamp_ms)?;
            outputs.push(format!(
                "drain: wallet={} token={} remaining={}",
                bal.wallet_id, bal.token_id, bal.vector.token
            ));
            events.push(ev);
        }
        NetworkOperation::AdjustNonTransferableDimensions {
            token_id,
            wallet_id,
            new_auth_ratio_au,
            new_energy,
            reason,
        } => {
            let (bal, ev) = apply_adjust_non_transferable_dimensions(
                state,
                token_id,
                wallet_id,
                *new_auth_ratio_au,
                *new_energy,
                reason,
                actor_pubkey,
                timestamp_ms,
            )?;
            outputs.push(format!(
                "dimensions adjusted: wallet={} token={} vec=[{}, {}, {}]",
                bal.wallet_id,
                bal.token_id,
                bal.vector.token,
                bal.vector.auth_ratio_au,
                bal.vector.energy
            ));
            events.push(ev);
        }
        NetworkOperation::CreateContract {
            name,
            region_id,
            rules,
            actions,
        } => {
            let mut rules_map = BTreeMap::new();
            if let Some(obj) = rules.as_object() {
                for (k, v) in obj {
                    rules_map.insert(k.clone(), v.clone());
                }
            }
            let (contract, ev) = apply_create_contract(
                state,
                name,
                region_id.as_deref(),
                rules_map,
                actions.clone(),
                actor_pubkey,
                timestamp_ms,
            )?;
            created_entities.push(CreatedEntitySummary {
                kind: "contract".to_string(),
                id: contract.contract_id.clone(),
                name: contract.name.clone(),
            });
            outputs.push(format!(
                "contract created: {} ({})",
                contract.name, contract.contract_id
            ));
            events.push(ev);
        }
        NetworkOperation::ExecuteContract {
            contract_id,
            action,
            args,
        } => {
            let (contract, ev) = apply_execute_contract(
                state,
                contract_id,
                action,
                args.clone(),
                actor_pubkey,
                timestamp_ms,
            )?;
            outputs.push(format!(
                "contract executed: {} action={} count={}",
                contract.name, action, contract.execution_count
            ));
            events.push(ev);
        }
        NetworkOperation::CreateLoan {
            name,
            token_id,
            lender_wallet_id,
            borrower_wallet_id,
            principal,
            collateral,
            interest_bps,
            maturity_at_ms,
        } => {
            let (loan, ev) = apply_create_loan(
                state,
                name,
                token_id,
                lender_wallet_id,
                borrower_wallet_id,
                *principal,
                *collateral,
                *interest_bps,
                *maturity_at_ms,
                actor_pubkey,
                timestamp_ms,
            )?;
            created_entities.push(CreatedEntitySummary {
                kind: "loan".to_string(),
                id: loan.loan_id.clone(),
                name: loan.name.clone(),
            });
            outputs.push(format!("loan created: {} ({})", loan.name, loan.loan_id));
            events.push(ev);
        }
        NetworkOperation::ExecuteLoan {
            loan_id,
            action,
            amount,
        } => {
            let (loan, mut evs) = apply_execute_loan(
                state,
                loan_id,
                action,
                *amount,
                actor_pubkey,
                timestamp_ms,
            )?;
            outputs.push(format!(
                "loan executed: {} action={} status={:?}",
                loan.name, action, loan.status
            ));
            events.append(&mut evs);
        }
    }

    Ok(TransitionOutcome {
        events,
        created_entities,
        outputs,
    })
}
