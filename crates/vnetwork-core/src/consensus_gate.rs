use crate::replay::apply_event_to_state;
use crate::state::{NetworkLedgerState, ValidatorEpochTransition};
use std::collections::{BTreeMap, BTreeSet};
use vnetwork_types::*;

pub fn verify_quorum_certificate(
    qc: &QuorumCertificate,
    validators: &[ConsensusValidator],
    ctx: &ConsensusVerificationContext,
) -> VResult<()> {
    verify_quorum_certificate_strict(qc, validators, ctx)
}

pub fn verify_quorum_certificate_strict(
    qc: &QuorumCertificate,
    validators: &[ConsensusValidator],
    ctx: &ConsensusVerificationContext,
) -> VResult<()> {
    // 0. Validate verification context & network consensus parameters
    ctx.consensus_parameters.validate()?;
    let expected_params_hash = ctx.consensus_parameters.parameters_hash()?;
    if ctx.consensus_parameters_hash != expected_params_hash {
        return Err(VNetworkError::Consensus(format!(
            "verification context consensus_parameters_hash `{}` != computed `{expected_params_hash}`",
            ctx.consensus_parameters_hash
        )));
    }

    // 1. Validate canonical pubkey uniqueness & active weights in validator set
    let expected_vset_hash = validate_validator_set(validators)?;

    // 2. Mandatory QC metadata, domain fields & canonical certificate_id derivation
    if qc.protocol_version != ctx.protocol_version || qc.protocol_version != PROTOCOL_VERSION {
        return Err(VNetworkError::ProfileMismatch(format!(
            "QC protocol_version `{}` != expected `{}`",
            qc.protocol_version, ctx.protocol_version
        )));
    }
    if qc.network_id.trim().is_empty() || qc.network_id != ctx.network_id {
        return Err(VNetworkError::ProfileMismatch(format!(
            "QC network_id `{}` != expected `{}`",
            qc.network_id, ctx.network_id
        )));
    }
    if qc.genesis_commitment.trim().is_empty() || qc.genesis_commitment != ctx.genesis_commitment
    {
        return Err(VNetworkError::ProfileMismatch(format!(
            "QC genesis_commitment `{}` != expected `{}`",
            qc.genesis_commitment, ctx.genesis_commitment
        )));
    }
    if qc.epoch == 0 {
        return Err(VNetworkError::Consensus(
            "QC epoch must be >= 1".to_string(),
        ));
    }
    if let Some(exp_ep) = ctx.expected_epoch {
        if qc.epoch != exp_ep {
            return Err(VNetworkError::Consensus(format!(
                "QC epoch {} != expected {exp_ep}",
                qc.epoch
            )));
        }
    }
    if qc.validator_set_hash.trim().is_empty() || qc.validator_set_hash != expected_vset_hash {
        return Err(VNetworkError::Consensus(format!(
            "QC validator_set_hash mismatch: expected {expected_vset_hash}, got {}",
            qc.validator_set_hash
        )));
    }
    if qc.consensus_parameters_hash != ctx.consensus_parameters_hash {
        return Err(VNetworkError::Consensus(format!(
            "QC consensus_parameters_hash `{}` != expected `{}`",
            qc.consensus_parameters_hash, ctx.consensus_parameters_hash
        )));
    }
    if qc.quorum_threshold_bps != ctx.consensus_parameters.quorum_threshold_bps {
        return Err(VNetworkError::Consensus(format!(
            "QC quorum_threshold_bps `{}` != network policy `{}`",
            qc.quorum_threshold_bps, ctx.consensus_parameters.quorum_threshold_bps
        )));
    }
    if qc.proposal_digest.len() != 64 {
        return Err(VNetworkError::Consensus(
            "QC missing full 64-hex proposal_digest".to_string(),
        ));
    }
    let expected_prop_id = format!("prop_{}_{}", qc.height, qc.proposal_digest);
    if qc.proposal_id != expected_prop_id {
        return Err(VNetworkError::Consensus(format!(
            "QC proposal_id `{}` != expected `{expected_prop_id}`",
            qc.proposal_id
        )));
    }
    if qc.parent_commitment.trim().is_empty()
        || qc.pre_state_root.trim().is_empty()
        || qc.post_state_root.trim().is_empty()
        || qc.operation_scope.trim().is_empty()
    {
        return Err(VNetworkError::Consensus(
            "QC missing required parent_commitment, pre_state_root, post_state_root, or operation_scope"
                .to_string(),
        ));
    }
    if qc.ordered_event_ids.len() != qc.event_hashes.len() {
        return Err(VNetworkError::Consensus(
            "QC ordered_event_ids length does not match event_hashes length".to_string(),
        ));
    }
    qc.verify_certificate_id()?;

    let active_validators: Vec<&ConsensusValidator> =
        validators.iter().filter(|v| v.active).collect();
    let expected_total_weight: u64 = active_validators
        .iter()
        .try_fold(0u64, |acc, v| acc.checked_add(v.weight))
        .ok_or_else(|| VNetworkError::Consensus("validator total weight overflow".to_string()))?;
    if qc.total_weight != expected_total_weight {
        return Err(VNetworkError::Consensus(format!(
            "QC total_weight {} != expected active weight {expected_total_weight}",
            qc.total_weight
        )));
    }

    let mut seen_validators = BTreeSet::new();
    let mut seen_pubkeys: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut verified_weight: u64 = 0;

    for vote in &qc.votes {
        if !vote.approve {
            return Err(VNetworkError::Consensus(format!(
                "quorum certificate contains non-approving vote from `{}`",
                vote.validator_id
            )));
        }
        if vote.proposal_id != qc.proposal_id
            || vote.proposal_digest != qc.proposal_digest
            || vote.network_id != qc.network_id
            || vote.genesis_commitment != qc.genesis_commitment
            || vote.protocol_version != qc.protocol_version
            || vote.height != qc.height
            || vote.round != qc.round
            || vote.epoch != qc.epoch
            || vote.validator_set_hash != qc.validator_set_hash
            || vote.consensus_parameters_hash != qc.consensus_parameters_hash
            || vote.parent_commitment != qc.parent_commitment
            || vote.pre_state_root != qc.pre_state_root
            || vote.post_state_root != qc.post_state_root
            || vote.operation_scope != qc.operation_scope
            || vote.vote_phase != qc.vote_phase
        {
            return Err(VNetworkError::Consensus(
                "quorum certificate vote does not match proposal/QC commitments".to_string(),
            ));
        }
        let val = active_validators
            .iter()
            .copied()
            .find(|v| v.validator_id == vote.validator_id)
            .ok_or_else(|| {
                VNetworkError::Consensus(format!(
                    "vote from non-validator or inactive `{}`",
                    vote.validator_id
                ))
            })?;
        if !seen_validators.insert(val.validator_id.clone()) {
            return Err(VNetworkError::Consensus(format!(
                "duplicate vote in QC from `{}`",
                val.validator_id
            )));
        }
        let canonical_pk = canonical_ed25519_pubkey_bytes(&vote.validator_pubkey_hex)?;
        if !seen_pubkeys.insert(canonical_pk) {
            return Err(VNetworkError::Consensus(format!(
                "duplicate Ed25519 public key across votes in QC for `{}`",
                val.validator_id
            )));
        }
        vote.verify(val)?;
        verified_weight = verified_weight
            .checked_add(val.weight)
            .ok_or_else(|| VNetworkError::Consensus("verified quorum weight overflow".to_string()))?;
    }

    if qc.approving_weight != verified_weight {
        return Err(VNetworkError::Consensus(format!(
            "QC approving_weight {} != verified weight {verified_weight}",
            qc.approving_weight
        )));
    }

    let threshold = ctx.consensus_parameters.quorum_threshold_bps as u128;
    if (verified_weight as u128) * 10_000 < (expected_total_weight as u128) * threshold {
        return Err(VNetworkError::Consensus(format!(
            "insufficient quorum weight: {verified_weight}/{expected_total_weight} (need >= {} bps)",
            threshold
        )));
    }
    Ok(())
}

pub fn verify_membership_chain_from_genesis(
    genesis_validators: &[ConsensusValidator],
    genesis_epoch: u64,
    ctx: &ConsensusVerificationContext,
    transitions: &[ValidatorEpochTransition],
    target_epoch: u64,
    target_vset_hash: &str,
    target_validators: &[ConsensusValidator],
) -> VResult<Vec<ConsensusValidator>> {
    if genesis_epoch == 0 {
        return Err(VNetworkError::Consensus(
            "genesis_epoch must be >= 1".to_string(),
        ));
    }
    if target_epoch < genesis_epoch {
        return Err(VNetworkError::Consensus(format!(
            "target_epoch {target_epoch} < genesis_epoch {genesis_epoch}"
        )));
    }

    let mut current_epoch = genesis_epoch;
    let mut current_validators = genesis_validators.to_vec();
    let mut current_hash = validate_validator_set(&current_validators)?;
    let mut last_height = 0u64;

    for tr in transitions {
        let next_epoch = current_epoch
            .checked_add(1)
            .ok_or_else(|| VNetworkError::Consensus("validator epoch overflow".to_string()))?;
        if tr.prev_epoch != current_epoch {
            return Err(VNetworkError::Consensus(format!(
                "validator transition prev_epoch {} != current epoch {current_epoch}",
                tr.prev_epoch
            )));
        }
        if tr.epoch != next_epoch {
            return Err(VNetworkError::Consensus(format!(
                "validator epoch transition gap: expected epoch {next_epoch}, got {}",
                tr.epoch
            )));
        }
        if tr.height <= last_height {
            return Err(VNetworkError::Consensus(format!(
                "validator transition height {} did not advance past {}",
                tr.height, last_height
            )));
        }
        if tr.prev_validator_set_hash != current_hash {
            return Err(VNetworkError::Consensus(format!(
                "validator transition prev_validator_set_hash mismatch at epoch {}",
                tr.epoch
            )));
        }
        if tr.consensus_parameters_hash != ctx.consensus_parameters_hash {
            return Err(VNetworkError::Consensus(format!(
                "validator transition consensus_parameters_hash mismatch at epoch {}",
                tr.epoch
            )));
        }
        let next_hash = validate_validator_set(&tr.new_validators)?;
        if tr.new_validator_set_hash != next_hash {
            return Err(VNetworkError::Consensus(format!(
                "validator transition new_validator_set_hash mismatch at epoch {}",
                tr.epoch
            )));
        }
        let expected_tr_digest = tr.compute_transition_payload_digest()?;
        if tr.transition_payload_digest.len() != 64
            || tr.transition_payload_digest != expected_tr_digest
        {
            return Err(VNetworkError::Consensus(format!(
                "validator transition payload digest mismatch at epoch {}",
                tr.epoch
            )));
        }

        let epoch_ctx = ctx.for_epoch(current_epoch)?;
        verify_quorum_certificate_strict(&tr.transition_certificate, &current_validators, &epoch_ctx)?;

        let qc = &tr.transition_certificate;
        let bound_to_transition = qc.post_state_root == tr.transition_payload_digest
            || qc.event_hashes.contains(&tr.transition_payload_digest);
        if qc.height != tr.height
            || qc.epoch != tr.prev_epoch
            || qc.validator_set_hash != tr.prev_validator_set_hash
            || qc.consensus_parameters_hash != tr.consensus_parameters_hash
            || !bound_to_transition
        {
            return Err(VNetworkError::Consensus(format!(
                "validator transition certificate at epoch {} does not certify transition payload digest",
                tr.epoch
            )));
        }

        current_epoch = tr.epoch;
        current_validators = tr.new_validators.clone();
        current_hash = next_hash;
        last_height = tr.height;
    }

    if current_epoch != target_epoch {
        return Err(VNetworkError::Consensus(format!(
            "proven validator epoch {current_epoch} != target epoch {target_epoch}"
        )));
    }
    let expected_target_hash = validate_validator_set(target_validators)?;
    if current_hash != target_vset_hash || current_hash != expected_target_hash {
        return Err(VNetworkError::Consensus(format!(
            "proven validator set hash `{current_hash}` != target `{target_vset_hash}`"
        )));
    }
    Ok(current_validators)
}

pub fn commit_verified_proposal(
    state: &mut NetworkLedgerState,
    proposal: &ConsensusProposal,
    qc: &QuorumCertificate,
    validators: &[ConsensusValidator],
) -> VResult<String> {
    let ctx = state.consensus_context()?;
    if proposal.network_id != ctx.network_id {
        return Err(VNetworkError::ProfileMismatch(format!(
            "proposal network_id `{}` != local `{}`",
            proposal.network_id, ctx.network_id
        )));
    }
    if ctx.genesis_commitment.trim().is_empty()
        || proposal.genesis_commitment != ctx.genesis_commitment
    {
        return Err(VNetworkError::ProfileMismatch(format!(
            "proposal genesis_commitment `{}` != local `{}`",
            proposal.genesis_commitment, ctx.genesis_commitment
        )));
    }
    if proposal.protocol_version != ctx.protocol_version {
        return Err(VNetworkError::ProfileMismatch(format!(
            "proposal protocol_version `{}` != local `{}`",
            proposal.protocol_version, ctx.protocol_version
        )));
    }
    if proposal.epoch != state.validator_epoch {
        return Err(VNetworkError::Consensus(format!(
            "proposal epoch {} != active validator_epoch {}",
            proposal.epoch, state.validator_epoch
        )));
    }
    if proposal.consensus_parameters_hash != ctx.consensus_parameters_hash {
        return Err(VNetworkError::Consensus(format!(
            "proposal consensus_parameters_hash `{}` != local `{}`",
            proposal.consensus_parameters_hash, ctx.consensus_parameters_hash
        )));
    }

    let expected_vhash = validate_validator_set(validators)?;
    if proposal.validator_set_hash != expected_vhash {
        return Err(VNetworkError::Consensus(format!(
            "proposal validator_set_hash mismatch: expected {expected_vhash}, got {}",
            proposal.validator_set_hash
        )));
    }

    let proposer = validators
        .iter()
        .find(|v| v.active && v.validator_id == proposal.proposer_validator_id)
        .ok_or_else(|| {
            VNetworkError::Consensus(format!(
                "unknown or inactive proposal proposer `{}`",
                proposal.proposer_validator_id
            ))
        })?;
    proposal.verify_proposer_signature(proposer)?;

    let expected_parent = state.expected_parent_commitment();
    if proposal.parent_commitment != expected_parent {
        return Err(VNetworkError::Consensus(format!(
            "proposal parent_commitment `{}` != expected `{expected_parent}`",
            proposal.parent_commitment
        )));
    }

    let current_root = state.compute_state_root()?;
    if proposal.pre_state_root != current_root {
        return Err(VNetworkError::Consensus(format!(
            "proposal pre_state_root `{}` does not match local `{current_root}`",
            proposal.pre_state_root
        )));
    }
    let next_height = state
        .height
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Consensus("ledger height overflow".to_string()))?;
    if proposal.height != next_height {
        return Err(VNetworkError::Consensus(format!(
            "proposal height {} != expected {next_height}",
            proposal.height
        )));
    }

    verify_quorum_certificate_strict(qc, validators, &ctx)?;
    if qc.proposal_id != proposal.proposal_id
        || qc.proposal_digest != proposal.proposal_digest
        || qc.network_id != proposal.network_id
        || qc.genesis_commitment != proposal.genesis_commitment
        || qc.protocol_version != proposal.protocol_version
        || qc.height != proposal.height
        || qc.round != proposal.round
        || qc.epoch != proposal.epoch
        || qc.validator_set_hash != proposal.validator_set_hash
        || qc.consensus_parameters_hash != proposal.consensus_parameters_hash
        || qc.parent_commitment != proposal.parent_commitment
        || qc.pre_state_root != proposal.pre_state_root
        || qc.post_state_root != proposal.post_state_root
        || qc.operation_scope != proposal.operation_scope
        || qc.ordered_event_ids != proposal.ordered_event_ids()
        || qc.event_hashes != proposal.ordered_event_hashes()
    {
        return Err(VNetworkError::Consensus(
            "quorum certificate does not strictly match proposal commitments".to_string(),
        ));
    }

    let mut staged = state.clone();
    let mut executed_event_ids = Vec::with_capacity(proposal.events.len());
    for ev in &proposal.events {
        if !ev.verify_hashes()? {
            return Err(VNetworkError::Consensus(format!(
                "proposal event {} failed hash verification",
                ev.event_id
            )));
        }
        apply_event_to_state(&mut staged, ev)?;
        executed_event_ids.push(ev.event_id.clone());
    }
    if executed_event_ids != qc.ordered_event_ids {
        return Err(VNetworkError::Consensus(
            "executed proposal event IDs diverge from certified QC".to_string(),
        ));
    }
    match &proposal.nonce_binding {
        Some((actor_pubkey, request_id, nonce)) => {
            let nonce_events: Vec<&LedgerEvent> = proposal
                .events
                .iter()
                .filter(|event| event.operation == "REQUEST_NONCE_COMMIT")
                .collect();
            if nonce_events.len() != 1 {
                return Err(VNetworkError::Consensus(
                    "signed request proposal must contain exactly one REQUEST_NONCE_COMMIT event"
                        .to_string(),
                ));
            }
            let event = nonce_events[0];
            let event_actor = event.payload.get("actor_pubkey").and_then(|v| v.as_str());
            let event_request = event.payload.get("request_id").and_then(|v| v.as_str());
            let event_nonce = event.payload.get("nonce").and_then(|v| v.as_u64());
            if event_actor != Some(actor_pubkey.as_str())
                || event_request != Some(request_id.as_str())
                || event_nonce != Some(*nonce)
                || staged.actor_nonces.get(actor_pubkey) != Some(nonce)
                || !staged.seen_request_ids.contains(request_id)
            {
                return Err(VNetworkError::Consensus(
                    "proposal nonce binding is not proven by its committed event".to_string(),
                ));
            }
        }
        None => {
            if proposal.events.iter().any(|event| event.operation == "REQUEST_NONCE_COMMIT") {
                return Err(VNetworkError::Consensus(
                    "proposal contains a request nonce event without a nonce binding".to_string(),
                ));
            }
        }
    }
    staged.height = proposal.height;
    let computed_post = staged.compute_state_root()?;
    if computed_post != proposal.post_state_root {
        return Err(VNetworkError::Consensus(format!(
            "re-executed post_state_root `{computed_post}` != proposal `{}`",
            proposal.post_state_root
        )));
    }

    staged.last_proposal_digest = proposal.proposal_digest.clone();
    staged.event_history_root = staged.compute_event_history_root();
    staged
        .certificates
        .insert(qc.certificate_id.clone(), qc.clone());
    *state = staged;
    Ok(computed_post)
}

pub fn replay_validator_epoch_history(
    genesis_validators: &[ConsensusValidator],
    genesis_epoch: u64,
    ctx: &ConsensusVerificationContext,
    transitions: &[ValidatorEpochTransition],
) -> VResult<(u64, Vec<ConsensusValidator>, BTreeMap<u64, Vec<ConsensusValidator>>)> {
    if genesis_epoch == 0 {
        return Err(VNetworkError::Consensus(
            "genesis_epoch must be >= 1".to_string(),
        ));
    }
    let mut epoch_map = BTreeMap::new();
    let mut current = genesis_validators.to_vec();
    validate_validator_set(&current)?;
    epoch_map.insert(genesis_epoch, current.clone());
    let mut current_epoch = genesis_epoch;
    for (idx, tr) in transitions.iter().enumerate() {
        verify_membership_chain_from_genesis(
            genesis_validators,
            genesis_epoch,
            ctx,
            &transitions[..=idx],
            tr.epoch,
            &tr.new_validator_set_hash,
            &tr.new_validators,
        )?;
        current_epoch = tr.epoch;
        current = tr.new_validators.clone();
        epoch_map.insert(current_epoch, current.clone());
    }
    Ok((current_epoch, current, epoch_map))
}
