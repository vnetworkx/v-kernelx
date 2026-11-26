use crate::authorization::record_nonce_and_request;
use crate::replay::apply_event_to_state;
use crate::state::NetworkLedgerState;
use vnetwork_types::*;

pub fn verify_quorum_certificate(
    qc: &QuorumCertificate,
    validators: &[ConsensusValidator],
) -> VResult<()> {
    let active_validators: Vec<&ConsensusValidator> =
        validators.iter().filter(|v| v.active).collect();
    if active_validators.is_empty() {
        return Err(VNetworkError::Consensus(
            "no active validators configured".to_string(),
        ));
    }

    if !qc.validator_set_hash.is_empty() {
        let expected_hash = compute_validator_set_hash(validators)?;
        if qc.validator_set_hash != expected_hash {
            return Err(VNetworkError::Consensus(format!(
                "QC validator_set_hash mismatch: expected {expected_hash}, got {}",
                qc.validator_set_hash
            )));
        }
    }

    let expected_total_weight: u64 = active_validators
        .iter()
        .try_fold(0u64, |acc, v| acc.checked_add(v.weight))
        .ok_or_else(|| VNetworkError::Consensus("validator total weight overflow".to_string()))?;
    if expected_total_weight == 0 {
        return Err(VNetworkError::Consensus(
            "total active validator weight cannot be zero".to_string(),
        ));
    }

    let mut seen_validators = std::collections::BTreeSet::new();
    let mut verified_weight: u64 = 0;

    for vote in &qc.votes {
        if !vote.approve {
            return Err(VNetworkError::Consensus(format!(
                "quorum certificate contains non-approving vote from `{}`",
                vote.validator_id
            )));
        }
        if vote.proposal_id != qc.proposal_id
            || vote.height != qc.height
            || vote.round != qc.round
            || vote.epoch != qc.epoch
            || vote.post_state_root != qc.post_state_root
            || vote.network_id != qc.network_id
        {
            return Err(VNetworkError::Consensus(
                "quorum certificate vote does not match proposal metadata".to_string(),
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
        vote.verify(val)?;
        verified_weight = verified_weight
            .checked_add(val.weight)
            .ok_or_else(|| VNetworkError::Consensus("verified quorum weight overflow".to_string()))?;
    }

    let threshold = qc.quorum_threshold_bps.max(DEFAULT_BFT_QUORUM_BPS) as u128;
    if (verified_weight as u128) * 10_000 < (expected_total_weight as u128) * threshold {
        return Err(VNetworkError::Consensus(format!(
            "insufficient quorum weight: {verified_weight}/{expected_total_weight} (need >= {} bps)",
            threshold
        )));
    }
    Ok(())
}

pub fn commit_verified_proposal(
    state: &mut NetworkLedgerState,
    proposal: &ConsensusProposal,
    qc: &QuorumCertificate,
    validators: &[ConsensusValidator],
) -> VResult<String> {
    if proposal.network_id != state.network_id {
        return Err(VNetworkError::ProfileMismatch(format!(
            "proposal network_id `{}` != local `{}`",
            proposal.network_id, state.network_id
        )));
    }
    if proposal.epoch != state.validator_epoch {
        return Err(VNetworkError::Consensus(format!(
            "proposal epoch {} != active validator_epoch {}",
            proposal.epoch, state.validator_epoch
        )));
    }
    if !proposal.validator_set_hash.is_empty() {
        let expected_vhash = compute_validator_set_hash(validators)?;
        if proposal.validator_set_hash != expected_vhash {
            return Err(VNetworkError::Consensus(format!(
                "proposal validator_set_hash mismatch: expected {expected_vhash}, got {}",
                proposal.validator_set_hash
            )));
        }
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

    let current_root = state.compute_state_root()?;
    if proposal.pre_state_root != current_root {
        return Err(VNetworkError::Consensus(format!(
            "proposal pre_state_root `{}` does not match local `{current_root}`",
            proposal.pre_state_root
        )));
    }
    if proposal.height != state.height + 1 {
        return Err(VNetworkError::Consensus(format!(
            "proposal height {} != expected {}",
            proposal.height,
            state.height + 1
        )));
    }

    verify_quorum_certificate(qc, validators)?;
    if qc.proposal_id != proposal.proposal_id
        || qc.height != proposal.height
        || qc.epoch != proposal.epoch
        || qc.post_state_root != proposal.post_state_root
    {
        return Err(VNetworkError::Consensus(
            "quorum certificate does not match proposal".to_string(),
        ));
    }

    let mut staged = state.clone();
    for ev in &proposal.events {
        if !ev.verify_hashes()? {
            return Err(VNetworkError::Consensus(format!(
                "proposal event {} failed hash verification",
                ev.event_id
            )));
        }
        apply_event_to_state(&mut staged, ev)?;
    }
    if let Some((actor_pubkey, request_id, nonce)) = &proposal.nonce_binding {
        record_nonce_and_request(&mut staged, request_id, actor_pubkey, *nonce);
    }
    staged.height = proposal.height;
    let computed_post = staged.compute_state_root()?;
    if computed_post != proposal.post_state_root {
        return Err(VNetworkError::Consensus(format!(
            "re-executed post_state_root `{computed_post}` != proposal `{}`",
            proposal.post_state_root
        )));
    }

    staged
        .certificates
        .insert(qc.certificate_id.clone(), qc.clone());
    *state = staged;
    Ok(computed_post)
}
