use crate::membership::ValidatorMembership;
use vnetwork_types::*;

pub fn sign_consensus_vote_with_provider(
    proposal: &ConsensusProposal,
    validator: &ConsensusValidator,
    signer: &dyn SigningProvider,
    approve: bool,
    vote_phase: VotePhase,
    timestamp_ms: u64,
) -> VResult<ConsensusVote> {
    if !validator.active || validator.weight == 0 {
        return Err(VNetworkError::Consensus(format!(
            "validator `{}` is inactive or zero-weight",
            validator.validator_id
        )));
    }
    let val_pk = validator.canonical_pubkey_bytes()?;
    let signer_pk = canonical_ed25519_pubkey_bytes(signer.public_key_hex())?;
    if val_pk != signer_pk {
        return Err(VNetworkError::Authorization(
            "signing key does not match validator public key".to_string(),
        ));
    }
    proposal.verify_digest_and_metadata()?;

    let mut vote = ConsensusVote {
        proposal_id: proposal.proposal_id.clone(),
        proposal_digest: proposal.proposal_digest.clone(),
        network_id: proposal.network_id.clone(),
        genesis_commitment: proposal.genesis_commitment.clone(),
        protocol_version: proposal.protocol_version.clone(),
        height: proposal.height,
        round: proposal.round,
        epoch: proposal.epoch,
        validator_set_hash: proposal.validator_set_hash.clone(),
        parent_commitment: proposal.parent_commitment.clone(),
        pre_state_root: proposal.pre_state_root.clone(),
        post_state_root: proposal.post_state_root.clone(),
        operation_scope: proposal.operation_scope.clone(),
        vote_phase,
        validator_id: validator.validator_id.clone(),
        validator_pubkey_hex: validator.validator_pubkey_hex.clone(),
        approve,
        timestamp_ms,
        signature: String::new(),
    };
    let bytes = vote.canonical_signing_bytes()?;
    vote.signature = signer.sign(&bytes)?;
    Ok(vote)
}

pub fn sign_consensus_vote(
    proposal: &ConsensusProposal,
    validator: &ConsensusValidator,
    signing_key: &KeypairMaterial,
    approve: bool,
    timestamp_ms: u64,
) -> VResult<ConsensusVote> {
    let provider = signing_key.to_signing_provider()?;
    sign_consensus_vote_with_provider(
        proposal,
        validator,
        &provider,
        approve,
        VotePhase::Commit,
        timestamp_ms,
    )
}

pub fn verify_consensus_vote(
    membership: &ValidatorMembership,
    vote: &ConsensusVote,
) -> VResult<ConsensusValidator> {
    let val = membership.get(&vote.validator_id).ok_or_else(|| {
        VNetworkError::Consensus(format!("unknown validator `{}`", vote.validator_id))
    })?;
    vote.verify(val)?;
    Ok(val.clone())
}
