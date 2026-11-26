use crate::membership::ValidatorMembership;
use vnetwork_types::*;

pub fn sign_consensus_vote(
    proposal: &ConsensusProposal,
    validator: &ConsensusValidator,
    signing_key: &KeypairMaterial,
    approve: bool,
    timestamp_ms: u64,
) -> VResult<ConsensusVote> {
    if signing_key.public_key_hex != validator.validator_pubkey_hex {
        return Err(VNetworkError::Authorization(
            "signing key does not match validator public key".to_string(),
        ));
    }
    let mut vote = ConsensusVote {
        proposal_id: proposal.proposal_id.clone(),
        network_id: proposal.network_id.clone(),
        height: proposal.height,
        round: proposal.round,
        epoch: proposal.epoch,
        validator_id: validator.validator_id.clone(),
        validator_pubkey_hex: validator.validator_pubkey_hex.clone(),
        approve,
        post_state_root: proposal.post_state_root.clone(),
        timestamp_ms,
        signature: String::new(),
    };
    let bytes = vote.canonical_signing_bytes()?;
    vote.signature = signing_key.sign(&bytes)?;
    Ok(vote)
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
