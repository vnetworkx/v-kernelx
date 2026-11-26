use vnetwork_consensus::{
    sign_consensus_vote, validate_proposal_against_state, ValidatorMembership,
};
use vnetwork_core::state::{GenesisConfig, NetworkLedgerState};
use vnetwork_types::*;

pub fn evaluate_and_sign_proposal(
    state: &NetworkLedgerState,
    genesis: &GenesisConfig,
    membership: &ValidatorMembership,
    proposal: &ConsensusProposal,
    validator_id: &str,
    validator_key: &KeypairMaterial,
    timestamp_ms: u64,
) -> VResult<ConsensusVote> {
    validate_proposal_against_state(state, genesis, membership, proposal)?;
    let val = membership.get(validator_id).ok_or_else(|| {
        VNetworkError::Consensus(format!("local validator `{validator_id}` not in set"))
    })?;
    sign_consensus_vote(proposal, val, validator_key, true, timestamp_ms)
}
