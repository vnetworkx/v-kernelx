use vnetwork_consensus::{validate_proposal_against_state, EquivocationStore, ValidatorMembership};
use vnetwork_core::state::{GenesisConfig, NetworkLedgerState};
use vnetwork_types::*;

pub fn evaluate_and_sign_proposal(
    state: &NetworkLedgerState,
    genesis: &GenesisConfig,
    membership: &ValidatorMembership,
    proposal: &ConsensusProposal,
    validator_id: &str,
    validator_signer: &dyn SigningProvider,
    equivocation_store: &mut EquivocationStore,
    timestamp_ms: u64,
) -> VResult<ConsensusVote> {
    validate_proposal_against_state(state, genesis, membership, proposal)?;
    let val = membership.get(validator_id).ok_or_else(|| {
        VNetworkError::Consensus(format!("local validator `{validator_id}` not in set"))
    })?;
    equivocation_store.sign_vote_safely(
        val,
        validator_signer,
        proposal,
        true,
        VotePhase::Commit,
        timestamp_ms,
    )
}
