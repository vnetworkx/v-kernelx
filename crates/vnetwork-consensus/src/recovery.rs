use crate::membership::ValidatorMembership;
use crate::synchronization::apply_verified_sync_batch;
use vnetwork_core::engine::ProtocolEngine;
use vnetwork_types::*;

pub fn recover_consensus_history(
    engine: &mut ProtocolEngine,
    membership: &ValidatorMembership,
    commits: &[(ConsensusProposal, QuorumCertificate)],
    timestamp_ms: u64,
) -> VResult<usize> {
    apply_verified_sync_batch(engine, membership, commits, timestamp_ms)
}
