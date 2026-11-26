use crate::finality::finalize_and_commit;
use crate::membership::ValidatorMembership;
use vnetwork_core::engine::ProtocolEngine;
use vnetwork_types::*;

pub fn apply_verified_sync_batch(
    engine: &mut ProtocolEngine,
    membership: &ValidatorMembership,
    commits: &[(ConsensusProposal, QuorumCertificate)],
    timestamp_ms: u64,
) -> VResult<usize> {
    let mut ordered = commits.to_vec();
    ordered.sort_by_key(|(p, _)| p.height);

    let mut applied = 0usize;
    for (proposal, qc) in ordered {
        if proposal.height <= engine.state.height {
            continue;
        }
        if proposal.height != engine.state.height + 1 {
            return Err(VNetworkError::Consensus(format!(
                "sync gap: local height is {}, received proposal height {}",
                engine.state.height, proposal.height
            )));
        }
        finalize_and_commit(engine, membership, &proposal, &qc, timestamp_ms)?;
        applied += 1;
    }
    Ok(applied)
}
