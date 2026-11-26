use crate::certificate::verify_certificate_strict;
use crate::membership::ValidatorMembership;
use vnetwork_core::engine::ProtocolEngine;
use vnetwork_types::*;

pub fn finalize_and_commit(
    engine: &mut ProtocolEngine,
    membership: &ValidatorMembership,
    proposal: &ConsensusProposal,
    qc: &QuorumCertificate,
    timestamp_ms: u64,
) -> VResult<String> {
    let ctx = engine.state.consensus_context()?;
    verify_certificate_strict(membership, qc, &ctx)?;
    engine.commit_proposal_with_qc(proposal, qc, timestamp_ms)
}
