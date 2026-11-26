use crate::certificate::verify_certificate;
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
    verify_certificate(membership, qc)?;
    engine.commit_proposal_with_qc(proposal, qc, timestamp_ms)
}
