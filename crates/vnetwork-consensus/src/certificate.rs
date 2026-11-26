use crate::membership::ValidatorMembership;
use vnetwork_core::consensus_gate::verify_quorum_certificate_strict;
use vnetwork_types::*;

pub fn verify_certificate(
    membership: &ValidatorMembership,
    qc: &QuorumCertificate,
    ctx: &ConsensusVerificationContext,
) -> VResult<()> {
    verify_certificate_strict(membership, qc, ctx)
}

pub fn verify_certificate_strict(
    membership: &ValidatorMembership,
    qc: &QuorumCertificate,
    ctx: &ConsensusVerificationContext,
) -> VResult<()> {
    if membership.consensus_parameters() != &ctx.consensus_parameters {
        return Err(VNetworkError::Consensus(
            "validator membership consensus parameters diverge from verification context"
                .to_string(),
        ));
    }
    let all = membership.all_validators();
    verify_quorum_certificate_strict(qc, &all, ctx)
}
