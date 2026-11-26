use crate::membership::ValidatorMembership;
use vnetwork_core::consensus_gate::verify_quorum_certificate;
use vnetwork_types::*;

pub fn verify_certificate(
    membership: &ValidatorMembership,
    qc: &QuorumCertificate,
) -> VResult<()> {
    let active = membership.active_validators();
    verify_quorum_certificate(qc, &active)
}
