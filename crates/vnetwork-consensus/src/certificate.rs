use crate::membership::ValidatorMembership;
use vnetwork_core::consensus_gate::verify_quorum_certificate_strict;
use vnetwork_types::*;

pub fn verify_certificate(
    membership: &ValidatorMembership,
    qc: &QuorumCertificate,
) -> VResult<()> {
    let all = membership.all_validators();
    verify_quorum_certificate_strict(qc, &all, None, None, None)
}

pub fn verify_certificate_strict(
    membership: &ValidatorMembership,
    qc: &QuorumCertificate,
    expected_network_id: Option<&str>,
    expected_genesis_commitment: Option<&str>,
    expected_epoch: Option<u64>,
) -> VResult<()> {
    let all = membership.all_validators();
    verify_quorum_certificate_strict(
        qc,
        &all,
        expected_network_id,
        expected_genesis_commitment,
        expected_epoch,
    )
}
