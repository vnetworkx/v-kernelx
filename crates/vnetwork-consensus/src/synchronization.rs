use crate::finality::finalize_and_commit;
use crate::membership::ValidatorMembership;
use vnetwork_core::consensus_gate::verify_membership_chain_from_genesis;
use vnetwork_core::engine::ProtocolEngine;
use vnetwork_types::*;

pub fn apply_verified_sync_batch(
    engine: &mut ProtocolEngine,
    membership: &ValidatorMembership,
    commits: &[(ConsensusProposal, QuorumCertificate)],
    timestamp_ms: u64,
) -> VResult<usize> {
    let expected_genesis_commitment = engine.genesis.commitment_hash()?;
    if engine.state.genesis_commitment != expected_genesis_commitment {
        return Err(VNetworkError::ProfileMismatch(
            "local engine genesis_commitment does not match genesis config".to_string(),
        ));
    }
    let ctx = engine
        .genesis
        .consensus_context_for_epoch(engine.state.validator_epoch)?;
    if membership.consensus_parameters() != &ctx.consensus_parameters {
        return Err(VNetworkError::Consensus(
            "validator membership consensus parameters diverge from genesis".to_string(),
        ));
    }
    let expected_vhash = membership.validator_set_hash()?;
    verify_membership_chain_from_genesis(
        &engine.genesis.initial_validators,
        engine.genesis.genesis_epoch,
        &ctx,
        &engine.state.validator_membership_history,
        engine.state.validator_epoch,
        &expected_vhash,
        &membership.all_validators(),
    )?;

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
        if proposal.network_id != engine.state.network_id
            || proposal.genesis_commitment != expected_genesis_commitment
            || proposal.protocol_version != engine.state.protocol_version
            || proposal.consensus_parameters_hash != ctx.consensus_parameters_hash
        {
            return Err(VNetworkError::ProfileMismatch(
                "synced proposal network, genesis commitment, consensus parameters, or protocol version mismatch"
                    .to_string(),
            ));
        }
        finalize_and_commit(engine, membership, &proposal, &qc, timestamp_ms)?;
        applied += 1;
    }
    Ok(applied)
}
