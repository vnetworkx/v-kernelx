use crate::eligibility::verify_proposer_eligibility;
use crate::membership::ValidatorMembership;
use vnetwork_core::authorization::record_nonce_and_request;
use vnetwork_core::language::validator_verify_program_bundle;
use vnetwork_core::replay::apply_event_to_state;
use vnetwork_core::state::{GenesisConfig, NetworkLedgerState};
use vnetwork_types::*;

pub fn validate_proposal_against_state(
    state: &NetworkLedgerState,
    genesis: &GenesisConfig,
    membership: &ValidatorMembership,
    proposal: &ConsensusProposal,
) -> VResult<()> {
    genesis.validate()?;
    let expected_genesis_commitment = genesis.commitment_hash()?;
    if state.genesis_commitment.trim().is_empty()
        || state.genesis_commitment != expected_genesis_commitment
    {
        return Err(VNetworkError::ProfileMismatch(
            "local state genesis_commitment does not match genesis configuration".to_string(),
        ));
    }

    proposal.verify_digest_and_metadata()?;

    if proposal.network_id != state.network_id {
        return Err(VNetworkError::ProfileMismatch(format!(
            "proposal network_id `{}` != local `{}`",
            proposal.network_id, state.network_id
        )));
    }
    if proposal.genesis_commitment != expected_genesis_commitment {
        return Err(VNetworkError::ProfileMismatch(format!(
            "proposal genesis_commitment `{}` != local `{expected_genesis_commitment}`",
            proposal.genesis_commitment
        )));
    }
    if proposal.protocol_version != state.protocol_version {
        return Err(VNetworkError::ProfileMismatch(format!(
            "proposal protocol_version `{}` != local `{}`",
            proposal.protocol_version, state.protocol_version
        )));
    }
    if proposal.epoch != state.validator_epoch {
        return Err(VNetworkError::Consensus(format!(
            "proposal epoch {} != active epoch {}",
            proposal.epoch, state.validator_epoch
        )));
    }
    let expected_params_hash = genesis.consensus_parameters.parameters_hash()?;
    if *membership.consensus_parameters() != genesis.consensus_parameters {
        return Err(VNetworkError::Consensus(
            "validator membership consensus parameters diverge from genesis policy".to_string(),
        ));
    }
    if proposal.consensus_parameters_hash != expected_params_hash
        || (!state.consensus_parameters_hash.is_empty()
            && proposal.consensus_parameters_hash != state.consensus_parameters_hash)
    {
        return Err(VNetworkError::Consensus(format!(
            "proposal consensus_parameters_hash `{}` != expected `{expected_params_hash}`",
            proposal.consensus_parameters_hash
        )));
    }

    let expected_vhash = membership.validator_set_hash()?;
    if proposal.validator_set_hash != expected_vhash {
        return Err(VNetworkError::Consensus(format!(
            "proposal validator_set_hash `{}` != local `{expected_vhash}`",
            proposal.validator_set_hash
        )));
    }

    let proposer = verify_proposer_eligibility(membership, &proposal.proposer_validator_id)?;
    proposal.verify_proposer_signature(&proposer)?;

    if proposal.height != state.height + 1 {
        return Err(VNetworkError::Consensus(format!(
            "unexpected proposal height {}, expected {}",
            proposal.height,
            state.height + 1
        )));
    }

    let expected_parent = state.expected_parent_commitment();
    if proposal.parent_commitment != expected_parent {
        return Err(VNetworkError::Consensus(format!(
            "proposal parent_commitment `{}` != local `{expected_parent}`",
            proposal.parent_commitment
        )));
    }

    let local_root = state.compute_state_root()?;
    if proposal.pre_state_root != local_root {
        return Err(VNetworkError::Consensus(format!(
            "pre_state_root mismatch: proposal {}, local {}",
            proposal.pre_state_root, local_root
        )));
    }

    if let Some(bundle) = &proposal.program_source_bundle {
        let (actor_pubkey, _, _) = proposal.nonce_binding.as_ref().ok_or_else(|| {
            VNetworkError::Authorization(
                "program proposal missing authenticated nonce_binding".to_string(),
            )
        })?;
        validator_verify_program_bundle(state, genesis, bundle, proposal, actor_pubkey)?;
    }

    let mut staged = state.clone();
    for ev in &proposal.events {
        if !ev.verify_hashes()? {
            return Err(VNetworkError::Consensus(format!(
                "event {} failed hash check in proposal {}",
                ev.event_id, proposal.proposal_id
            )));
        }
        apply_event_to_state(&mut staged, ev)?;
    }
    if let Some((actor, req_id, nonce)) = &proposal.nonce_binding {
        record_nonce_and_request(&mut staged, req_id, actor, *nonce);
    }
    staged.height = proposal.height;
    let computed_post = staged.compute_state_root()?;
    if computed_post != proposal.post_state_root {
        return Err(VNetworkError::Consensus(format!(
            "re-executed post_state_root `{computed_post}` != proposal `{}`",
            proposal.post_state_root
        )));
    }

    Ok(())
}
