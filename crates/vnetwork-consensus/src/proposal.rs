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
    if proposal.network_id != state.network_id {
        return Err(VNetworkError::ProfileMismatch(format!(
            "proposal network_id `{}` != local `{}`",
            proposal.network_id, state.network_id
        )));
    }
    if proposal.epoch != state.validator_epoch {
        return Err(VNetworkError::Consensus(format!(
            "proposal epoch {} != active epoch {}",
            proposal.epoch, state.validator_epoch
        )));
    }
    if !proposal.validator_set_hash.is_empty() {
        let expected_vhash = compute_validator_set_hash(&membership.all_validators())?;
        if proposal.validator_set_hash != expected_vhash {
            return Err(VNetworkError::Consensus(format!(
                "proposal validator_set_hash `{}` != local `{expected_vhash}`",
                proposal.validator_set_hash
            )));
        }
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

    let local_root = state.compute_state_root()?;
    if proposal.pre_state_root != local_root {
        return Err(VNetworkError::Consensus(format!(
            "pre_state_root mismatch: proposal {}, local {}",
            proposal.pre_state_root, local_root
        )));
    }

    if let Some(bundle) = &proposal.program_source_bundle {
        let actor_pubkey = proposal
            .events
            .first()
            .map(|e| e.actor_pubkey.as_str())
            .unwrap_or(&proposer.validator_pubkey_hex);
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
