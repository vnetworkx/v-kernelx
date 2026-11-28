use crate::eligibility::verify_proposer_eligibility;
use crate::membership::ValidatorMembership;
use vnetwork_core::authorization::{
    commit_request_nonce_event, commit_signed_operation_intent_event, validate_signed_envelope,
};
use vnetwork_core::identity::{
    commit_participant_join_intent_event, verify_and_register_participant, JoinNetworkRequest,
};
use vnetwork_core::language::validator_verify_program_bundle;
use vnetwork_core::replay::apply_event_to_state;
use vnetwork_core::state::{GenesisConfig, NetworkLedgerState};
use vnetwork_core::transition::apply_network_operation_with_genesis;
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

    if proposal.nonce_binding.is_none()
        && proposal.program_source_bundle.is_none()
        && proposal.operation_scope == "PARTICIPANT_JOIN"
    {
        let intent_events: Vec<&LedgerEvent> = proposal
            .events
            .iter()
            .filter(|event| event.operation == "PARTICIPANT_JOIN_INTENT")
            .collect();
        if intent_events.len() != 1 {
            return Err(VNetworkError::Consensus(
                "participant join proposal must contain exactly one PARTICIPANT_JOIN_INTENT"
                    .to_string(),
            ));
        }
        let intent = intent_events[0];
        let challenge: ParticipantChallenge =
            serde_json::from_value(intent.payload.get("challenge").cloned().ok_or_else(|| {
                VNetworkError::Serialization(
                    "missing challenge in PARTICIPANT_JOIN_INTENT".to_string(),
                )
            })?)
            .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
        let request: JoinNetworkRequest =
            serde_json::from_value(intent.payload.get("request").cloned().ok_or_else(|| {
                VNetworkError::Serialization(
                    "missing request in PARTICIPANT_JOIN_INTENT".to_string(),
                )
            })?)
            .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
        if intent.network_id != state.network_id
            || intent.entity_id != challenge.challenge_id
            || intent.actor_pubkey != request.participant_pubkey
            || request.challenge_id != challenge.challenge_id
        {
            return Err(VNetworkError::Consensus(
                "participant join intent does not match proposal network/identity metadata"
                    .to_string(),
            ));
        }

        // Challenges are short-lived transport state and are intentionally not
        // part of the replicated state root. Rehydrate the signed challenge
        // carried by the join intent, then run the normal enrollment validator.
        let mut expected = state.clone();
        if let Some(existing) = expected.challenges.get(&challenge.challenge_id) {
            if existing != &challenge {
                return Err(VNetworkError::Consensus(
                    "participant join challenge conflicts with local challenge state".to_string(),
                ));
            }
        } else {
            expected
                .challenges
                .insert(challenge.challenge_id.clone(), challenge.clone());
        }
        let expected_intent = commit_participant_join_intent_event(
            &mut expected,
            &challenge,
            &request,
            proposal.timestamp_ms,
        )?;
        if expected_intent.event_id != intent.event_id
            || expected_intent.event_hash != intent.event_hash
        {
            return Err(VNetworkError::Consensus(
                "PARTICIPANT_JOIN_INTENT is not the deterministic signed join event".to_string(),
            ));
        }
        verify_and_register_participant(&mut expected, &request, proposal.timestamp_ms)?;
        let generated_events = &expected.events[state.events.len()..];
        if generated_events != proposal.events.as_slice() {
            return Err(VNetworkError::Consensus(
                "participant join proposal events do not match verified challenge enrollment"
                    .to_string(),
            ));
        }
        expected.height = proposal.height;
        let computed_post = expected.compute_state_root()?;
        if computed_post != proposal.post_state_root {
            return Err(VNetworkError::Consensus(format!(
                "re-executed join post_state_root '{}' != proposal '{}'",
                computed_post, proposal.post_state_root
            )));
        }
        return Ok(());
    }

    // A participant join is the only unsigned-binding exception and was
    // independently authenticated and re-executed above. Every other proposal
    // must carry an actor-authenticated operation (or a verified .vx bundle).
    if proposal.nonce_binding.is_none() && proposal.program_source_bundle.is_none() {
        return Err(VNetworkError::Consensus(
            "proposal is missing an authenticated operation binding".to_string(),
        ));
    }

    if let Some((bound_actor, bound_request, bound_nonce)) = proposal.nonce_binding.as_ref() {
        if proposal.program_source_bundle.is_none() {
            let intent_events: Vec<&LedgerEvent> = proposal
                .events
                .iter()
                .filter(|event| event.operation == "SIGNED_OPERATION_INTENT")
                .collect();
            if intent_events.len() != 1 {
                return Err(VNetworkError::Consensus(
                    "ordinary signed operation proposal must contain exactly one SIGNED_OPERATION_INTENT"
                        .to_string(),
                ));
            }
            let intent = intent_events[0];
            let envelope: SignedRequestEnvelope = serde_json::from_value(
                intent.payload.get("envelope").cloned().ok_or_else(|| {
                    VNetworkError::Serialization(
                        "missing envelope in SIGNED_OPERATION_INTENT".to_string(),
                    )
                })?,
            )
            .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
            let operation: NetworkOperation = serde_json::from_value(
                intent.payload.get("operation").cloned().ok_or_else(|| {
                    VNetworkError::Serialization(
                        "missing operation in SIGNED_OPERATION_INTENT".to_string(),
                    )
                })?,
            )
            .map_err(|e| VNetworkError::Serialization(e.to_string()))?;

            if envelope.actor_pubkey != *bound_actor
                || envelope.request_id != *bound_request
                || envelope.nonce != *bound_nonce
                || intent.actor_pubkey != envelope.actor_pubkey
                || intent.entity_id != envelope.request_id
                || intent.network_id != state.network_id
            {
                return Err(VNetworkError::Consensus(
                    "signed operation intent does not match proposal nonce binding".to_string(),
                ));
            }
            validate_signed_envelope(state, &envelope)?;
            let operation_hash = blake3_hex(&canonical_json_bytes(&operation)?);
            if envelope.payload_hash != operation_hash {
                return Err(VNetworkError::Signature(
                    "signed operation payload hash does not match canonical operation".to_string(),
                ));
            }
            let operation_scope = serde_json::to_value(&operation)
                .map_err(|e| VNetworkError::Serialization(e.to_string()))?
                .get("op")
                .and_then(|value| value.as_str())
                .ok_or_else(|| {
                    VNetworkError::Serialization(
                        "signed operation is missing its op discriminator".to_string(),
                    )
                })?
                .to_string();
            if operation_scope != proposal.operation_scope {
                return Err(VNetworkError::Consensus(
                    "signed operation discriminator does not match proposal operation_scope"
                        .to_string(),
                ));
            }

            // Re-execute the actor-signed command against the exact pre-state.
            // This re-runs authorization and semantic preconditions on every
            // validator instead of trusting the proposer's resulting payloads.
            let mut expected = state.clone();
            let expected_intent = commit_signed_operation_intent_event(
                &mut expected,
                &envelope,
                &operation,
                proposal.timestamp_ms,
            )?;
            if expected_intent.event_id != intent.event_id
                || expected_intent.event_hash != intent.event_hash
            {
                return Err(VNetworkError::Consensus(
                    "SIGNED_OPERATION_INTENT is not the deterministic authenticated intent event"
                        .to_string(),
                ));
            }
            apply_network_operation_with_genesis(
                &mut expected,
                genesis,
                &operation,
                &envelope.actor_pubkey,
                proposal.timestamp_ms,
            )?;
            commit_request_nonce_event(
                &mut expected,
                &envelope.request_id,
                &envelope.actor_pubkey,
                envelope.nonce,
                proposal.timestamp_ms,
            )?;

            let generated_events = &expected.events[state.events.len()..];
            if generated_events != proposal.events.as_slice() {
                return Err(VNetworkError::Consensus(
                    "proposal events do not match deterministic execution of the signed operation"
                        .to_string(),
                ));
            }
            expected.height = proposal.height;
            let computed_post = expected.compute_state_root()?;
            if computed_post != proposal.post_state_root {
                return Err(VNetworkError::Consensus(format!(
                    "re-executed post_state_root '{}' != proposal '{}'",
                    computed_post, proposal.post_state_root
                )));
            }
            return Ok(());
        }
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
    match &proposal.nonce_binding {
        Some((actor, request_id, nonce)) => {
            let nonce_events: Vec<&LedgerEvent> = proposal
                .events
                .iter()
                .filter(|event| event.operation == "REQUEST_NONCE_COMMIT")
                .collect();
            if nonce_events.len() != 1 {
                return Err(VNetworkError::Consensus(
                    "signed request proposal must contain exactly one REQUEST_NONCE_COMMIT event"
                        .to_string(),
                ));
            }
            let event = nonce_events[0];
            if event.payload.get("actor_pubkey").and_then(|v| v.as_str()) != Some(actor.as_str())
                || event.payload.get("request_id").and_then(|v| v.as_str())
                    != Some(request_id.as_str())
                || event.payload.get("nonce").and_then(|v| v.as_u64()) != Some(*nonce)
                || staged.actor_nonces.get(actor) != Some(nonce)
                || !staged.seen_request_ids.contains(request_id)
            {
                return Err(VNetworkError::Consensus(
                    "proposal nonce binding is not proven by its committed event".to_string(),
                ));
            }
        }
        None => {
            return Err(VNetworkError::Consensus(
                "proposal is missing an authenticated operation binding".to_string(),
            ));
        }
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
