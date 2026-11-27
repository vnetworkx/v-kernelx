use vnetwork_consensus::{sign_consensus_vote, validate_proposal_against_state, ValidatorMembership};
use vnetwork_core::consensus_gate::{
    replay_validator_epoch_history, verify_membership_chain_from_genesis,
    verify_quorum_certificate_strict,
};
use vnetwork_core::authorization::{
    commit_request_nonce_event, commit_signed_operation_intent_event,
};
use vnetwork_core::identity::{
    canonical_join_signing_bytes, issue_participant_challenge, verify_and_register_participant,
    JoinNetworkRequest,
};
use vnetwork_core::state::{GenesisConfig, NetworkLedgerState, ValidatorEpochTransition};
use vnetwork_types::*;

fn make_validators(count: usize, joined_epoch: u64) -> (Vec<KeypairMaterial>, Vec<ConsensusValidator>) {
    let keys: Vec<KeypairMaterial> = (0..count)
        .map(|_| KeypairMaterial::generate("validator"))
        .collect();
    let validators = keys
        .iter()
        .enumerate()
        .map(|(i, k)| ConsensusValidator {
            validator_id: format!("val_{}", i + 1),
            node_id: format!("nod_val_{}", i + 1),
            validator_pubkey_hex: k.public_key_hex.clone(),
            weight: 100,
            active: true,
            joined_epoch,
        })
        .collect();
    (keys, validators)
}

#[test]
fn test_qc_rejects_empty_vset_hash_low_threshold_wrong_policy_and_duplicate_pubkey() {
    let (keys, validators) = make_validators(4, 1);

    // Threshold < 6667 bps MUST be rejected
    assert!(ValidatorMembership::try_new(validators.clone(), 5001).is_err());

    // Duplicate canonical pubkey under different validator_id MUST be rejected
    let mut dup_validators = validators.clone();
    dup_validators[1].validator_pubkey_hex = validators[0].validator_pubkey_hex.clone();
    assert!(validate_validator_set(&dup_validators).is_err());

    let membership = ValidatorMembership::try_new(validators.clone(), DEFAULT_BFT_QUORUM_BPS).unwrap();
    let genesis = GenesisConfig::for_profile(
        NetworkProfile::Testnet,
        "vector-testnet-1",
        "Strict BFT Test",
        validators.clone(),
    );
    let genesis_comm = genesis.commitment_hash().unwrap();
    let params_hash = genesis.consensus_parameters.parameters_hash().unwrap();
    let ctx = genesis.consensus_context_for_epoch(1).unwrap();
    let vset_hash = membership.validator_set_hash().unwrap();

    let mut prop = ConsensusProposal {
        proposal_id: String::new(),
        proposal_version: PROPOSAL_VERSION,
        network_id: "vector-testnet-1".to_string(),
        genesis_commitment: genesis_comm.clone(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        height: 1,
        round: 1,
        epoch: 1,
        validator_set_hash: vset_hash.clone(),
        consensus_parameters_hash: params_hash.clone(),
        proposer_validator_id: "val_1".to_string(),
        parent_commitment: genesis_comm.clone(),
        pre_state_root: "pre".to_string(),
        post_state_root: "post".to_string(),
        proposal_digest: String::new(),
        operation_scope: "OP".to_string(),
        events: vec![],
        program_id: None,
        tx_id: None,
        program_source_bundle: None,
        nonce_binding: None,
        execution_params: Default::default(),
        timestamp_ms: 1000,
        proposer_signature: String::new(),
    };
    prop.finalize_digest_and_id().unwrap();
    prop.proposer_signature = keys[0].sign(&prop.canonical_signing_bytes().unwrap()).unwrap();

    let votes = vec![
        sign_consensus_vote(&prop, &validators[0], &keys[0], true, 1001).unwrap(),
        sign_consensus_vote(&prop, &validators[1], &keys[1], true, 1002).unwrap(),
        sign_consensus_vote(&prop, &validators[2], &keys[2], true, 1003).unwrap(),
    ];

    let mut base_qc = QuorumCertificate {
        certificate_id: String::new(),
        proposal_id: prop.proposal_id.clone(),
        proposal_digest: prop.proposal_digest.clone(),
        network_id: prop.network_id.clone(),
        genesis_commitment: genesis_comm.clone(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        height: 1,
        round: 1,
        epoch: 1,
        validator_set_hash: vset_hash,
        consensus_parameters_hash: params_hash.clone(),
        parent_commitment: genesis_comm.clone(),
        pre_state_root: "pre".to_string(),
        post_state_root: "post".to_string(),
        operation_scope: "OP".to_string(),
        vote_phase: VotePhase::Commit,
        ordered_event_ids: vec![],
        event_hashes: vec![],
        total_weight: 400,
        approving_weight: 300,
        quorum_threshold_bps: DEFAULT_BFT_QUORUM_BPS,
        votes,
        finalized_at_ms: 1003,
    };
    base_qc.finalize_certificate_id().unwrap();

    verify_quorum_certificate_strict(&base_qc, &validators, &ctx).unwrap();

    // Empty validator_set_hash MUST fail
    let mut bad_qc = base_qc.clone();
    bad_qc.validator_set_hash = String::new();
    assert!(verify_quorum_certificate_strict(&bad_qc, &validators, &ctx).is_err());

    // Quorum threshold lowered below 6667 MUST fail
    let mut low_qc = base_qc.clone();
    low_qc.quorum_threshold_bps = 5001;
    assert!(verify_quorum_certificate_strict(&low_qc, &validators, &ctx).is_err());

    // Valid QC with 6667 bps MUST fail when network consensus policy requires 8000 bps
    let strict_params = NetworkConsensusParameters::with_quorum_threshold_bps(8000).unwrap();
    let strict_ctx = ConsensusVerificationContext::new(
        "vector-testnet-1",
        genesis_comm.clone(),
        PROTOCOL_VERSION,
        Some(1),
        strict_params,
    )
    .unwrap();
    assert!(verify_quorum_certificate_strict(&base_qc, &validators, &strict_ctx).is_err());

    // Wrong consensus_parameters_hash MUST fail
    let mut bad_params_qc = base_qc.clone();
    bad_params_qc.consensus_parameters_hash = "b".repeat(64);
    assert!(verify_quorum_certificate_strict(&bad_params_qc, &validators, &ctx).is_err());

    // Altered certificate_id MUST fail canonical verification
    let mut altered_id_qc = base_qc.clone();
    altered_id_qc.certificate_id = "qc_1_forged".to_string();
    assert!(verify_quorum_certificate_strict(&altered_id_qc, &validators, &ctx).is_err());

    // Certificate digest MUST reject duplicate votes with same pubkey/validator
    let mut dup_vote_qc = base_qc.clone();
    dup_vote_qc.votes.push(dup_vote_qc.votes[0].clone());
    assert!(dup_vote_qc.certificate_digest().is_err());

    // Wrong proposal digest MUST fail
    let mut tampered_digest_qc = base_qc.clone();
    tampered_digest_qc.proposal_digest = "a".repeat(64);
    assert!(verify_quorum_certificate_strict(&tampered_digest_qc, &validators, &ctx).is_err());
}

#[test]
fn test_proposal_digest_tampering_and_genesis_membership_chain() {
    let (keys, validators) = make_validators(4, 1);
    let genesis = GenesisConfig::for_profile(
        NetworkProfile::Testnet,
        "vector-testnet-1",
        "Chain Test",
        validators.clone(),
    );
    let state = NetworkLedgerState::try_new(&genesis).unwrap();
    let membership = ValidatorMembership::try_new(validators.clone(), DEFAULT_BFT_QUORUM_BPS).unwrap();
    let pre_root = state.compute_state_root().unwrap();
    let vset_hash = membership.validator_set_hash().unwrap();
    let params_hash = genesis.consensus_parameters.parameters_hash().unwrap();
    let ctx = genesis.consensus_context_for_epoch(1).unwrap();

    let mut prop = ConsensusProposal {
        proposal_id: String::new(),
        proposal_version: PROPOSAL_VERSION,
        network_id: "vector-testnet-1".to_string(),
        genesis_commitment: genesis.commitment_hash().unwrap(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        height: 1,
        round: 1,
        epoch: 1,
        validator_set_hash: vset_hash.clone(),
        consensus_parameters_hash: params_hash.clone(),
        proposer_validator_id: "val_1".to_string(),
        parent_commitment: state.expected_parent_commitment(),
        pre_state_root: pre_root.clone(),
        post_state_root: pre_root.clone(),
        proposal_digest: String::new(),
        operation_scope: "NOOP".to_string(),
        events: vec![],
        program_id: None,
        tx_id: None,
        program_source_bundle: None,
        nonce_binding: None,
        execution_params: Default::default(),
        timestamp_ms: 2000,
        proposer_signature: String::new(),
    };
    prop.finalize_digest_and_id().unwrap();
    prop.proposer_signature = keys[0].sign(&prop.canonical_signing_bytes().unwrap()).unwrap();

    // Tampered execution_params breaks proposal digest verification
    let mut tampered = prop.clone();
    tampered
        .execution_params
        .insert("evil".to_string(), serde_json::json!(true));
    assert!(validate_proposal_against_state(&state, &genesis, &membership, &tampered).is_err());

    // Valid transition from epoch 5 -> epoch 6 (tests non-1 genesis_epoch support)
    let (_epoch5_keys, epoch5_vals) = make_validators(4, 5);
    let genesis_e5 = {
        let mut g = GenesisConfig::for_profile(
            NetworkProfile::Testnet,
            "vector-testnet-1",
            "Non-One Genesis Epoch",
            validators.clone(),
        );
        g.genesis_epoch = 5;
        g
    };
    let e5_ctx = genesis_e5.consensus_context_for_epoch(5).unwrap();
    let e5_hash = validate_validator_set(&validators).unwrap();
    let e6_hash = validate_validator_set(&epoch5_vals).unwrap();
    let mut valid_tr = ValidatorEpochTransition {
        prev_epoch: 5,
        epoch: 6,
        height: 10,
        prev_validator_set_hash: e5_hash.clone(),
        new_validator_set_hash: e6_hash.clone(),
        consensus_parameters_hash: e5_ctx.consensus_parameters_hash.clone(),
        transition_payload_digest: String::new(),
        new_validators: epoch5_vals.clone(),
        transition_certificate: QuorumCertificate {
            certificate_id: String::new(),
            proposal_id: String::new(),
            proposal_digest: String::new(),
            network_id: "vector-testnet-1".to_string(),
            genesis_commitment: e5_ctx.genesis_commitment.clone(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            height: 10,
            round: 1,
            epoch: 5,
            validator_set_hash: e5_hash.clone(),
            consensus_parameters_hash: e5_ctx.consensus_parameters_hash.clone(),
            parent_commitment: e5_ctx.genesis_commitment.clone(),
            pre_state_root: "pre_tr".to_string(),
            post_state_root: String::new(),
            operation_scope: "VALIDATOR_EPOCH_TRANSITION".to_string(),
            vote_phase: VotePhase::Commit,
            ordered_event_ids: vec![],
            event_hashes: vec![],
            total_weight: 400,
            approving_weight: 300,
            quorum_threshold_bps: DEFAULT_BFT_QUORUM_BPS,
            votes: vec![],
            finalized_at_ms: 2500,
        },
    };
    valid_tr.finalize_payload_digest().unwrap();
    let mut tr_prop = ConsensusProposal {
        proposal_id: String::new(),
        proposal_version: PROPOSAL_VERSION,
        network_id: "vector-testnet-1".to_string(),
        genesis_commitment: e5_ctx.genesis_commitment.clone(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        height: 10,
        round: 1,
        epoch: 5,
        validator_set_hash: e5_hash.clone(),
        consensus_parameters_hash: e5_ctx.consensus_parameters_hash.clone(),
        proposer_validator_id: "val_1".to_string(),
        parent_commitment: e5_ctx.genesis_commitment.clone(),
        pre_state_root: "pre_tr".to_string(),
        post_state_root: valid_tr.transition_payload_digest.clone(),
        proposal_digest: String::new(),
        operation_scope: "VALIDATOR_EPOCH_TRANSITION".to_string(),
        events: vec![],
        program_id: None,
        tx_id: None,
        program_source_bundle: None,
        nonce_binding: None,
        execution_params: Default::default(),
        timestamp_ms: 2500,
        proposer_signature: String::new(),
    };
    tr_prop.finalize_digest_and_id().unwrap();
    let tr_votes = vec![
        sign_consensus_vote(&tr_prop, &validators[0], &keys[0], true, 2501).unwrap(),
        sign_consensus_vote(&tr_prop, &validators[1], &keys[1], true, 2502).unwrap(),
        sign_consensus_vote(&tr_prop, &validators[2], &keys[2], true, 2503).unwrap(),
    ];
    valid_tr.transition_certificate.proposal_id = tr_prop.proposal_id;
    valid_tr.transition_certificate.proposal_digest = tr_prop.proposal_digest;
    valid_tr.transition_certificate.post_state_root = valid_tr.transition_payload_digest.clone();
    valid_tr.transition_certificate.votes = tr_votes;
    valid_tr.transition_certificate.finalize_certificate_id().unwrap();

    let (replayed_ep, replayed_vals, _) =
        replay_validator_epoch_history(&validators, 5, &e5_ctx, &[valid_tr.clone()]).unwrap();
    assert_eq!(replayed_ep, 6);
    assert_eq!(replayed_vals, epoch5_vals);

    // Substituting new_validators while reusing a real prior-epoch QC MUST be rejected
    let (_alt_keys, alt_vals) = make_validators(4, 6);
    let alt_hash = validate_validator_set(&alt_vals).unwrap();
    let mut substituted = valid_tr.clone();
    substituted.new_validators = alt_vals.clone();
    substituted.new_validator_set_hash = alt_hash.clone();
    substituted.finalize_payload_digest().unwrap();
    assert!(verify_membership_chain_from_genesis(
        &validators,
        5,
        &e5_ctx,
        &[substituted],
        6,
        &alt_hash,
        &alt_vals,
    )
    .is_err());

    // Forged validator epoch transition signed by rogue keys MUST be rejected
    let (rogue_keys, rogue_vals) = make_validators(4, 2);
    let rogue_hash = validate_validator_set(&rogue_vals).unwrap();
    let mut forged_prop = ConsensusProposal {
        proposal_id: String::new(),
        proposal_version: PROPOSAL_VERSION,
        network_id: "vector-testnet-1".to_string(),
        genesis_commitment: genesis.commitment_hash().unwrap(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        height: 5,
        round: 1,
        epoch: 1,
        validator_set_hash: vset_hash.clone(),
        consensus_parameters_hash: params_hash.clone(),
        proposer_validator_id: "val_1".to_string(),
        parent_commitment: "p".to_string(),
        pre_state_root: "pre".to_string(),
        post_state_root: "post".to_string(),
        proposal_digest: String::new(),
        operation_scope: "EPOCH".to_string(),
        events: vec![],
        program_id: None,
        tx_id: None,
        program_source_bundle: None,
        nonce_binding: None,
        execution_params: Default::default(),
        timestamp_ms: 3000,
        proposer_signature: String::new(),
    };
    forged_prop.finalize_digest_and_id().unwrap();
    let rogue_vote =
        sign_consensus_vote(&forged_prop, &rogue_vals[0], &rogue_keys[0], true, 3001).unwrap();
    let mut forged_qc = QuorumCertificate {
        certificate_id: String::new(),
        proposal_id: forged_prop.proposal_id.clone(),
        proposal_digest: forged_prop.proposal_digest.clone(),
        network_id: forged_prop.network_id.clone(),
        genesis_commitment: forged_prop.genesis_commitment.clone(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        height: 5,
        round: 1,
        epoch: 1,
        validator_set_hash: vset_hash.clone(),
        consensus_parameters_hash: params_hash.clone(),
        parent_commitment: "p".to_string(),
        pre_state_root: "pre".to_string(),
        post_state_root: "post".to_string(),
        operation_scope: "EPOCH".to_string(),
        vote_phase: VotePhase::Commit,
        ordered_event_ids: vec![],
        event_hashes: vec![],
        total_weight: 400,
        approving_weight: 100,
        quorum_threshold_bps: DEFAULT_BFT_QUORUM_BPS,
        votes: vec![rogue_vote],
        finalized_at_ms: 3001,
    };
    forged_qc.finalize_certificate_id().unwrap();
    let mut bad_transition = ValidatorEpochTransition {
        prev_epoch: 1,
        epoch: 2,
        height: 5,
        prev_validator_set_hash: vset_hash,
        new_validator_set_hash: rogue_hash.clone(),
        consensus_parameters_hash: params_hash,
        transition_payload_digest: String::new(),
        new_validators: rogue_vals.clone(),
        transition_certificate: forged_qc,
    };
    bad_transition.finalize_payload_digest().unwrap();

    assert!(verify_membership_chain_from_genesis(
        &validators,
        1,
        &ctx,
        &[bad_transition],
        2,
        &rogue_hash,
        &rogue_vals
    )
    .is_err());
}


#[test]
fn ordinary_signed_operation_is_reexecuted_before_validator_vote() {
    let (validator_keys, validators) = make_validators(4, 1);
    let genesis = GenesisConfig::for_profile(
        NetworkProfile::Testnet,
        "vector-testnet-semantic-validation",
        "Semantic Validation Test",
        validators.clone(),
    );
    let membership =
        ValidatorMembership::try_new(validators.clone(), DEFAULT_BFT_QUORUM_BPS).unwrap();
    let mut state = NetworkLedgerState::try_new(&genesis).unwrap();

    // Enroll a normal member through the real signed challenge path. Open
    // enrollment gives Network membership, but it does not confer governance.
    let actor = KeypairMaterial::generate("ordinary-member");
    let node = KeypairMaterial::generate("ordinary-node");
    let challenge = issue_participant_challenge(&mut state, 1_000);
    let requested_scopes = vec![ParticipationLevel::Network];
    let join_bytes = canonical_join_signing_bytes(
        &challenge,
        &actor.public_key_hex,
        &node.public_key_hex,
        &requested_scopes,
    )
    .unwrap();
    let join = JoinNetworkRequest {
        challenge_id: challenge.challenge_id,
        participant_pubkey: actor.public_key_hex.clone(),
        node_pubkey: node.public_key_hex.clone(),
        display_name: "ordinary-member".to_string(),
        node_kind: NodeKind::FullNode,
        requested_scopes,
        advertised_addresses: vec![],
        participant_signature: actor.sign(&join_bytes).unwrap(),
        node_signature: node.sign(&join_bytes).unwrap(),
        scope_authorizations: vec![],
    };
    verify_and_register_participant(&mut state, &join, 1_001).unwrap();

    // The member signs a syntactically valid operation that they are not
    // authorized to perform. A malicious proposer can construct a plausible
    // event-only post-state, but honest validators must re-run the operation.
    let operation = NetworkOperation::CreateSpace {
        name: "Unauthorized Space".to_string(),
        visibility: "public".to_string(),
        ghost: false,
    };
    let request_id = "req_unauthorized_space".to_string();
    let network_id = state.network_id.clone();
    let payload_hash = blake3_hex(&canonical_json_bytes(&operation).unwrap());
    let signing_bytes = SignedRequestEnvelope::canonical_signing_bytes(
        &network_id,
        &request_id,
        &actor.public_key_hex,
        1,
        2_000,
        &payload_hash,
    )
    .unwrap();
    let envelope = SignedRequestEnvelope {
        request_id: request_id.clone(),
        network_id: network_id.clone(),
        actor_pubkey: actor.public_key_hex.clone(),
        nonce: 1,
        timestamp_ms: 2_000,
        signature: actor.sign(&signing_bytes).unwrap(),
        payload_hash,
    };

    // Forge the proposer-supplied events without applying CreateSpace. This
    // would pass a replay-only validator, because the resulting state root is
    // internally consistent with these events.
    let mut forged_state = state.clone();
    let intent = commit_signed_operation_intent_event(
        &mut forged_state,
        &envelope,
        &operation,
        2_000,
    )
    .unwrap();
    let nonce_event = commit_request_nonce_event(
        &mut forged_state,
        &request_id,
        &actor.public_key_hex,
        1,
        2_000,
    )
    .unwrap();
    forged_state.height = state.height + 1;
    let post_state_root = forged_state.compute_state_root().unwrap();

    let mut proposal = ConsensusProposal {
        proposal_id: String::new(),
        proposal_version: PROPOSAL_VERSION,
        network_id: network_id.clone(),
        genesis_commitment: genesis.commitment_hash().unwrap(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        height: state.height + 1,
        round: 1,
        epoch: state.validator_epoch,
        validator_set_hash: membership.validator_set_hash().unwrap(),
        consensus_parameters_hash: genesis.consensus_parameters.parameters_hash().unwrap(),
        proposer_validator_id: validators[0].validator_id.clone(),
        parent_commitment: state.expected_parent_commitment(),
        pre_state_root: state.compute_state_root().unwrap(),
        post_state_root,
        proposal_digest: String::new(),
        operation_scope: "CreateSpace".to_string(),
        events: vec![intent, nonce_event],
        program_id: None,
        tx_id: Some("tx_unauthorized_space".to_string()),
        program_source_bundle: None,
        nonce_binding: Some((actor.public_key_hex.clone(), request_id, 1)),
        execution_params: Default::default(),
        timestamp_ms: 2_000,
        proposer_signature: String::new(),
    };
    proposal.finalize_digest_and_id().unwrap();
    proposal.proposer_signature = validator_keys[0]
        .sign(&proposal.canonical_signing_bytes().unwrap())
        .unwrap();

    assert!(
        validate_proposal_against_state(&state, &genesis, &membership, &proposal).is_err(),
        "validators must reject a signed but unauthorized operation before voting"
    );
}
