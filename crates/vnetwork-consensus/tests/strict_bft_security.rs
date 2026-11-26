use vnetwork_consensus::{sign_consensus_vote, validate_proposal_against_state, ValidatorMembership};
use vnetwork_core::consensus_gate::{
    verify_membership_chain_from_genesis, verify_quorum_certificate_strict,
};
use vnetwork_core::state::{GenesisConfig, NetworkLedgerState, ValidatorEpochTransition};
use vnetwork_types::*;

fn make_validators(count: usize) -> (Vec<KeypairMaterial>, Vec<ConsensusValidator>) {
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
            joined_epoch: 1,
        })
        .collect();
    (keys, validators)
}

#[test]
fn test_qc_rejects_empty_vset_hash_low_threshold_and_duplicate_pubkey() {
    let (keys, validators) = make_validators(4);

    // Threshold < 6667 bps MUST be rejected
    assert!(ValidatorMembership::try_new(validators.clone(), 5001).is_err());

    // Duplicate canonical pubkey under different validator_id MUST be rejected
    let mut dup_validators = validators.clone();
    dup_validators[1].validator_pubkey_hex = validators[0].validator_pubkey_hex.clone();
    assert!(validate_validator_set(&dup_validators).is_err());

    let membership = ValidatorMembership::new(validators.clone(), DEFAULT_BFT_QUORUM_BPS);
    let genesis = GenesisConfig::for_profile(
        NetworkProfile::Testnet,
        "vector-testnet-1",
        "Strict BFT Test",
        validators.clone(),
    );
    let genesis_comm = genesis.commitment_hash().unwrap();
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

    let base_qc = QuorumCertificate {
        certificate_id: "qc_1".to_string(),
        proposal_id: prop.proposal_id.clone(),
        proposal_digest: prop.proposal_digest.clone(),
        network_id: prop.network_id.clone(),
        genesis_commitment: genesis_comm.clone(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        height: 1,
        round: 1,
        epoch: 1,
        validator_set_hash: vset_hash,
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

    verify_quorum_certificate_strict(
        &base_qc,
        &validators,
        Some("vector-testnet-1"),
        Some(&genesis_comm),
        Some(1),
    )
    .unwrap();

    // Empty validator_set_hash bypassed prior checks — must now fail
    let mut bad_qc = base_qc.clone();
    bad_qc.validator_set_hash = String::new();
    assert!(verify_quorum_certificate_strict(&bad_qc, &validators, None, None, None).is_err());

    // Quorum threshold lowered below 6667 must fail
    let mut low_qc = base_qc.clone();
    low_qc.quorum_threshold_bps = 5001;
    assert!(verify_quorum_certificate_strict(&low_qc, &validators, None, None, None).is_err());

    // Wrong proposal digest must fail
    let mut tampered_digest_qc = base_qc.clone();
    tampered_digest_qc.proposal_digest = "a".repeat(64);
    assert!(verify_quorum_certificate_strict(&tampered_digest_qc, &validators, None, None, None).is_err());
}

#[test]
fn test_proposal_digest_tampering_and_genesis_membership_chain() {
    let (keys, validators) = make_validators(4);
    let genesis = GenesisConfig::for_profile(
        NetworkProfile::Testnet,
        "vector-testnet-1",
        "Chain Test",
        validators.clone(),
    );
    let state = NetworkLedgerState::try_new(&genesis).unwrap();
    let membership = ValidatorMembership::new(validators.clone(), DEFAULT_BFT_QUORUM_BPS);
    let pre_root = state.compute_state_root().unwrap();
    let vset_hash = membership.validator_set_hash().unwrap();

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

    // Forged validator epoch transition without valid prior-epoch QC MUST be rejected
    let (rogue_keys, rogue_vals) = make_validators(4);
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
    let forged_qc = QuorumCertificate {
        certificate_id: "qc_forged".to_string(),
        proposal_id: forged_prop.proposal_id.clone(),
        proposal_digest: forged_prop.proposal_digest.clone(),
        network_id: forged_prop.network_id.clone(),
        genesis_commitment: forged_prop.genesis_commitment.clone(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        height: 5,
        round: 1,
        epoch: 1,
        validator_set_hash: vset_hash.clone(),
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
    let bad_transition = ValidatorEpochTransition {
        epoch: 2,
        height: 5,
        prev_validator_set_hash: vset_hash,
        new_validator_set_hash: rogue_hash.clone(),
        new_validators: rogue_vals.clone(),
        transition_certificate: forged_qc,
    };

    assert!(verify_membership_chain_from_genesis(
        &validators,
        &[bad_transition],
        2,
        &rogue_hash,
        &rogue_vals
    )
    .is_err());
}
