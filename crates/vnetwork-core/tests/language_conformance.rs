use std::collections::BTreeMap;
use std::path::Path;
use vnetwork_core::engine::ProtocolEngine;
use vnetwork_core::identity::{
    canonical_join_signing_bytes, JoinNetworkRequest, SignedScopeAuthorization,
};
use vnetwork_core::language::{compile_vx_source, SubmitProgramRequest};
use vnetwork_core::state::GenesisConfig;
use vnetwork_core::token::canonical_transfer_approval_bytes;
use vnetwork_core::wallet::canonical_wallet_pop_bytes;
use vnetwork_types::*;

fn single_val_qc(
    prop: &ConsensusProposal,
    val_kp: &KeypairMaterial,
    _qc_id: &str,
    ts: u64,
) -> QuorumCertificate {
    let mut vote = ConsensusVote {
        proposal_id: prop.proposal_id.clone(),
        proposal_digest: prop.proposal_digest.clone(),
        network_id: prop.network_id.clone(),
        genesis_commitment: prop.genesis_commitment.clone(),
        protocol_version: prop.protocol_version.clone(),
        height: prop.height,
        round: prop.round,
        epoch: prop.epoch,
        validator_set_hash: prop.validator_set_hash.clone(),
        consensus_parameters_hash: prop.consensus_parameters_hash.clone(),
        parent_commitment: prop.parent_commitment.clone(),
        pre_state_root: prop.pre_state_root.clone(),
        post_state_root: prop.post_state_root.clone(),
        operation_scope: prop.operation_scope.clone(),
        vote_phase: VotePhase::Commit,
        validator_id: "val_1".to_string(),
        validator_pubkey_hex: val_kp.public_key_hex.clone(),
        approve: true,
        timestamp_ms: ts,
        signature: String::new(),
    };
    let bytes = vote.canonical_signing_bytes().unwrap();
    vote.signature = val_kp.sign(&bytes).unwrap();
    let mut qc = QuorumCertificate {
        certificate_id: String::new(),
        proposal_id: prop.proposal_id.clone(),
        proposal_digest: prop.proposal_digest.clone(),
        network_id: prop.network_id.clone(),
        genesis_commitment: prop.genesis_commitment.clone(),
        protocol_version: prop.protocol_version.clone(),
        height: prop.height,
        round: prop.round,
        epoch: prop.epoch,
        validator_set_hash: prop.validator_set_hash.clone(),
        consensus_parameters_hash: prop.consensus_parameters_hash.clone(),
        parent_commitment: prop.parent_commitment.clone(),
        pre_state_root: prop.pre_state_root.clone(),
        post_state_root: prop.post_state_root.clone(),
        operation_scope: prop.operation_scope.clone(),
        vote_phase: VotePhase::Commit,
        ordered_event_ids: prop.ordered_event_ids(),
        event_hashes: prop.ordered_event_hashes(),
        total_weight: 100,
        approving_weight: 100,
        quorum_threshold_bps: DEFAULT_BFT_QUORUM_BPS,
        votes: vec![vote],
        finalized_at_ms: ts,
    };
    qc.finalize_certificate_id().unwrap();
    qc
}

fn signed_scope_auth(
    grantor: &KeypairMaterial,
    target_pubkey: &str,
    network_id: &str,
    scopes: Vec<ParticipationLevel>,
) -> SignedScopeAuthorization {
    let mut auth = SignedScopeAuthorization {
        target_participant_pubkey: target_pubkey.to_string(),
        grantor_pubkey: grantor.public_key_hex.clone(),
        scopes,
        target_id: None,
        expires_at_ms: None,
        authorization_basis: "genesis_validator_delegation".to_string(),
        signature: String::new(),
    };
    let bytes = auth.canonical_signing_bytes(network_id).unwrap();
    auth.signature = grantor.sign(&bytes).unwrap();
    auth
}

fn make_dev_engine() -> (ProtocolEngine, KeypairMaterial, KeypairMaterial, KeypairMaterial) {
    let val_kp = KeypairMaterial::generate("validator");
    let genesis = GenesisConfig::for_profile(
        NetworkProfile::Development,
        "vector-devnet-1",
        "Dev Network",
        vec![ConsensusValidator {
            validator_id: "val_1".to_string(),
            node_id: "nod_val_1".to_string(),
            validator_pubkey_hex: val_kp.public_key_hex.clone(),
            weight: 100,
            active: true,
            joined_epoch: 1,
        }],
    )
    .with_drain_policy(
        DrainPolicy::new(
            ScopeDrainRate::ConfiguredBps(0),
            ScopeDrainRate::ConfiguredBps(0),
            ScopeDrainRate::ConfiguredBps(50),
            ScopeDrainRate::ConfiguredBps(150),
        )
        .unwrap(),
    );
    let mut engine = ProtocolEngine::new(genesis);

    let participant_kp = KeypairMaterial::generate("participant");
    let node_kp = KeypairMaterial::generate("node");
    let ch = engine.issue_challenge(1_000);
    let scopes = vec![
        ParticipationLevel::Network,
        ParticipationLevel::Space,
        ParticipationLevel::Region,
        ParticipationLevel::Wallet,
        ParticipationLevel::Token,
    ];
    let join_bytes = canonical_join_signing_bytes(
        &ch,
        &participant_kp.public_key_hex,
        &node_kp.public_key_hex,
        &scopes,
    )
    .unwrap();
    let scope_auth = signed_scope_auth(
        &val_kp,
        &participant_kp.public_key_hex,
        "vector-devnet-1",
        vec![
            ParticipationLevel::Space,
            ParticipationLevel::Region,
            ParticipationLevel::Wallet,
            ParticipationLevel::Token,
        ],
    );
    let join_req = JoinNetworkRequest {
        challenge_id: ch.challenge_id,
        participant_pubkey: participant_kp.public_key_hex.clone(),
        node_pubkey: node_kp.public_key_hex.clone(),
        display_name: "conformance-user".to_string(),
        node_kind: NodeKind::FullNode,
        requested_scopes: scopes,
        advertised_addresses: vec![],
        participant_signature: participant_kp.sign(&join_bytes).unwrap(),
        node_signature: node_kp.sign(&join_bytes).unwrap(),
        scope_authorizations: vec![scope_auth],
    };
    let (_, _, prop, _) = engine
        .stage_participant_join(&join_req, "val_1", |b| val_kp.sign(b), 1_001)
        .unwrap();
    let qc = single_val_qc(&prop, &val_kp, "qc_1", 1_002);
    engine.commit_proposal_with_qc(&prop, &qc, 1_002).unwrap();

    (engine, val_kp, participant_kp, node_kp)
}

fn sign_program_req(
    file_name: &str,
    source_bytes: &str,
    modules: BTreeMap<String, String>,
    actor: &KeypairMaterial,
    network_id: &str,
    nonce: u64,
    request_id: &str,
) -> SubmitProgramRequest {
    let mut req = SubmitProgramRequest {
        file_name: file_name.to_string(),
        source_bytes: source_bytes.to_string(),
        modules,
        actor_pubkey: actor.public_key_hex.clone(),
        network_id: network_id.to_string(),
        request_id: request_id.to_string(),
        nonce,
        signature: String::new(),
        execution_params: BTreeMap::new(),
    };
    let bytes = req.canonical_signing_bytes().unwrap();
    req.signature = actor.sign(&bytes).unwrap();
    req
}

fn sign_operation(
    actor: &KeypairMaterial,
    network_id: &str,
    nonce: u64,
    request_id: &str,
    ts: u64,
    op: &NetworkOperation,
) -> SignedRequestEnvelope {
    let payload_hash = blake3_hex(&canonical_json_bytes(op).unwrap());
    let mut env = SignedRequestEnvelope {
        actor_pubkey: actor.public_key_hex.clone(),
        network_id: network_id.to_string(),
        request_id: request_id.to_string(),
        nonce,
        timestamp_ms: ts,
        payload_hash,
        signature: String::new(),
    };
    let bytes = env.canonical_signing_bytes().unwrap();
    env.signature = actor.sign(&bytes).unwrap();
    env
}

#[test]
fn test_all_example_vx_programs_compile_cleanly() {
    let examples_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples/vector-language");

    for entry in std::fs::read_dir(&examples_dir).unwrap() {
        let path = entry.unwrap().path();
        if matches!(path.extension().and_then(|e| e.to_str()), Some("vx") | Some("vdx")) {
            let src = std::fs::read_to_string(&path).unwrap();
            let fname = path.file_name().unwrap().to_str().unwrap();
            let compiled = compile_vx_source(&src, fname, &BTreeMap::new(), Some(&examples_dir))
                .unwrap_or_else(|e| panic!("failed to compile {fname}: {e}"));
            assert!(!compiled.program_hash.is_empty(), "{fname} missing program hash");
        }
    }
}

#[test]
fn test_vdx_import_tamper_and_runtime_op_rejection() {
    let mut mods = BTreeMap::new();
    mods.insert(
        "policies.vdx".to_string(),
        "space create ModSpace { visibility = \"public\" }".to_string(),
    );
    let wrong_hash_src = r#"
import "policies.vdx" blake3 "0000000000000000000000000000000000000000000000000000000000000000";
query network;
"#;
    let err = compile_vx_source(wrong_hash_src, "main.vx", &mods, None).unwrap_err();
    assert!(err.to_string().contains("hash mismatch"));

    let runtime_in_vdx = r#"transfer "X" from "A" to "B" amount 10;"#;
    let vdx_err = compile_vx_source(runtime_in_vdx, "bad.vdx", &BTreeMap::new(), None).unwrap_err();
    assert!(vdx_err.to_string().contains(".vdx"));
}

#[test]
fn test_rejects_module_path_traversal_and_absolute_imports() {
    let base = std::env::temp_dir().join(format!("vx_trav_{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&base).unwrap();
    let outside = base.parent().unwrap().join(format!("outside_{}.vdx", uuid::Uuid::new_v4().simple()));
    std::fs::write(&outside, "space create Outside { visibility = \"public\" }").unwrap();

    let traversal_src = format!(
        "import \"../{}\";\nquery network;\n",
        outside.file_name().unwrap().to_str().unwrap()
    );
    let err = compile_vx_source(&traversal_src, "trav.vx", &BTreeMap::new(), Some(&base)).unwrap_err();
    assert!(err.to_string().contains("unsafe") || err.to_string().contains("escape"));

    let abs_src = format!("import \"{}\";\nquery network;\n", outside.to_string_lossy());
    let abs_err = compile_vx_source(&abs_src, "abs.vx", &BTreeMap::new(), Some(&base)).unwrap_err();
    assert!(abs_err.to_string().contains("unsafe") || abs_err.to_string().contains("absolute"));

    #[cfg(unix)]
    {
        let link_path = base.join("escape.vdx");
        std::os::unix::fs::symlink(&outside, &link_path).unwrap();
        let sym_src = "import \"escape.vdx\";\nquery network;\n";
        let sym_err = compile_vx_source(sym_src, "sym.vx", &BTreeMap::new(), Some(&base)).unwrap_err();
        assert!(sym_err.to_string().contains("escape"));
    }

    let _ = std::fs::remove_file(&outside);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn test_rejects_authratio_and_energy_direct_mutation_and_non_3d_token() {
    let vector_transfer = r#"
transfer "TOK" from "W1" to "W2" amount [10, 5, 1];
"#;
    let err = compile_vx_source(vector_transfer, "bad_xfer.vx", &BTreeMap::new(), None).unwrap_err();
    assert!(err.to_string().contains("AuthRatio") || err.to_string().contains("only Token"));

    let dim2_token = r#"
token create BAD in "W1" {
    dimensions = 2;
    vector = [100, 1000];
}
"#;
    let err2 = compile_vx_source(dim2_token, "bad_dim.vx", &BTreeMap::new(), None).unwrap_err();
    assert!(err2.to_string().contains("3"));
}

#[test]
fn test_staged_execution_leaves_zero_partial_state_on_failure_and_rejects_replay() {
    let (mut engine, val_kp, actor_kp, _) = make_dev_engine();
    let initial_root = engine.state.compute_state_root().unwrap();

    let failing_prog = r#"
space create PartialSpace { visibility = "public" }
region create PartialRegion in "PartialSpace" { prefix = "PRT"; visibility = "public"; section = 1; }
wallet create PartialWallet in "PartialRegion" { name = "Partial Wallet"; }
transfer "NONEXISTENT" from "PartialWallet" to "MissingWallet" amount 999;
"#;
    let req = sign_program_req(
        "fail.vx",
        failing_prog,
        BTreeMap::new(),
        &actor_kp,
        "vector-devnet-1",
        1,
        "req_fail_1",
    );
    let res = engine
        .stage_program_submission(&req, None, "val_1", |b| val_kp.sign(b), 2_000)
        .unwrap();
    let failed_sub = res.unwrap_err();
    assert_eq!(failed_sub.status, ProgramLifecycleStatus::Failed);
    assert_eq!(failed_sub.failed_operation_index, Some(3));
    assert!(engine.state.spaces.is_empty());
    assert!(engine.state.regions.is_empty());
    assert!(engine.state.wallets.is_empty());
    assert_eq!(engine.state.compute_state_root().unwrap(), initial_root);

    let ok_prog = r#"
space create OkSpace { visibility = "public" }
region create OkRegion in "OkSpace" { prefix = "OK"; visibility = "public"; section = 1; }
wallet create OkWalletA in "OkRegion" { name = "Wallet A"; }
wallet create OkWalletB in "OkRegion" { name = "Wallet B"; }
token create OKTOK in "OkWalletA" {
    name = "OK Token";
    symbol = "OKTOK";
    dimensions = 3;
    vector = [1000, 1000, 0];
    max_supply = 1000;
    drain_bps = 100;
    purpose = "test";
    external_monetary_value = "None";
}
transfer "OKTOK" from "OkWalletA" to "OkWalletB" amount 250;
"#;
    let req2 = sign_program_req(
        "ok.vx",
        ok_prog,
        BTreeMap::new(),
        &actor_kp,
        "vector-devnet-1",
        2,
        "req_ok_2",
    );
    let staged = engine
        .stage_program_submission(&req2, None, "val_1", |b| val_kp.sign(b), 2_100)
        .unwrap()
        .unwrap();
    let qc = single_val_qc(&staged.proposal, &val_kp, "qc_ok", 2_101);
    vnetwork_core::language::validator_verify_program_bundle(
        &engine.state,
        &engine.genesis,
        staged.proposal.program_source_bundle.as_ref().unwrap(),
        &staged.proposal,
        &actor_kp.public_key_hex,
    )
    .expect("validator verification of .vx source & execution should succeed");

    // The proposer signature does not replace the actor's authorization of
    // the program submission. Tampering with the carried actor signature must
    // invalidate the proposal commitment and fail independent verification.
    let mut tampered_bundle = staged.proposal.program_source_bundle.clone().unwrap();
    tampered_bundle.submitter_signature = Some("00".repeat(64));
    let mut tampered_proposal = staged.proposal.clone();
    tampered_proposal.program_source_bundle = Some(tampered_bundle.clone());
    assert_ne!(
        tampered_proposal.compute_expected_digest().unwrap(),
        staged.proposal.proposal_digest
    );
    assert!(
        vnetwork_core::language::validator_verify_program_bundle(
            &engine.state,
            &engine.genesis,
            &tampered_bundle,
            &tampered_proposal,
            &actor_kp.public_key_hex,
        )
        .is_err(),
        "validators must reject program bundles without a valid submitter signature"
    );

    let mut missing_signature_bundle = staged.proposal.program_source_bundle.clone().unwrap();
    missing_signature_bundle.submitter_signature = None;
    assert!(
        vnetwork_core::language::validator_verify_program_bundle(
            &engine.state,
            &engine.genesis,
            &missing_signature_bundle,
            &staged.proposal,
            &actor_kp.public_key_hex,
        )
        .is_err(),
        "validators must reject program bundles with no submitter signature"
    );

    engine.commit_proposal_with_qc(&staged.proposal, &qc, 2_101).unwrap();
    assert_eq!(engine.state.spaces.len(), 1);
    assert_eq!(engine.state.tokens.len(), 1);
    assert!(engine.verify_replay().unwrap().valid);

    let replay_req = sign_program_req(
        "ok.vx",
        ok_prog,
        BTreeMap::new(),
        &actor_kp,
        "vector-devnet-1",
        2,
        "req_ok_replay",
    );
    let replay_err = engine
        .stage_program_submission(&replay_req, None, "val_1", |b| val_kp.sign(b), 2_200)
        .unwrap_err();
    assert!(matches!(replay_err, VNetworkError::ReplayRejected(_)));
}

#[test]
fn test_open_join_cannot_self_escalate_scope() {
    let (mut engine, val_kp, _, _) = make_dev_engine();
    let rogue_p = KeypairMaterial::generate("rogue-p");
    let rogue_n = KeypairMaterial::generate("rogue-n");
    let ch = engine.issue_challenge(3_000);
    let requested = vec![
        ParticipationLevel::Network,
        ParticipationLevel::Space,
        ParticipationLevel::Wallet,
        ParticipationLevel::Token,
    ];
    let bytes = canonical_join_signing_bytes(
        &ch,
        &rogue_p.public_key_hex,
        &rogue_n.public_key_hex,
        &requested,
    )
    .unwrap();
    let join_req = JoinNetworkRequest {
        challenge_id: ch.challenge_id,
        participant_pubkey: rogue_p.public_key_hex.clone(),
        node_pubkey: rogue_n.public_key_hex.clone(),
        display_name: "rogue".to_string(),
        node_kind: NodeKind::FullNode,
        requested_scopes: requested,
        advertised_addresses: vec![],
        participant_signature: rogue_p.sign(&bytes).unwrap(),
        node_signature: rogue_n.sign(&bytes).unwrap(),
        scope_authorizations: vec![],
    };
    let (participant, _, prop, _) = engine
        .stage_participant_join(&join_req, "val_1", |b| val_kp.sign(b), 3_001)
        .unwrap();
    assert_eq!(participant.scope.levels.len(), 1);
    assert!(participant.scope.levels.contains(&ParticipationLevel::Network));
    let qc = single_val_qc(&prop, &val_kp, "qc_rogue", 3_002);
    engine.commit_proposal_with_qc(&prop, &qc, 3_002).unwrap();

    let create_space = r#"space create RogueSpace { visibility = "public" }"#;
    let req = sign_program_req(
        "rogue.vx",
        create_space,
        BTreeMap::new(),
        &rogue_p,
        "vector-devnet-1",
        1,
        "req_rogue_1",
    );
    let failed = engine
        .stage_program_submission(&req, None, "val_1", |b| val_kp.sign(b), 3_003)
        .unwrap()
        .unwrap_err();
    assert_eq!(failed.status, ProgramLifecycleStatus::Rejected);
}

#[test]
fn test_wallet_pop_multisig_and_loan_collateral_escrow_conservation() {
    let (mut engine, val_kp, actor_kp, _) = make_dev_engine();
    let cosigner_kp = KeypairMaterial::generate("cosigner");

    // 1. Setup Space + Region
    let space_op = NetworkOperation::CreateSpace {
        name: "VaultSpace".to_string(),
        visibility: "public".to_string(),
        ghost: false,
    };
    let env1 = sign_operation(&actor_kp, "vector-devnet-1", 1, "op_1", 4_000, &space_op);
    let b1 = engine
        .stage_signed_operation(&env1, &space_op, "val_1", |b| val_kp.sign(b), 4_000)
        .unwrap();
    let qc1 = single_val_qc(&b1.proposal, &val_kp, "qc_m1", 4_001);
    engine.commit_proposal_with_qc(&b1.proposal, &qc1, 4_001).unwrap();
    let space_id = b1.created_entities[0].id.clone();

    let reg_op = NetworkOperation::CreateRegion {
        space_id,
        name: "VaultRegion".to_string(),
        prefix: Some("VLT".to_string()),
        title: None,
        visibility: "public".to_string(),
        section: 1,
        ghost: false,
    };
    let env2 = sign_operation(&actor_kp, "vector-devnet-1", 2, "op_2", 4_002, &reg_op);
    let b2 = engine
        .stage_signed_operation(&env2, &reg_op, "val_1", |b| val_kp.sign(b), 4_002)
        .unwrap();
    let qc2 = single_val_qc(&b2.proposal, &val_kp, "qc_m2", 4_003);
    engine.commit_proposal_with_qc(&b2.proposal, &qc2, 4_003).unwrap();
    let region_id = b2.created_entities[0].id.clone();

    // 2. Create 2-of-2 multisig wallet and borrower wallet
    let w_a = NetworkOperation::CreateWallet {
        region_id: region_id.clone(),
        name: "MultiVault".to_string(),
        ghost: false,
        approval_threshold: Some(2),
    };
    let env3 = sign_operation(&actor_kp, "vector-devnet-1", 3, "op_3", 4_004, &w_a);
    let b3 = engine
        .stage_signed_operation(&env3, &w_a, "val_1", |b| val_kp.sign(b), 4_004)
        .unwrap();
    let qc3 = single_val_qc(&b3.proposal, &val_kp, "qc_m3", 4_005);
    engine.commit_proposal_with_qc(&b3.proposal, &qc3, 4_005).unwrap();
    let vault_id = b3.created_entities[0].id.clone();

    let w_b = NetworkOperation::CreateWallet {
        region_id,
        name: "BorrowerVault".to_string(),
        ghost: false,
        approval_threshold: Some(1),
    };
    let env4 = sign_operation(&actor_kp, "vector-devnet-1", 4, "op_4", 4_006, &w_b);
    let b4 = engine
        .stage_signed_operation(&env4, &w_b, "val_1", |b| val_kp.sign(b), 4_006)
        .unwrap();
    let qc4 = single_val_qc(&b4.proposal, &val_kp, "qc_m4", 4_007);
    engine.commit_proposal_with_qc(&b4.proposal, &qc4, 4_007).unwrap();
    let borrower_id = b4.created_entities[0].id.clone();

    // 3. Invalid PoP fails; valid PoP succeeds
    let bad_auth = NetworkOperation::AuthorizeWalletKey {
        wallet_id: vault_id.clone(),
        authorized_pubkey: cosigner_kp.public_key_hex.clone(),
        role: "signer".to_string(),
        permissions: vec![],
        allowed_token_ids: vec![],
        max_amount_per_op: None,
        expires_at_ms: None,
        pop_nonce: Some("pop_n1".to_string()),
        pop_signature: Some("deadbeef".to_string()),
        participant_identity: None,
    };
    let env_bad = sign_operation(&actor_kp, "vector-devnet-1", 5, "op_5_bad", 4_008, &bad_auth);
    assert!(engine
        .stage_signed_operation(&env_bad, &bad_auth, "val_1", |b| val_kp.sign(b), 4_008)
        .is_err());

    let p_id = derive_participant_id(&actor_kp.public_key_hex);
    let pop_bytes = canonical_wallet_pop_bytes(
        "vector-devnet-1",
        &vault_id,
        &p_id,
        &cosigner_kp.public_key_hex,
        "wallet_key_authorization",
        "pop_n1",
        None,
        PROTOCOL_VERSION,
    )
    .unwrap();
    let pop_sig = cosigner_kp.sign(&pop_bytes).unwrap();
    let good_auth = NetworkOperation::AuthorizeWalletKey {
        wallet_id: vault_id.clone(),
        authorized_pubkey: cosigner_kp.public_key_hex.clone(),
        role: "signer".to_string(),
        permissions: vec![],
        allowed_token_ids: vec![],
        max_amount_per_op: None,
        expires_at_ms: None,
        pop_nonce: Some("pop_n1".to_string()),
        pop_signature: Some(pop_sig),
        participant_identity: Some(p_id),
    };
    let env5 = sign_operation(&actor_kp, "vector-devnet-1", 5, "op_5", 4_009, &good_auth);
    let b5 = engine
        .stage_signed_operation(&env5, &good_auth, "val_1", |b| val_kp.sign(b), 4_009)
        .unwrap();
    let qc5 = single_val_qc(&b5.proposal, &val_kp, "qc_m5", 4_010);
    engine.commit_proposal_with_qc(&b5.proposal, &qc5, 4_010).unwrap();

    // 4. Mint token in MultiVault and test 2-of-2 multisig transfer
    let tok_op = NetworkOperation::CreateToken {
        wallet_id: vault_id.clone(),
        name: "Multi Token".to_string(),
        symbol: "MTOK".to_string(),
        initial_supply: 50_000,
        max_supply: 50_000,
        unlimited_supply: false,
        auth_ratio_au: 1000,
        energy: 5,
        drain_bps: 0,
        purpose: "multisig".to_string(),
        external_monetary_value: "None".to_string(),
        ghost: false,
    };
    let env6 = sign_operation(&actor_kp, "vector-devnet-1", 6, "op_6", 4_011, &tok_op);
    let b6 = engine
        .stage_signed_operation(&env6, &tok_op, "val_1", |b| val_kp.sign(b), 4_011)
        .unwrap();
    let qc6 = single_val_qc(&b6.proposal, &val_kp, "qc_m6", 4_012);
    engine.commit_proposal_with_qc(&b6.proposal, &qc6, 4_012).unwrap();
    let token_id = b6.created_entities[0].id.clone();

    let solo_xfer = NetworkOperation::TransferToken {
        token_id: token_id.clone(),
        from_wallet_id: vault_id.clone(),
        to_wallet_id: borrower_id.clone(),
        amount: 5_000,
        cosignatures: vec![],
    };
    let env_solo = sign_operation(&actor_kp, "vector-devnet-1", 7, "op_7_solo", 4_013, &solo_xfer);
    assert!(engine
        .stage_signed_operation(&env_solo, &solo_xfer, "val_1", |b| val_kp.sign(b), 4_013)
        .is_err());

    let approval_bytes = canonical_transfer_approval_bytes(
        "vector-devnet-1",
        PROTOCOL_VERSION,
        &token_id,
        &vault_id,
        &borrower_id,
        5_000,
    )
    .unwrap();
    let cosig = cosigner_kp.sign(&approval_bytes).unwrap();
    let multi_xfer = NetworkOperation::TransferToken {
        token_id: token_id.clone(),
        from_wallet_id: vault_id.clone(),
        to_wallet_id: borrower_id.clone(),
        amount: 5_000,
        cosignatures: vec![(cosigner_kp.public_key_hex.clone(), cosig)],
    };
    let env7 = sign_operation(&actor_kp, "vector-devnet-1", 7, "op_7", 4_014, &multi_xfer);
    let b7 = engine
        .stage_signed_operation(&env7, &multi_xfer, "val_1", |b| val_kp.sign(b), 4_014)
        .unwrap();
    let qc7 = single_val_qc(&b7.proposal, &val_kp, "qc_m7", 4_015);
    engine.commit_proposal_with_qc(&b7.proposal, &qc7, 4_015).unwrap();

    // Non-transferable dimensions stay [5000, 0, 0] on recipient
    let recipient_vec = engine.state.get_balance(&token_id, &borrower_id).unwrap().vector;
    assert_eq!(recipient_vec, TokenVector::new(5_000, 0, 0));

    // 5. Collateralized loan create -> escrow locks collateral -> repay -> escrow releases -> replay verifies!
    let loan_op = NetworkOperation::CreateLoan {
        name: "CollateralLoan".to_string(),
        token_id: token_id.clone(),
        lender_wallet_id: vault_id.clone(),
        borrower_wallet_id: borrower_id.clone(),
        principal: 1_000,
        collateral: 3_000,
        interest_bps: 0,
        maturity_at_ms: None,
    };
    let env8 = sign_operation(&actor_kp, "vector-devnet-1", 8, "op_8", 4_016, &loan_op);
    let b8 = engine
        .stage_signed_operation(&env8, &loan_op, "val_1", |b| val_kp.sign(b), 4_016)
        .unwrap();
    let qc8 = single_val_qc(&b8.proposal, &val_kp, "qc_m8", 4_017);
    engine.commit_proposal_with_qc(&b8.proposal, &qc8, 4_017).unwrap();
    assert_eq!(
        engine.state.get_balance(&token_id, &borrower_id).unwrap().vector.token,
        2_000
    );
    assert!(engine.verify_replay().unwrap().valid);
}

#[test]
fn test_production_profile_disallows_atlas_bootstrap() {
    let val_kp = KeypairMaterial::generate("validator");
    let prod_genesis = GenesisConfig::for_profile(
        NetworkProfile::Production,
        "vector-main",
        "Mainnet",
        vec![ConsensusValidator {
            validator_id: "val_1".to_string(),
            node_id: "nod_val_1".to_string(),
            validator_pubkey_hex: val_kp.public_key_hex.clone(),
            weight: 100,
            active: true,
            joined_epoch: 1,
        }],
    );
    let mut engine = ProtocolEngine::new(prod_genesis);
    let actor_kp = KeypairMaterial::generate("participant");
    let node_kp = KeypairMaterial::generate("node");
    let ch = engine.issue_challenge(100);
    let scopes = vec![
        ParticipationLevel::Network,
        ParticipationLevel::Space,
        ParticipationLevel::Region,
        ParticipationLevel::Wallet,
        ParticipationLevel::Token,
    ];
    let join_bytes = canonical_join_signing_bytes(
        &ch,
        &actor_kp.public_key_hex,
        &node_kp.public_key_hex,
        &scopes,
    )
    .unwrap();
    let scope_auth = signed_scope_auth(
        &val_kp,
        &actor_kp.public_key_hex,
        "vector-main",
        vec![
            ParticipationLevel::Space,
            ParticipationLevel::Region,
            ParticipationLevel::Wallet,
            ParticipationLevel::Token,
        ],
    );
    let (_, _, prop, _) = engine
        .stage_participant_join(
            &JoinNetworkRequest {
                challenge_id: ch.challenge_id,
                participant_pubkey: actor_kp.public_key_hex.clone(),
                node_pubkey: node_kp.public_key_hex.clone(),
                display_name: "prod-user".to_string(),
                node_kind: NodeKind::FullNode,
                requested_scopes: scopes,
                advertised_addresses: vec![],
                participant_signature: actor_kp.sign(&join_bytes).unwrap(),
                node_signature: node_kp.sign(&join_bytes).unwrap(),
                scope_authorizations: vec![scope_auth],
            },
            "val_1",
            |b| val_kp.sign(b),
            101,
        )
        .unwrap();
    let qc = single_val_qc(&prop, &val_kp, "qc_p1", 102);
    engine.commit_proposal_with_qc(&prop, &qc, 102).unwrap();

    let atlas_src = include_str!("../../../examples/vector-language/bootstrap-atlas.vx");
    let req = sign_program_req(
        "bootstrap-atlas.vx",
        atlas_src,
        BTreeMap::new(),
        &actor_kp,
        "vector-main",
        1,
        "req_atlas",
    );
    let failed = engine
        .stage_program_submission(&req, None, "val_1", |b| val_kp.sign(b), 200)
        .unwrap()
        .unwrap_err();
    assert_eq!(failed.status, ProgramLifecycleStatus::Rejected);
    assert!(failed.error_message.unwrap().contains("ATLAS"));
}

#[test]
fn test_parentless_ghost_entities_and_certify_execute_and_replay_cleanly() {
    let (mut engine, val_kp, actor_kp, _) = make_dev_engine();
    let ghost_src = r#"
region ghost create GhostRegNet { prefix = "GRN"; visibility = "private"; section = 1; }
wallet ghost create GhostWalNet { name = "GhostWalNet"; }
token ghost create GhostTokNet {
    name = "Ghost Token";
    symbol = "GTOK";
    dimensions = 3;
    vector = [5000, 100, 10];
    max_supply = 5000;
}
certify "GhostRegNet" with ctx(op="cert", space="network");
drain token "GhostTokNet" amount 250;
"#;
    let req = sign_program_req(
        "ghost_and_certify.vx",
        ghost_src,
        BTreeMap::new(),
        &actor_kp,
        "vector-devnet-1",
        1,
        "req_ghost_cert_1",
    );
    let staged = engine
        .stage_program_submission(&req, None, "val_1", |b| val_kp.sign(b), 5_000)
        .unwrap()
        .unwrap();
    let qc = single_val_qc(&staged.proposal, &val_kp, "qc_ghost_1", 5_001);
    engine
        .commit_proposal_with_qc(&staged.proposal, &qc, 5_001)
        .unwrap();

    assert_eq!(engine.state.regions.len(), 1);
    assert_eq!(engine.state.wallets.len(), 1);
    assert_eq!(engine.state.tokens.len(), 1);
    let reg = engine.state.regions.values().next().unwrap();
    assert!(reg.ghost);
    assert!(reg.space_id.is_empty());
    assert_eq!(reg.auth_ratio_bps, 10_000);
    let wal = engine.state.wallets.values().next().unwrap();
    assert!(wal.ghost);
    assert!(wal.region_id.is_empty());
    let tok = engine.state.tokens.values().next().unwrap();
    assert!(tok.ghost);
    assert!(tok.wallet_id.is_empty());
    assert_eq!(tok.total_supply, 4_750);
    assert!(vnetwork_core::supply::verify_token_supply_conservation(&engine.state, &tok.token_id).unwrap());

    let assessment = vnetwork_core::ghost::inspect_ghost_entities(&engine.state).unwrap();
    assert_eq!(assessment.total_ghost_entities, 3);
    assert_eq!(assessment.parentless_regions.len(), 1);
    assert_eq!(assessment.parentless_wallets.len(), 1);
    assert_eq!(assessment.parentless_tokens.len(), 1);
    assert!(engine.verify_replay().unwrap().valid);
    assert!(engine.reconstruct_entity("region", &reg.region_id).unwrap().verified);
    assert!(engine.reconstruct_entity("token", &tok.token_id).unwrap().verified);
}
