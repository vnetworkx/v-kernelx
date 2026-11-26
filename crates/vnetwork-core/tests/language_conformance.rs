use std::collections::BTreeMap;
use std::path::Path;
use vnetwork_core::engine::ProtocolEngine;
use vnetwork_core::identity::{canonical_join_signing_bytes, JoinNetworkRequest};
use vnetwork_core::language::{compile_vx_source, SubmitProgramRequest};
use vnetwork_core::state::GenesisConfig;
use vnetwork_types::*;

fn single_val_qc(
    prop: &ConsensusProposal,
    val_kp: &KeypairMaterial,
    qc_id: &str,
    ts: u64,
) -> QuorumCertificate {
    let mut vote = ConsensusVote {
        proposal_id: prop.proposal_id.clone(),
        network_id: prop.network_id.clone(),
        height: prop.height,
        round: prop.round,
        epoch: prop.epoch,
        validator_id: "val_1".to_string(),
        validator_pubkey_hex: val_kp.public_key_hex.clone(),
        approve: true,
        post_state_root: prop.post_state_root.clone(),
        timestamp_ms: ts,
        signature: String::new(),
    };
    let bytes = vote.canonical_signing_bytes().unwrap();
    vote.signature = val_kp.sign(&bytes).unwrap();
    QuorumCertificate {
        certificate_id: qc_id.to_string(),
        proposal_id: prop.proposal_id.clone(),
        network_id: prop.network_id.clone(),
        height: prop.height,
        round: prop.round,
        epoch: prop.epoch,
        post_state_root: prop.post_state_root.clone(),
        event_hashes: prop.events.iter().map(|e| e.event_hash.clone()).collect(),
        total_weight: 100,
        approving_weight: 100,
        quorum_threshold_bps: 6667,
        votes: vec![vote],
        finalized_at_ms: ts,
    }
}

fn make_dev_engine() -> (ProtocolEngine, KeypairMaterial, KeypairMaterial, KeypairMaterial) {
    let val_kp = KeypairMaterial::generate("validator");
    let genesis = GenesisConfig::for_profile(
        NetworkProfile::Development,
        "vnetwork-devnet-1",
        "Dev Network",
        vec![ConsensusValidator {
            validator_id: "val_1".to_string(),
            node_id: "nod_val_1".to_string(),
            validator_pubkey_hex: val_kp.public_key_hex.clone(),
            weight: 100,
            active: true,
            joined_epoch: 1,
        }],
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

    // Fail at step 4 (transfer from non-existent/insufficient wallet after creating Space/Region/Wallet)
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
        "vnetwork-devnet-1",
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
        "vnetwork-devnet-1",
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

    engine.commit_proposal_with_qc(&staged.proposal, &qc, 2_101).unwrap();
    assert_eq!(engine.state.spaces.len(), 1);
    assert_eq!(engine.state.tokens.len(), 1);

    let replay_req = sign_program_req(
        "ok.vx",
        ok_prog,
        BTreeMap::new(),
        &actor_kp,
        "vnetwork-devnet-1",
        2,
        "req_ok_replay",
    );
    let replay_err = engine
        .stage_program_submission(&replay_req, None, "val_1", |b| val_kp.sign(b), 2_200)
        .unwrap_err();
    assert!(matches!(replay_err, VNetworkError::ReplayRejected(_)));
}

#[test]
fn test_production_profile_disallows_atlas_bootstrap() {
    let val_kp = KeypairMaterial::generate("validator");
    let prod_genesis = GenesisConfig::for_profile(
        NetworkProfile::Production,
        "vnetwork-mainnet-1",
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
        "vnetwork-mainnet-1",
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
