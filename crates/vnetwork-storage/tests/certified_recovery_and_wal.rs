use std::fs;
use vnetwork_core::engine::ProtocolEngine;
use vnetwork_core::identity::{canonical_join_signing_bytes, JoinNetworkRequest};
use vnetwork_core::state::GenesisConfig;
use vnetwork_storage::{EventWal, StorageDatabase, LEGACY_UNCERTIFIED_SNAPSHOT_FILE};
use vnetwork_types::*;

fn single_val_qc(
    prop: &ConsensusProposal,
    val_kp: &KeypairMaterial,
    qc_id: &str,
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
    vote.signature = val_kp.sign(&vote.canonical_signing_bytes().unwrap()).unwrap();
    QuorumCertificate {
        certificate_id: qc_id.to_string(),
        proposal_id: prop.proposal_id.clone(),
        proposal_digest: prop.proposal_digest.clone(),
        network_id: prop.network_id.clone(),
        genesis_commitment: prop.genesis_commitment.clone(),
        protocol_version: prop.protocol_version.clone(),
        height: prop.height,
        round: prop.round,
        epoch: prop.epoch,
        validator_set_hash: prop.validator_set_hash.clone(),
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
    }
}

#[test]
fn test_rejects_legacy_uncertified_snapshot_and_wal_divergence() {
    let dir = std::env::temp_dir().join(format!(
        "vnetwork_strict_storage_{}_{}",
        std::process::id(),
        now_ms()
    ));
    let _ = fs::remove_dir_all(&dir);
    let val_kp = KeypairMaterial::generate("validator");
    let genesis = GenesisConfig::for_profile(
        NetworkProfile::Testnet,
        "vector-testnet-1",
        "Strict Storage Test",
        vec![ConsensusValidator {
            validator_id: "val_1".to_string(),
            node_id: "nod_val_1".to_string(),
            validator_pubkey_hex: val_kp.public_key_hex.clone(),
            weight: 100,
            active: true,
            joined_epoch: 1,
        }],
    );

    let (db, state, _) = StorageDatabase::open_and_recover(&dir, &genesis).unwrap();
    let mut engine = ProtocolEngine::from_restored(genesis.clone(), state);
    let p_kp = KeypairMaterial::generate("participant");
    let n_kp = KeypairMaterial::generate("node");
    let ch = engine.issue_challenge(100);
    let scopes = vec![ParticipationLevel::Network];
    let join_bytes = canonical_join_signing_bytes(
        &ch,
        &p_kp.public_key_hex,
        &n_kp.public_key_hex,
        &scopes,
    )
    .unwrap();
    let req = JoinNetworkRequest {
        challenge_id: ch.challenge_id,
        participant_pubkey: p_kp.public_key_hex.clone(),
        node_pubkey: n_kp.public_key_hex.clone(),
        display_name: "strict-wal-user".to_string(),
        node_kind: NodeKind::FullNode,
        requested_scopes: scopes,
        advertised_addresses: vec![],
        participant_signature: p_kp.sign(&join_bytes).unwrap(),
        node_signature: n_kp.sign(&join_bytes).unwrap(),
        scope_authorizations: vec![],
    };
    let (_, _, prop, _) = engine
        .stage_participant_join(&req, "val_1", |b| val_kp.sign(b), 101)
        .unwrap();
    let qc = single_val_qc(&prop, &val_kp, "qc_strict_1", 102);
    engine.commit_proposal_with_qc(&prop, &qc, 102).unwrap();
    db.persist_commit(&engine.state, &prop, &qc).unwrap();
    drop(db);

    // 1. Extra uncertified event injected into events.wal must fail closed
    let extra_ev = LedgerEvent::build(
        2,
        vec![engine.state.events[0].event_hash.clone()],
        "vector-testnet-1",
        "space",
        "spc_injected",
        "SPACE_CREATE",
        &p_kp.public_key_hex,
        99,
        200,
        serde_json::json!({"forged": true}),
        "",
        blake3_hex(b"forged"),
    )
    .unwrap();
    EventWal::new(&dir).append_events(&[extra_ev]).unwrap();
    assert!(
        StorageDatabase::open_and_recover(&dir, &genesis).is_err(),
        "extra uncertified WAL event must fail closed"
    );

    // Restore clean events.wal
    EventWal::new(&dir).rewrite_all(&engine.state.events).unwrap();
    let (db_ok, _, rep) = StorageDatabase::open_and_recover(&dir, &genesis).unwrap();
    assert!(rep.wal_consistency_ok);
    db_ok.check_health().unwrap();
    drop(db_ok);

    // 2. Replace certified checkpoint with legacy uncertified state.snapshot.json -> must fail closed!
    fs::remove_file(dir.join("certified.checkpoint.json")).unwrap();
    fs::write(
        dir.join(LEGACY_UNCERTIFIED_SNAPSHOT_FILE),
        serde_json::to_vec_pretty(&engine.state).unwrap(),
    )
    .unwrap();
    assert!(
        StorageDatabase::open_and_recover(&dir, &genesis).is_err(),
        "legacy uncertified state.snapshot.json without certified.checkpoint.json must be rejected"
    );

    let _ = fs::remove_dir_all(&dir);
}
