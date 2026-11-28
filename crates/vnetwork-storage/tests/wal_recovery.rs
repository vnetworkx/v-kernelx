use std::fs;
use vnetwork_core::engine::ProtocolEngine;
use vnetwork_core::identity::{canonical_join_signing_bytes, JoinNetworkRequest};
use vnetwork_core::snapshot::CertifiedCheckpoint;
use vnetwork_core::state::GenesisConfig;
use vnetwork_storage::{save_certified_checkpoint, PersistFailpoint, StorageDatabase};
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
    vote.signature = val_kp
        .sign(&vote.canonical_signing_bytes().unwrap())
        .unwrap();
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

#[test]
fn test_wal_persistence_crash_recovery_and_profile_guard() {
    let dir = std::env::temp_dir().join(format!(
        "vnetwork_wal_test_{}_{}",
        std::process::id(),
        now_ms()
    ));
    let _ = fs::remove_dir_all(&dir);
    let val_kp = KeypairMaterial::generate("validator");
    let genesis = GenesisConfig::for_profile(
        NetworkProfile::Testnet,
        "vector-testnet-1",
        "Testnet",
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
    assert_eq!(state.height, 0);
    db.check_health().unwrap();
    drop(db);

    // Mismatched profile or validator set fails loudly
    let wrong_genesis = GenesisConfig::for_profile(
        NetworkProfile::Production,
        "vector-testnet-1",
        "Prod",
        vec![],
    );
    assert!(StorageDatabase::open_and_recover(&dir, &wrong_genesis).is_err());

    let wrong_val_genesis = GenesisConfig::for_profile(
        NetworkProfile::Testnet,
        "vector-testnet-1",
        "Testnet",
        vec![],
    );
    assert!(StorageDatabase::open_and_recover(&dir, &wrong_val_genesis).is_err());

    // Simulated uncommitted crash at AfterEventWal rolls back uncertified events
    let (db2, state2, _) = StorageDatabase::open_and_recover(&dir, &genesis).unwrap();
    let mut engine = ProtocolEngine::from_restored(genesis.clone(), state2);
    let p_kp = KeypairMaterial::generate("participant");
    let n_kp = KeypairMaterial::generate("node");
    let ch = engine.issue_challenge(100);
    let scopes = vec![ParticipationLevel::Network];
    let join_bytes =
        canonical_join_signing_bytes(&ch, &p_kp.public_key_hex, &n_kp.public_key_hex, &scopes)
            .unwrap();
    let req = JoinNetworkRequest {
        challenge_id: ch.challenge_id,
        participant_pubkey: p_kp.public_key_hex.clone(),
        node_pubkey: n_kp.public_key_hex.clone(),
        display_name: "wal-user".to_string(),
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
    let qc = single_val_qc(&prop, &val_kp, "qc_wal_1", 102);
    engine.commit_proposal_with_qc(&prop, &qc, 102).unwrap();

    // Crash BEFORE committed marker
    let crash_res = db2.persist_commit_with_failpoint(
        &engine.state,
        &prop,
        &qc,
        PersistFailpoint::AfterEventWal,
    );
    assert!(crash_res.is_err());
    drop(db2);

    let (db3, state3, rep3) = StorageDatabase::open_and_recover(&dir, &genesis).unwrap();
    assert_eq!(rep3.rolled_back_uncommitted, 1);
    assert_eq!(state3.height, 0);
    assert!(state3.events.is_empty());

    // Crash AFTER committed marker rolls forward cleanly
    let crash_res2 = db3.persist_commit_with_failpoint(
        &engine.state,
        &prop,
        &qc,
        PersistFailpoint::AfterCommittedMarker,
    );
    assert!(crash_res2.is_err());
    drop(db3);

    let (_db4, state4, rep4) = StorageDatabase::open_and_recover(&dir, &genesis).unwrap();
    assert_eq!(rep4.proposals_replayed, 1);
    assert_eq!(state4.height, 1);
    assert_eq!(state4.events.len(), 1);

    // CertifiedCheckpoint tampering detection
    let mut tampered_state = state4.clone();
    tampered_state.logical_clock = 9999;
    let ckpt = CertifiedCheckpoint::build(
        &tampered_state,
        &qc,
        &prop.proposal_digest,
        &prop.parent_commitment,
        102,
    )
    .unwrap();
    save_certified_checkpoint(&dir, &ckpt).unwrap();
    assert!(StorageDatabase::open_and_recover(&dir, &genesis).is_err());

    // Restore valid checkpoint so we can test trailing partial WAL recovery & fail-closed corruption
    let valid_ckpt = CertifiedCheckpoint::build(
        &state4,
        &qc,
        &prop.proposal_digest,
        &prop.parent_commitment,
        102,
    )
    .unwrap();
    save_certified_checkpoint(&dir, &valid_ckpt).unwrap();

    // Appending an unterminated partial trailing line to events.wal (simulating mid-write crash)
    // quarantines the fragment and recovers cleanly to height 1.
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("events.wal"))
            .unwrap();
        f.write_all(b"{\"partial_corrupt_tail_without_newline")
            .unwrap();
    }
    let (db5, state5, rep5) = StorageDatabase::open_and_recover(&dir, &genesis).unwrap();
    assert_eq!(state5.height, 1);
    assert_eq!(rep5.quarantined_artifacts.len(), 1);
    assert!(std::path::Path::new(&rep5.quarantined_artifacts[0]).exists());
    db5.check_health().unwrap();
    drop(db5);

    // Complete newline-terminated corrupt line in consensus_commits.wal MUST fail closed
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("consensus_commits.wal"))
            .unwrap();
        writeln!(f, "{{\"corrupt_complete_line\":true}}").unwrap();
    }
    assert!(StorageDatabase::open_and_recover(&dir, &genesis).is_err());

    let _ = fs::remove_dir_all(&dir);
}
