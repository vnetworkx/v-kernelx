use std::fs;
use vnetwork_consensus::{EquivocationStore, ValidatorMembership};
use vnetwork_core::consensus_gate::verify_quorum_certificate_strict;
use vnetwork_node::{
    load_or_generate_encrypted_key, rotate_encrypted_key, NodeIdentity, NodeIdentityLoadOptions,
};
use vnetwork_types::*;

fn test_temp_dir(label: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "vnetwork_sec_{}_{}_{}",
        label,
        std::process::id(),
        now_ms()
    ));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn test_encrypted_key_envelope_and_aad_protection() {
    let dir = test_temp_dir("envelope");
    let node_key = dir.join("node.key.json");
    let val_key = dir.join("validator.key.json");

    let opts = NodeIdentityLoadOptions {
        profile: NetworkProfile::Production,
        passphrase: Some("strong-test-passphrase-123!".to_string()),
        kdf_params: Some(KeyKdfParams::fast_for_tests()),
        allow_plaintext_key_fallback: false,
        external_node_signer: None,
        external_validator_signer: None,
    };

    let identity =
        NodeIdentity::load_or_create_secure(&node_key, Some(&val_key), Some("val_1"), true, &opts)
            .expect("secure identity creation should succeed");
    assert!(identity.storage_security_mode.contains("encrypted-envelope-v1"));

    // Debug output must redact private seed material
    let dbg = format!("{identity:?}");
    assert!(!dbg.contains("private_key_hex"));

    // Persisted JSON must be encrypted envelope with ciphertext_hex and NO private_key_hex
    let raw = fs::read_to_string(&node_key).unwrap();
    assert!(raw.contains("ciphertext_hex"));
    assert!(!raw.contains("private_key_hex"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&node_key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file must enforce 0600 permissions");
    }

    // Wrong passphrase fails closed
    let bad_opts = NodeIdentityLoadOptions {
        passphrase: Some("wrong-passphrase".to_string()),
        ..opts.clone()
    };
    assert!(
        NodeIdentity::load_or_create_secure(&node_key, Some(&val_key), Some("val_1"), true, &bad_opts)
            .is_err()
    );

    // Tampered AAD metadata inside envelope must fail AES-GCM decryption
    let mut val_json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    val_json["key_role"] = serde_json::Value::String("validator".to_string());
    let tampered_path = dir.join("tampered.key.json");
    fs::write(&tampered_path, serde_json::to_vec_pretty(&val_json).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tampered_path, fs::Permissions::from_mode(0o600));
    }
    assert!(load_or_generate_encrypted_key(&tampered_path, "node", &opts).is_err());

    // Key rotation records versioned rotation history
    let (rotated_sk, meta) = rotate_encrypted_key(
        &node_key,
        "strong-test-passphrase-123!",
        "rotated-passphrase-456!",
        Some(KeyKdfParams::fast_for_tests()),
        "test_rotation",
        10_000,
    )
    .unwrap();
    assert_eq!(meta.key_version, 2);
    assert_eq!(meta.rotation_history.len(), 2);
    assert_ne!(
        rotated_sk.public_key_hex,
        identity.node_metadata.public_key_hex
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_plaintext_key_refused_without_explicit_override_and_insecure_perms_rejected() {
    let dir = test_temp_dir("plaintext_refuse");
    let legacy_path = dir.join("legacy.key.json");
    let kp = KeypairMaterial::generate("node");
    let legacy_json = serde_json::json!({
        "key_role": "node",
        "public_key_hex": kp.public_key_hex,
        "private_key_hex": kp.private_key_hex,
    });
    fs::write(&legacy_path, serde_json::to_vec_pretty(&legacy_json).unwrap()).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // First set overly permissive 0644
        fs::set_permissions(&legacy_path, fs::Permissions::from_mode(0o644)).unwrap();
        let override_opts = NodeIdentityLoadOptions {
            allow_plaintext_key_fallback: true,
            ..Default::default()
        };
        assert!(
            load_or_generate_encrypted_key(&legacy_path, "node", &override_opts).is_err(),
            "insecure permissions 0644 must be refused"
        );
        fs::set_permissions(&legacy_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    // Even with 0600, default refuses plaintext fallback
    let strict_opts = NodeIdentityLoadOptions::default();
    assert!(load_or_generate_encrypted_key(&legacy_path, "node", &strict_opts).is_err());

    // Explicit override succeeds for migration inspection
    let override_opts = NodeIdentityLoadOptions {
        allow_plaintext_key_fallback: true,
        ..Default::default()
    };
    let (loaded, meta) = load_or_generate_encrypted_key(&legacy_path, "node", &override_opts).unwrap();
    assert_eq!(loaded.public_key_hex, kp.public_key_hex);
    assert_eq!(meta.storage_mode, "legacy-plaintext-override");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_durable_anti_equivocation_intent_crash_and_corruption_fail_closed() {
    let dir = test_temp_dir("equivocation");
    let val_sk = ProtectedSigningKey::generate("validator");
    let validator = ConsensusValidator {
        validator_id: "val_1".to_string(),
        node_id: "nod_val_1".to_string(),
        validator_pubkey_hex: val_sk.public_key_hex.clone(),
        weight: 100,
        active: true,
        joined_epoch: 1,
    };
    let vset_hash = validate_validator_set(&[validator.clone()]).unwrap();
    let genesis_comm = blake3_hex(b"eq-test-genesis");

    let mut prop_a = ConsensusProposal {
        proposal_id: String::new(),
        proposal_version: PROPOSAL_VERSION,
        network_id: "vector-devnet-1".to_string(),
        genesis_commitment: genesis_comm.clone(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        height: 1,
        round: 1,
        epoch: 1,
        validator_set_hash: vset_hash.clone(),
        proposer_validator_id: "val_1".to_string(),
        parent_commitment: genesis_comm.clone(),
        pre_state_root: "pre_1".to_string(),
        post_state_root: "post_a".to_string(),
        proposal_digest: String::new(),
        operation_scope: "TEST".to_string(),
        events: vec![],
        program_id: None,
        tx_id: None,
        program_source_bundle: None,
        nonce_binding: None,
        execution_params: Default::default(),
        timestamp_ms: 1000,
        proposer_signature: String::new(),
    };
    prop_a.finalize_digest_and_id().unwrap();
    prop_a.proposer_signature = val_sk.sign(&prop_a.canonical_signing_bytes().unwrap()).unwrap();

    let mut prop_b = prop_a.clone();
    prop_b.post_state_root = "post_b_conflict".to_string();
    prop_b.finalize_digest_and_id().unwrap();
    prop_b.proposer_signature = val_sk.sign(&prop_b.canonical_signing_bytes().unwrap()).unwrap();

    let mut store = EquivocationStore::open(&dir).unwrap();
    // Simulate crash right after writing IntentPending BEFORE signing
    let crash_res = store.sign_vote_safely_with_failpoint(
        &validator,
        &LocalEncryptedSigningProvider::new(val_sk.clone(), "encrypted"),
        &prop_a,
        true,
        VotePhase::Commit,
        1001,
        true,
    );
    assert!(crash_res.is_err());
    drop(store);

    // After restart, conflicting proposal on same slot MUST be refused even though IntentPending never returned a signature
    let mut reopened = EquivocationStore::open(&dir).unwrap();
    let signer = LocalEncryptedSigningProvider::new(val_sk.clone(), "encrypted");
    assert!(reopened
        .sign_vote_safely(&validator, &signer, &prop_b, true, VotePhase::Commit, 1002)
        .is_err());

    // Exact retry for prop_a completes and is idempotent
    let vote_1 = reopened
        .sign_vote_safely(&validator, &signer, &prop_a, true, VotePhase::Commit, 1003)
        .unwrap();
    let vote_2 = reopened
        .sign_vote_safely(&validator, &signer, &prop_a, true, VotePhase::Commit, 1004)
        .unwrap();
    assert_eq!(vote_1, vote_2);

    // Valid QC check succeeds
    let membership = ValidatorMembership::new(vec![validator.clone()], DEFAULT_BFT_QUORUM_BPS);
    let qc = QuorumCertificate {
        certificate_id: "qc_1".to_string(),
        proposal_id: prop_a.proposal_id.clone(),
        proposal_digest: prop_a.proposal_digest.clone(),
        network_id: prop_a.network_id.clone(),
        genesis_commitment: genesis_comm.clone(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        height: 1,
        round: 1,
        epoch: 1,
        validator_set_hash: vset_hash,
        parent_commitment: genesis_comm,
        pre_state_root: "pre_1".to_string(),
        post_state_root: "post_a".to_string(),
        operation_scope: "TEST".to_string(),
        vote_phase: VotePhase::Commit,
        ordered_event_ids: vec![],
        event_hashes: vec![],
        total_weight: 100,
        approving_weight: 100,
        quorum_threshold_bps: DEFAULT_BFT_QUORUM_BPS,
        votes: vec![vote_1],
        finalized_at_ms: 1003,
    };
    verify_quorum_certificate_strict(&qc, &membership.all_validators(), None, None, None).unwrap();

    // Corrupting equivocation_votes.wal causes EquivocationStore::open to fail closed
    drop(reopened);
    fs::write(dir.join("equivocation_votes.wal"), "{corrupt-json\n").unwrap();
    assert!(EquivocationStore::open(&dir).is_err());

    let _ = fs::remove_dir_all(&dir);
}
