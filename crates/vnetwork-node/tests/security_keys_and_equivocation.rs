use std::fs;
use std::sync::Arc;
use vnetwork_consensus::{EquivocationDetector, EquivocationStore, ValidatorMembership};
use vnetwork_core::consensus_gate::verify_quorum_certificate_strict;
use vnetwork_node::{
    load_or_generate_encrypted_key, migrate_plaintext_key_to_encrypted, rotate_encrypted_key,
    NodeConfig, NodeIdentity, NodeIdentityLoadOptions,
};
use vnetwork_types::*;
use zeroize::Zeroizing;

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
        passphrase: Some(Zeroizing::new("strong-test-passphrase-123!".to_string())),
        kdf_params: Some(KeyKdfParams::fast_for_tests()),
        allow_plaintext_key_fallback: false,
        external_node_signer: None,
        external_validator_signer: None,
        transport_key_path: None,
    };

    // Passphrase must be redacted in Debug formatting of options
    let opts_dbg = format!("{opts:?}");
    assert!(!opts_dbg.contains("strong-test-passphrase-123!"));
    assert!(opts_dbg.contains("[REDACTED]"));

    let identity =
        NodeIdentity::load_or_create_secure(&node_key, Some(&val_key), Some("val_1"), true, &opts)
            .expect("secure identity creation should succeed");
    assert!(identity
        .storage_security_mode
        .contains("encrypted-envelope-v1"));

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
        profile: NetworkProfile::Production,
        passphrase: Some(Zeroizing::new("wrong-passphrase".to_string())),
        kdf_params: Some(KeyKdfParams::fast_for_tests()),
        allow_plaintext_key_fallback: false,
        external_node_signer: None,
        external_validator_signer: None,
        transport_key_path: None,
    };
    assert!(NodeIdentity::load_or_create_secure(
        &node_key,
        Some(&val_key),
        Some("val_1"),
        true,
        &bad_opts
    )
    .is_err());

    // Tampered AAD metadata inside envelope must fail AES-GCM decryption
    let mut val_json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    val_json["key_role"] = serde_json::Value::String("validator".to_string());
    let tampered_path = dir.join("tampered.key.json");
    fs::write(
        &tampered_path,
        serde_json::to_vec_pretty(&val_json).unwrap(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tampered_path, fs::Permissions::from_mode(0o600));
    }
    assert!(load_or_generate_encrypted_key(&tampered_path, "node", &opts).is_err());

    // Manipulated KDF upper bounds (memory/CPU DoS) must fail validation
    let mut dos_json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    dos_json["kdf_params"]["m_cost_kib"] = serde_json::json!(64_000_000u32);
    let dos_path = dir.join("dos_kdf.key.json");
    fs::write(&dos_path, serde_json::to_vec_pretty(&dos_json).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dos_path, fs::Permissions::from_mode(0o600));
    }
    assert!(load_or_generate_encrypted_key(&dos_path, "node", &opts).is_err());

    // Key rotation records versioned rotation history and verifies reloaded file
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
fn test_plaintext_key_refused_in_production_and_offline_migration_succeeds() {
    let dir = test_temp_dir("plaintext_migrate");
    let legacy_path = dir.join("legacy.key.json");
    let backup_path = dir.join("legacy.key.json.bak");
    let migrated_path = dir.join("node.migrated.key.json");

    let kp = KeypairMaterial::generate("node");
    let legacy_json = serde_json::json!({
        "key_role": "node",
        "public_key_hex": kp.public_key_hex,
        "private_key_hex": kp.private_key_hex,
    });
    fs::write(
        &legacy_path,
        serde_json::to_vec_pretty(&legacy_json).unwrap(),
    )
    .unwrap();

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

    // Default refuses plaintext fallback
    let strict_opts = NodeIdentityLoadOptions::default();
    assert!(load_or_generate_encrypted_key(&legacy_path, "node", &strict_opts).is_err());

    // Production refuses plaintext fallback EVEN IF caller sets allow_plaintext_key_fallback=true
    let prod_override_opts = NodeIdentityLoadOptions {
        profile: NetworkProfile::Production,
        allow_plaintext_key_fallback: true,
        ..Default::default()
    };
    assert!(load_or_generate_encrypted_key(&legacy_path, "node", &prod_override_opts).is_err());

    let mut prod_cfg = NodeConfig {
        profile: NetworkProfile::Production,
        network_id: "vector-main".to_string(),
        allow_plaintext_key_fallback: true,
        ..Default::default()
    };
    assert!(prod_cfg.validate().is_err());
    prod_cfg.allow_plaintext_key_fallback = false;
    assert!(prod_cfg.validate().is_ok());

    // Explicit offline migration encrypts, reloads, verifies identity, keeps backup, and removes legacy plaintext
    let migration_pass = Zeroizing::new("migration-passphrase-789!".to_string());
    let migrated_meta = migrate_plaintext_key_to_encrypted(
        &legacy_path,
        &migrated_path,
        Some("node"),
        &migration_pass,
        Some(KeyKdfParams::fast_for_tests()),
        Some(&backup_path),
        true,
        20_000,
    )
    .unwrap();
    assert_eq!(migrated_meta.public_key_hex, kp.public_key_hex);
    assert!(!legacy_path.exists());
    assert!(backup_path.exists());

    // Resulting encrypted envelope unlocks in Production without fallback
    let prod_unlock_opts = NodeIdentityLoadOptions {
        profile: NetworkProfile::Production,
        passphrase: Some(migration_pass),
        kdf_params: Some(KeyKdfParams::fast_for_tests()),
        allow_plaintext_key_fallback: false,
        external_node_signer: None,
        external_validator_signer: None,
        transport_key_path: None,
    };
    let (loaded, meta) =
        load_or_generate_encrypted_key(&migrated_path, "node", &prod_unlock_opts).unwrap();
    assert_eq!(loaded.public_key_hex, kp.public_key_hex);
    assert_eq!(meta.storage_mode, "encrypted-envelope-v1");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_external_node_signer_with_separate_transport_key() {
    let dir = test_temp_dir("ext_node_signer");
    let node_key = dir.join("unused_node.key.json");
    let transport_key = dir.join("node.transport.key.json");
    let val_key = dir.join("validator.key.json");

    let ext_sk = ProtectedSigningKey::generate("node");
    let ext_sk_for_cb = ext_sk.clone();
    let ext_meta = ext_sk.metadata("external-hsm", 1, 1000, None, vec![]);
    let ext_provider = ExternalSignerProvider::new(
        ext_meta,
        "mock-hsm",
        Arc::new(move |msg| ext_sk_for_cb.sign(msg)),
    )
    .unwrap();

    // Missing transport_key_path fails cleanly
    let bad_opts = NodeIdentityLoadOptions {
        profile: NetworkProfile::Production,
        passphrase: Some(Zeroizing::new("pass-123".to_string())),
        kdf_params: Some(KeyKdfParams::fast_for_tests()),
        allow_plaintext_key_fallback: false,
        external_node_signer: Some(ext_provider.clone()),
        external_validator_signer: None,
        transport_key_path: None,
    };
    assert!(
        NodeIdentity::load_or_create_secure(&node_key, Some(&val_key), None, false, &bad_opts)
            .is_err()
    );

    // Providing transport_key_path succeeds with external node signer + local encrypted transport key
    let good_opts = NodeIdentityLoadOptions {
        profile: NetworkProfile::Production,
        passphrase: Some(Zeroizing::new("pass-123".to_string())),
        kdf_params: Some(KeyKdfParams::fast_for_tests()),
        allow_plaintext_key_fallback: false,
        external_node_signer: Some(ext_provider),
        external_validator_signer: None,
        transport_key_path: Some(transport_key.clone()),
    };
    let id =
        NodeIdentity::load_or_create_secure(&node_key, Some(&val_key), None, false, &good_opts)
            .unwrap();
    assert_eq!(id.node_metadata.public_key_hex, ext_sk.public_key_hex);
    assert!(id.storage_security_mode.contains("external:mock-hsm"));
    assert!(transport_key.exists());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_durable_anti_equivocation_intent_crash_lock_and_evidence_integrity() {
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
    let params = NetworkConsensusParameters::default();
    let params_hash = params.parameters_hash().unwrap();

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
        consensus_parameters_hash: params_hash.clone(),
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
    prop_a.proposer_signature = val_sk
        .sign(&prop_a.canonical_signing_bytes().unwrap())
        .unwrap();

    let mut prop_b = prop_a.clone();
    prop_b.post_state_root = "post_b_conflict".to_string();
    prop_b.finalize_digest_and_id().unwrap();
    prop_b.proposer_signature = val_sk
        .sign(&prop_b.canonical_signing_bytes().unwrap())
        .unwrap();

    let mut store = EquivocationStore::open(&dir).unwrap();
    // Exclusive writer lock refuses a second concurrent writer instance on same directory
    assert!(
        EquivocationStore::open(&dir).is_err(),
        "concurrent EquivocationStore::open must fail closed while lock is held"
    );
    // In-process health check must succeed without colliding with self writer lock
    store.check_health().unwrap();

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

    // Observing a signed vote for prop_b against an unsigned IntentPending slot MUST record
    // ConflictingSigningIntent incident WITHOUT fabricating empty-signature EquivocationEvidence
    let mut bad_signed_b = ConsensusVote {
        proposal_id: prop_b.proposal_id.clone(),
        proposal_digest: prop_b.proposal_digest.clone(),
        network_id: prop_b.network_id.clone(),
        genesis_commitment: prop_b.genesis_commitment.clone(),
        protocol_version: prop_b.protocol_version.clone(),
        height: prop_b.height,
        round: prop_b.round,
        epoch: prop_b.epoch,
        validator_set_hash: prop_b.validator_set_hash.clone(),
        consensus_parameters_hash: prop_b.consensus_parameters_hash.clone(),
        parent_commitment: prop_b.parent_commitment.clone(),
        pre_state_root: prop_b.pre_state_root.clone(),
        post_state_root: prop_b.post_state_root.clone(),
        operation_scope: prop_b.operation_scope.clone(),
        vote_phase: VotePhase::Commit,
        validator_id: validator.validator_id.clone(),
        validator_pubkey_hex: validator.validator_pubkey_hex.clone(),
        approve: true,
        timestamp_ms: 1001,
        signature: String::new(),
    };
    bad_signed_b.signature = val_sk
        .sign(&bad_signed_b.canonical_signing_bytes().unwrap())
        .unwrap();
    assert!(store.record_observed_vote(&bad_signed_b, 1001).is_err());
    assert!(
        store.evidence().is_empty(),
        "IntentPending conflict must NOT fabricate ProvenEquivocation with empty signature"
    );
    assert_eq!(
        store.incidents().last().map(|i| i.classification),
        Some(VoteEvidenceClassification::ConflictingSigningIntent)
    );

    // Invalid observed vote (malformed pubkey) must be rejected WITHOUT fake self-equivocation evidence
    let mut invalid_vote = bad_signed_b.clone();
    invalid_vote.validator_pubkey_hex = "not_hex".to_string();
    assert!(store.record_observed_vote(&invalid_vote, 1001).is_err());
    assert!(store.evidence().is_empty());

    let mut detector = EquivocationDetector::new();
    assert!(detector.check_and_record(&invalid_vote, 1001).is_err());
    assert!(detector.evidence.is_empty());
    assert_eq!(
        detector.incidents.last().map(|i| i.classification),
        Some(VoteEvidenceClassification::InvalidObservedVote)
    );

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
    reopened.check_health().unwrap();

    // Rotated validator key cannot sign under old membership until an authorized membership update occurs
    let val_key_path = dir.join("val.key.json");
    let opts = NodeIdentityLoadOptions {
        profile: NetworkProfile::Production,
        passphrase: Some(Zeroizing::new("val-pass-1".to_string())),
        kdf_params: Some(KeyKdfParams::fast_for_tests()),
        ..Default::default()
    };
    let (vsk_disk, _) = load_or_generate_encrypted_key(&val_key_path, "validator", &opts).unwrap();
    let (vsk_rotated, _) = rotate_encrypted_key(
        &val_key_path,
        "val-pass-1",
        "val-pass-2",
        Some(KeyKdfParams::fast_for_tests()),
        "key_rotation",
        1005,
    )
    .unwrap();
    assert_ne!(vsk_disk.public_key_hex, vsk_rotated.public_key_hex);
    let mut prop_next = prop_a.clone();
    prop_next.height = 2;
    prop_next.finalize_digest_and_id().unwrap();
    assert!(
        reopened
            .sign_vote_safely(
                &validator,
                &LocalEncryptedSigningProvider::new(vsk_rotated, "encrypted"),
                &prop_next,
                true,
                VotePhase::Commit,
                1006,
            )
            .is_err(),
        "locally rotated validator key must not be accepted under un-transitioned validator membership"
    );

    // Valid QC check succeeds with canonical certificate_id and full ConsensusVerificationContext
    let membership =
        ValidatorMembership::try_new(vec![validator.clone()], DEFAULT_BFT_QUORUM_BPS).unwrap();
    let mut qc = QuorumCertificate {
        certificate_id: String::new(),
        proposal_id: prop_a.proposal_id.clone(),
        proposal_digest: prop_a.proposal_digest.clone(),
        network_id: prop_a.network_id.clone(),
        genesis_commitment: genesis_comm.clone(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        height: 1,
        round: 1,
        epoch: 1,
        validator_set_hash: vset_hash.clone(),
        consensus_parameters_hash: params_hash.clone(),
        parent_commitment: genesis_comm.clone(),
        pre_state_root: "pre_1".to_string(),
        post_state_root: "post_a".to_string(),
        operation_scope: "TEST".to_string(),
        vote_phase: VotePhase::Commit,
        ordered_event_ids: vec![],
        event_hashes: vec![],
        total_weight: 100,
        approving_weight: 100,
        quorum_threshold_bps: DEFAULT_BFT_QUORUM_BPS,
        votes: vec![vote_1.clone()],
        finalized_at_ms: 1003,
    };
    qc.finalize_certificate_id().unwrap();
    let ctx = ConsensusVerificationContext {
        network_id: prop_a.network_id.clone(),
        genesis_commitment: genesis_comm.clone(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        validator_epoch: 1,
        validator_set_hash: vset_hash.clone(),
        consensus_parameters: params.clone(),
        consensus_parameters_hash: params_hash.clone(),
    };
    verify_quorum_certificate_strict(&qc, &membership.all_validators(), &ctx).unwrap();

    // Corrupting equivocation_evidence.wal with unsigned evidence must fail closed
    drop(reopened);
    let fake_ev = EquivocationEvidence {
        network_id: prop_a.network_id.clone(),
        genesis_commitment: genesis_comm.clone(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        validator_id: "val_1".to_string(),
        pubkey_fingerprint: pubkey_fingerprint(&validator.validator_pubkey_hex).unwrap(),
        epoch: 1,
        height: 1,
        round: 1,
        vote_phase: VotePhase::Commit,
        reason: "fake".to_string(),
        vote_a: ConsensusVote {
            signature: String::new(),
            ..vote_1.clone()
        },
        vote_b: bad_signed_b,
        detected_at_ms: 1009,
    };
    fs::write(
        dir.join("equivocation_evidence.wal"),
        format!("{}\n", serde_json::to_string(&fake_ev).unwrap()),
    )
    .unwrap();
    assert!(
        EquivocationStore::open(&dir).is_err(),
        "tampered/unsigned evidence entry on disk must fail closed"
    );

    // Corrupting equivocation_votes.wal causes EquivocationStore::open to fail closed
    let _ = fs::remove_file(dir.join("equivocation_evidence.wal"));
    fs::write(dir.join("equivocation_votes.wal"), "{corrupt-json\n").unwrap();
    assert!(EquivocationStore::open(&dir).is_err());

    let _ = fs::remove_dir_all(&dir);
}
