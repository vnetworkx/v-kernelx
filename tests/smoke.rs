use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};
use v_kernelx::region::REGION_CREATE_OPERATION_NAME;
use v_kernelx::{
    authorize_region_access, build_region_genesis_event, canonical_event_hash,
    canonical_payload_hash, find_region_by_lookup_key, find_valid_nonce, list_regions_from_events,
    region_state_from_event, validate_dag, validate_region_create_request, verify_origin,
    KernelEngine, MemoryStore, OperationType, RegionCreateRequest, RegionVisibility,
    SettlementOutcome, SimulationHarness, VectorEvent, VectorState,
};

fn sign_region_request(
    signing_key: &SigningKey,
    request: &RegionCreateRequest,
) -> (String, String) {
    let mut payload = BTreeMap::new();
    payload.insert("region_name".to_string(), request.region_name.clone());
    payload.insert(
        "region_prefix".to_string(),
        request.region_prefix.clone().unwrap_or_default(),
    );
    payload.insert(
        "suggested_title".to_string(),
        request.suggested_title.clone().unwrap_or_default(),
    );
    payload.insert(
        "visibility".to_string(),
        request.visibility.as_str().to_string(),
    );
    payload.insert("section".to_string(), request.section.to_string());
    payload.insert(
        "trigger_event_hash".to_string(),
        request.trigger_event_hash.clone(),
    );
    payload.insert("creation_proof".to_string(), request.creation_proof.clone());
    payload.insert(
        "access_key".to_string(),
        request.access_key.clone().unwrap_or_default(),
    );
    payload.insert(
        "metadata".to_string(),
        serde_json::to_string(&request.metadata).expect("metadata serialization"),
    );

    let bytes = v_kernelx::canonical_region_request_signature_bytes(request)
        .expect("canonical request serialization");
    let signature = signing_key.sign(&bytes);

    (
        hex::encode(signing_key.verifying_key().to_bytes()),
        hex::encode(signature.to_bytes()),
    )
}

#[test]
fn smoke_flow_runs_end_to_end() {
    let mut harness = SimulationHarness::new();
    let report = harness.basic_flow().expect("simulation should complete");

    assert_eq!(report.vectors.len(), 2);
    assert!(report.records >= 6);

    let v_a = report
        .vectors
        .iter()
        .find(|v| v.vector_id == "v-a")
        .expect("v-a exists");
    let v_b = report
        .vectors
        .iter()
        .find(|v| v.vector_id == "v-b")
        .expect("v-b exists");

    assert_eq!(v_a.components.len(), 2);
    assert_eq!(v_b.components.len(), 2);
    assert!(v_a.certification.certified);
    assert!(v_b.certification.certified);
}

#[test]
fn origin_nonce_search_finds_valid_nonce() {
    let seed = "seed-for-test";
    let nonce = find_valid_nonce(seed, 1, 1_000_000).expect("nonce should exist");
    assert!(verify_origin(seed, nonce, 1));
}

#[test]
fn replay_is_deterministic_for_same_history() {
    let mut engine = KernelEngine::<MemoryStore>::new();

    let seed_a = "seed-a";
    let nonce_a = find_valid_nonce(seed_a, 1, 1_000_000).expect("nonce for a");
    let seed_b = "seed-b";
    let nonce_b = find_valid_nonce(seed_b, 1, 1_000_000).expect("nonce for b");

    let _a = engine
        .origin_create(
            "v-a",
            "pk-a",
            "space-main",
            vec![100, 50],
            seed_a,
            nonce_a,
            1,
        )
        .expect("origin a");

    let _b = engine
        .origin_create(
            "v-b",
            "pk-b",
            "space-main",
            vec![25, 25],
            seed_b,
            nonce_b,
            1,
        )
        .expect("origin b");

    let _ = engine
        .transfer("v-a", "v-b", vec![10, 5])
        .expect("transfer should succeed");

    let _ = engine.drain("v-a", 100).expect("drain should succeed");

    let _ = engine
        .project("v-b", vec![5, 5], "escrow-1")
        .expect("project should succeed");

    let _ = engine
        .reconstruct(
            "v-b",
            SettlementOutcome {
                outcome_tag: "settled".to_string(),
                gains: vec![1, 2],
                losses: vec![0, 1],
            },
        )
        .expect("reconstruct should succeed");

    let replay_1 = engine
        .replay_canonical_history()
        .expect("first replay should succeed");
    let replay_2 = engine
        .replay_canonical_history()
        .expect("second replay should succeed");

    assert_eq!(replay_1, replay_2);
    assert_eq!(replay_1.state_root, replay_2.state_root);
    assert_eq!(replay_1.replay_hash, replay_2.replay_hash);
    assert_eq!(replay_1.final_state, replay_2.final_state);
}

#[test]
fn query_results_are_clone_safe_and_do_not_mutate_engine_state() {
    let mut engine = KernelEngine::<MemoryStore>::new();

    let seed_a = "clone-safe-a";
    let nonce_a = find_valid_nonce(seed_a, 1, 1_000_000).expect("nonce a");
    let seed_b = "clone-safe-b";
    let nonce_b = find_valid_nonce(seed_b, 1, 1_000_000).expect("nonce b");

    let _ = engine
        .origin_create(
            "v-a",
            "pk-a",
            "space-main",
            vec![100, 50],
            seed_a,
            nonce_a,
            1,
        )
        .expect("origin a");

    let _ = engine
        .origin_create(
            "v-b",
            "pk-b",
            "space-main",
            vec![25, 25],
            seed_b,
            nonce_b,
            1,
        )
        .expect("origin b");

    let original_vector = engine
        .query_vector("v-a")
        .expect("query vector")
        .expect("vector exists");

    let mut mutated_vector = original_vector.clone();
    mutated_vector.components[0] = 999_999;
    mutated_vector.owner_pubkey = "tampered".to_string();

    let fresh_vector = engine
        .query_vector("v-a")
        .expect("query vector again")
        .expect("vector exists again");

    assert_eq!(fresh_vector.components[0], 100);
    assert_eq!(fresh_vector.owner_pubkey, "pk-a");
    assert_ne!(mutated_vector, fresh_vector);

    let original_events = engine.query_events().expect("query events");
    assert!(!original_events.is_empty());

    let mut tampered_events = original_events.clone();
    tampered_events[0].event_hash = "tampered-hash".to_string();
    tampered_events[0].payload_hash = "tampered-payload".to_string();

    let fresh_events = engine.query_events().expect("query events again");

    assert_eq!(original_events, fresh_events);
    assert_ne!(tampered_events, fresh_events);
}

#[test]
fn region_create_request_rejects_invalid_section() {
    let req = RegionCreateRequest {
        region_name: "SSP20".to_string(),
        region_prefix: Some("SSP".to_string()),
        suggested_title: Some("Spatial Service Protocol".to_string()),
        visibility: RegionVisibility::Public,
        section: 0,
        trigger_event_hash: "trigger-hash-1".to_string(),
        creation_proof: "proof-hash-1".to_string(),
        access_key: None,
        metadata: BTreeMap::new(),
        request_signature: "signature-1".to_string(),
    };

    assert!(validate_region_create_request(&req).is_err());
}

#[test]
fn region_genesis_is_canonical_and_queryable() {
    let mut metadata = BTreeMap::new();
    metadata.insert("region_theme".to_string(), "spatial".to_string());

    let req = RegionCreateRequest {
        region_name: "SSP20".to_string(),
        region_prefix: Some("SSP".to_string()),
        suggested_title: Some("Spatial Service Protocol".to_string()),
        visibility: RegionVisibility::Public,
        section: 23,
        trigger_event_hash: "trigger-hash-1".to_string(),
        creation_proof: "proof-hash-1".to_string(),
        access_key: None,
        metadata,
        request_signature: "signature-1".to_string(),
    };

    validate_region_create_request(&req).expect("request should be valid");

    let event_a = build_region_genesis_event(&req, "pk-region", 7, 1_234, 1)
        .expect("genesis event should build");
    let event_b = build_region_genesis_event(&req, "pk-region", 7, 1_234, 1)
        .expect("same input should build the same event");

    assert_eq!(event_a.payload_hash, event_b.payload_hash);
    assert_eq!(event_a.event_hash, event_b.event_hash);
    assert!(matches!(
        event_a.operation,
        OperationType::Other(ref name) if name == REGION_CREATE_OPERATION_NAME
    ));
    assert_eq!(
        event_a
            .vector_after
            .metadata
            .get("core_registry")
            .map(|v| v.as_str()),
        Some("core")
    );
    assert_eq!(
        event_a
            .vector_after
            .metadata
            .get("default_auth_ratio")
            .map(|v| v.as_str()),
        Some("1.0")
    );

    let derived = region_state_from_event(&event_a).expect("region should derive");
    assert_eq!(derived.region_name, "SSP20");
    assert_eq!(derived.normalized_name, "ssp20");
    assert_eq!(derived.section, 23);
    assert_eq!(derived.visibility.as_str(), "public");
    assert_eq!(derived.creator_public_key, "pk-region");

    let regions =
        list_regions_from_events(std::slice::from_ref(&event_a)).expect("regions should list");
    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0], derived);

    let found = find_region_by_lookup_key(std::slice::from_ref(&event_a), "SSP20", Some("SSP"))
        .expect("lookup should succeed")
        .expect("region should be found");
    assert_eq!(found.region_id, derived.region_id);

    assert!(authorize_region_access(&derived, None));
}

#[test]
fn private_region_authorization_uses_access_key() {
    let req = RegionCreateRequest {
        region_name: "ARX57".to_string(),
        region_prefix: Some("ARX".to_string()),
        suggested_title: Some("Access Region".to_string()),
        visibility: RegionVisibility::Private,
        section: 57,
        trigger_event_hash: "trigger-hash-2".to_string(),
        creation_proof: "proof-hash-2".to_string(),
        access_key: Some("region-secret".to_string()),
        metadata: BTreeMap::new(),
        request_signature: "signature-2".to_string(),
    };

    let event = build_region_genesis_event(&req, "pk-region-2", 9, 2_000, 1)
        .expect("private region event should build");
    assert!(matches!(
        event.operation,
        OperationType::Other(ref name) if name == REGION_CREATE_OPERATION_NAME
    ));
    let derived = region_state_from_event(&event).expect("private region should derive");

    assert!(!authorize_region_access(&derived, None));
    assert!(!authorize_region_access(&derived, Some("wrong-secret")));
    assert!(authorize_region_access(&derived, Some("region-secret")));
}

#[test]
fn create_region_is_canonical_and_rejects_duplicates() {
    let mut engine = KernelEngine::<MemoryStore>::new();

    let seed_core = "core-seed";
    let nonce_core = find_valid_nonce(seed_core, 1, 1_000_000).expect("core nonce");

    engine
        .origin_create("core", "core-pk", "core", vec![1], seed_core, nonce_core, 1)
        .expect("core origin");

    let mut metadata = BTreeMap::new();
    metadata.insert("region_theme".to_string(), "spatial".to_string());

    let request = RegionCreateRequest {
        region_name: "SSP20".to_string(),
        region_prefix: Some("SSP".to_string()),
        suggested_title: Some("Spatial Service Protocol".to_string()),
        visibility: RegionVisibility::Public,
        section: 23,
        trigger_event_hash: "trigger-hash-3".to_string(),
        creation_proof: "proof-hash-3".to_string(),
        access_key: None,
        metadata,
        request_signature: String::new(),
    };

    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let (actor_public_key, request_signature) = sign_region_request(&signing_key, &request);

    let mut signed_request = request.clone();
    signed_request.request_signature = request_signature;

    let created_1 = engine
        .create_region(signed_request.clone(), actor_public_key.clone())
        .expect("region create should succeed");

    let created_2 = engine
        .query_region(&created_1.region_id)
        .expect("query by id should succeed")
        .expect("region should exist");

    assert_eq!(created_1, created_2);

    let by_name = engine
        .query_region_by_name("SSP20", Some("SSP"))
        .expect("query by name should succeed")
        .expect("region should exist");
    assert_eq!(by_name.region_id, created_1.region_id);

    let resolved = engine
        .resolve_region_id("SSP20", Some("SSP"))
        .expect("resolve should succeed")
        .expect("region id should exist");
    assert_eq!(resolved, created_1.region_id);

    assert!(engine
        .region_exists("SSP20", Some("SSP"))
        .expect("exists check should succeed"));

    assert!(engine
        .authorize_region(&created_1.region_id, None)
        .expect("authorization should succeed"));

    let report =
        v_kernelx::debug_region_create_request_signature(&actor_public_key, &signed_request)
            .expect("debug report");

    eprintln!(
        "[test-region] lookup_key={} payload_len={} payload_hash={} sig_len={} verified={} preview={}",
        report.lookup_key,
        report.payload_len,
        report.payload_hash,
        report.signature_len,
        report.verified,
        report.canonical_preview_hex
    );

    assert!(
        report.verified,
        "local signature verification failed before engine call"
    );

    let duplicate = engine.create_region(signed_request, actor_public_key);
    assert!(duplicate.is_err());

    let replay_1 = engine
        .replay_canonical_history()
        .expect("replay should succeed");
    let replay_2 = engine
        .replay_canonical_history()
        .expect("replay should remain deterministic");
    assert_eq!(replay_1, replay_2);
    assert_eq!(replay_1.replay_hash, replay_2.replay_hash);

    assert!(replay_1.final_state.contains_key(&created_1.region_id));

    let region_state = replay_1
        .final_state
        .get(&created_1.region_id)
        .expect("region state exists");

    assert_eq!(
        region_state.metadata.get("core_registry"),
        Some(&"core".to_string())
    );

    assert_eq!(
        region_state.metadata.get("default_auth_ratio"),
        Some(&"1.0".to_string())
    );
}

#[test]
fn region_public_and_private_rules_hold_via_event_derivation() {
    let public_req = RegionCreateRequest {
        region_name: "PUBLIC23".to_string(),
        region_prefix: Some("PUB".to_string()),
        suggested_title: Some("Public Region".to_string()),
        visibility: RegionVisibility::Public,
        section: 23,
        trigger_event_hash: "trigger-hash-4".to_string(),
        creation_proof: "proof-hash-4".to_string(),
        access_key: None,
        metadata: BTreeMap::new(),
        request_signature: "signature-4".to_string(),
    };

    let public_event = build_region_genesis_event(&public_req, "pk-public", 10, 3_000, 1)
        .expect("public region event should build");
    assert!(matches!(
        public_event.operation,
        OperationType::Other(ref name) if name == REGION_CREATE_OPERATION_NAME
    ));
    let public_state = region_state_from_event(&public_event).expect("public region should derive");
    assert!(authorize_region_access(&public_state, None));

    let private_req = RegionCreateRequest {
        region_name: "PRIVATE95".to_string(),
        region_prefix: Some("PRV".to_string()),
        suggested_title: Some("Private Region".to_string()),
        visibility: RegionVisibility::Private,
        section: 95,
        trigger_event_hash: "trigger-hash-5".to_string(),
        creation_proof: "proof-hash-5".to_string(),
        access_key: Some("private-key".to_string()),
        metadata: BTreeMap::new(),
        request_signature: "signature-5".to_string(),
    };

    let private_event = build_region_genesis_event(&private_req, "pk-private", 11, 4_000, 1)
        .expect("private region event should build");
    assert!(matches!(
        private_event.operation,
        OperationType::Other(ref name) if name == REGION_CREATE_OPERATION_NAME
    ));
    let private_state =
        region_state_from_event(&private_event).expect("private region should derive");

    assert!(!authorize_region_access(&private_state, None));
    assert!(authorize_region_access(&private_state, Some("private-key")));
    assert!(!authorize_region_access(&private_state, Some("wrong-key")));
}

#[test]
fn dag_validation_rejects_missing_parent() {
    let mut state_before = VectorState::zero(2, "pk-a", "STANDARD");
    state_before.components = vec![10, 20];

    let mut state_after = state_before.clone();
    state_after.components = vec![5, 15];

    let mut event = VectorEvent::new(
        "event-1",
        vec!["missing-parent-hash".to_string()],
        "space-main",
        "v-a",
        OperationType::Transfer,
        state_before,
        state_after,
        1.0,
        true,
        "pk-a",
        1,
        1,
    );

    event.payload_hash = canonical_payload_hash(&event);
    event.event_hash = canonical_event_hash(&event);

    let result = validate_dag(&[event]);
    assert!(result.is_err());
}

#[test]
fn region_creation_is_fully_replayable_and_immutable() {
    let mut engine = KernelEngine::<MemoryStore>::new();

    let seed_core = "core-seed";
    let nonce_core = find_valid_nonce(seed_core, 1, 1_000_000).expect("nonce");

    engine
        .origin_create("core", "core-pk", "core", vec![1], seed_core, nonce_core, 1)
        .expect("core origin");

    let request = RegionCreateRequest {
        region_name: "CORENET".to_string(),
        region_prefix: Some("COR".to_string()),
        suggested_title: Some("Core Network".to_string()),
        visibility: RegionVisibility::Public,
        section: 1,
        trigger_event_hash: "core-trigger".to_string(),
        creation_proof: "core-proof".to_string(),
        access_key: None,
        metadata: BTreeMap::new(),
        request_signature: String::new(),
    };

    let signing_key = SigningKey::from_bytes(&[9u8; 32]);

    let (actor_public_key, request_signature) = sign_region_request(&signing_key, &request);

    let mut signed_request = request.clone();
    signed_request.request_signature = request_signature;

    let region = engine
        .create_region(signed_request, actor_public_key)
        .expect("region create");

    let replay_a = engine.replay_canonical_history().expect("replay a");
    let replay_b = engine.replay_canonical_history().expect("replay b");

    assert_eq!(replay_a, replay_b);

    assert!(replay_a.final_state.contains_key(&region.region_id));

    let stored = replay_a.final_state.get(&region.region_id).unwrap();

    assert_eq!(
        stored.metadata.get("core_registry"),
        Some(&"core".to_string())
    );

    assert_eq!(
        stored.metadata.get("default_auth_ratio"),
        Some(&"1.0".to_string())
    );
}
