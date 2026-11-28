use vnetwork_core::authorization::commit_request_nonce_event;
use vnetwork_core::replay::{apply_event_to_state, verify_replay_equivalence};
use vnetwork_core::state::{GenesisConfig, NetworkLedgerState};
use vnetwork_types::*;

fn genesis_and_state() -> (GenesisConfig, NetworkLedgerState) {
    let validator = KeypairMaterial::generate("request-replay-validator");
    let genesis = GenesisConfig::for_profile(
        NetworkProfile::Development,
        "request-replay-regression",
        "Request Replay Regression",
        vec![ConsensusValidator {
            validator_id: "validator-1".to_string(),
            node_id: "node-1".to_string(),
            validator_pubkey_hex: validator.public_key_hex,
            weight: 100,
            active: true,
            joined_epoch: 1,
        }],
    );
    let state = NetworkLedgerState::try_new(&genesis).expect("valid genesis");
    (genesis, state)
}

#[test]
fn replay_reconstructs_actor_nonce_and_seen_request_id() {
    let (genesis, mut state) = genesis_and_state();
    let actor = KeypairMaterial::generate("request-actor");
    commit_request_nonce_event(
        &mut state,
        "request-1",
        &actor.public_key_hex,
        1,
        100,
    )
    .expect("valid nonce commit");

    assert_eq!(state.actor_nonces.get(&actor.public_key_hex), Some(&1));
    assert!(state.seen_request_ids.contains("request-1"));
    let report = verify_replay_equivalence(&state, &genesis).expect("replay report");
    assert!(report.valid, "replayed anti-replay indexes must match live state");
}

#[test]
fn replay_detects_tampered_live_nonce_indexes() {
    let (genesis, mut state) = genesis_and_state();
    let actor = KeypairMaterial::generate("tampered-request-actor");
    commit_request_nonce_event(
        &mut state,
        "request-1",
        &actor.public_key_hex,
        1,
        100,
    )
    .expect("valid nonce commit");

    state.actor_nonces.insert(actor.public_key_hex.clone(), 99);
    let report = verify_replay_equivalence(&state, &genesis).expect("replay report");
    assert!(!report.valid, "tampered nonce indexes must not be copied into replay state");
}

#[test]
fn replay_rejects_a_second_commit_for_the_same_request_nonce() {
    let (genesis, mut state) = genesis_and_state();
    let actor = KeypairMaterial::generate("duplicate-request-actor");
    let event = commit_request_nonce_event(
        &mut state,
        "request-1",
        &actor.public_key_hex,
        1,
        100,
    )
    .expect("valid nonce commit");

    let mut replayed = NetworkLedgerState::try_new(&genesis).expect("valid genesis");
    apply_event_to_state(&mut replayed, &event).expect("first nonce event replays");
    assert!(apply_event_to_state(&mut replayed, &event).is_err());
}
