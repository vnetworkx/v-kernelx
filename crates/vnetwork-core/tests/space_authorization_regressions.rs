use std::collections::BTreeMap;
use vnetwork_core::apply_create_space;
use vnetwork_core::state::{GenesisConfig, NetworkLedgerState};
use vnetwork_core::transition::apply_network_operation_with_policy;
use vnetwork_types::*;

fn state_with_participant(basis: &str) -> (NetworkLedgerState, KeypairMaterial) {
    let validator = KeypairMaterial::generate("space-test-validator");
    let genesis = GenesisConfig::for_profile(
        NetworkProfile::Development,
        "space-authorization-regression",
        "Space authorization regression",
        vec![ConsensusValidator {
            validator_id: "validator-1".to_string(),
            node_id: "node-1".to_string(),
            validator_pubkey_hex: validator.public_key_hex.clone(),
            weight: 100,
            active: true,
            joined_epoch: 1,
        }],
    );
    let mut state = NetworkLedgerState::try_new(&genesis).expect("valid genesis");
    let actor = KeypairMaterial::generate("space-actor");
    let mut scope = ParticipationScope {
        levels: Default::default(),
        grants: vec![ScopeGrant {
            level: ParticipationLevel::Network,
            target_id: None,
            granted_at_ms: 1,
            grantor_pubkey: "test-governance-authority".to_string(),
            expires_at_ms: None,
            authorization_basis: basis.to_string(),
            revoked: false,
        }],
        validator_eligible: false,
    };
    scope.recompute_levels(2);
    let participant_id = derive_participant_id(&actor.public_key_hex);
    state.participants.insert(
        participant_id.clone(),
        ParticipantRecord {
            participant_id,
            public_key_hex: actor.public_key_hex.clone(),
            node_id: "node-actor".to_string(),
            node_pubkey_hex: "node-key".to_string(),
            display_name: "actor".to_string(),
            node_kind: NodeKind::FullNode,
            status: ParticipationStatus::Active,
            scope,
            joined_at_ms: 1,
            last_seen_ms: 1,
        },
    );
    (state, actor)
}

#[test]
fn ordinary_network_membership_cannot_create_first_space() {
    let (mut state, actor) = state_with_participant("challenge_response");
    let result = apply_create_space(
        &mut state,
        "first-space",
        Visibility::Public,
        false,
        &actor.public_key_hex,
        BTreeMap::new(),
        10,
    );
    assert!(matches!(result, Err(VNetworkError::Authorization(_))));
    assert!(state.spaces.is_empty());
    assert!(state.events.is_empty());
}

#[test]
fn explicit_network_governance_can_create_first_space_without_preexisting_space_grant() {
    let (mut state, actor) = state_with_participant("network_governance");
    let (space, event) = apply_create_space(
        &mut state,
        "first-space",
        Visibility::Public,
        false,
        &actor.public_key_hex,
        BTreeMap::new(),
        10,
    )
    .expect("network governance should create the first Space");
    assert_eq!(state.spaces.get(&space.space_id), Some(&space));
    assert_eq!(event.operation, "SPACE_CREATE");
    assert_eq!(state.events.len(), 1);
}

#[test]
fn expired_or_revoked_governance_cannot_create_space() {
    for (expiry, revoked) in [(Some(9), false), (None, true)] {
        let (mut state, actor) = state_with_participant("network_governance");
        let participant = state.participants.values_mut().next().unwrap();
        participant.scope.grants[0].expires_at_ms = expiry;
        participant.scope.grants[0].revoked = revoked;
        let result = apply_create_space(
            &mut state,
            "blocked-space",
            Visibility::Private,
            false,
            &actor.public_key_hex,
            BTreeMap::new(),
            10,
        );
        assert!(matches!(result, Err(VNetworkError::Authorization(_))));
        assert!(state.spaces.is_empty());
    }
}


#[test]
fn failed_network_transition_does_not_leak_partial_space_mutation() {
    let (mut state, actor) = state_with_participant("network_governance");
    state.logical_clock = u64::MAX;
    let before = state.clone();
    let result = apply_network_operation_with_policy(
        &mut state,
        false,
        &NetworkOperation::CreateSpace {
            name: "must-not-commit".to_string(),
            visibility: "PUBLIC".to_string(),
            ghost: false,
        },
        &actor.public_key_hex,
        10,
    );
    assert!(result.is_err());
    assert_eq!(state, before);
}
