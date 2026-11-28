use vnetwork_core::identity::{apply_grant_participant_scope, apply_revoke_participant_scope};
use vnetwork_core::state::GenesisConfig;
use vnetwork_core::state::NetworkLedgerState;
use vnetwork_types::*;

fn state_with_participants() -> (NetworkLedgerState, String, String, String) {
    let validator = KeypairMaterial::generate("validator");
    let genesis = GenesisConfig::for_profile(
        NetworkProfile::Development,
        "identity-authorization-regression",
        "Identity authorization regression",
        vec![ConsensusValidator {
            validator_id: "validator-1".to_string(),
            node_id: "node-validator-1".to_string(),
            validator_pubkey_hex: validator.public_key_hex.clone(),
            weight: 100,
            active: true,
            joined_epoch: 1,
        }],
    );
    let mut state = NetworkLedgerState::try_new(&genesis).expect("valid test genesis");
    let ordinary = KeypairMaterial::generate("ordinary-participant");
    let authority = KeypairMaterial::generate("network-authority");
    let outsider = KeypairMaterial::generate("outsider");

    insert_participant(&mut state, &ordinary, vec![baseline_network_grant()], ParticipationStatus::Active);
    insert_participant(
        &mut state,
        &authority,
        vec![ScopeGrant {
            level: ParticipationLevel::Network,
            target_id: None,
            granted_at_ms: 1,
            grantor_pubkey: "genesis-governance".to_string(),
            expires_at_ms: None,
            authorization_basis: "genesis_governance".to_string(),
            revoked: false,
        }],
        ParticipationStatus::Active,
    );
    insert_participant(&mut state, &outsider, vec![baseline_network_grant()], ParticipationStatus::Active);
    (
        state,
        ordinary.public_key_hex.clone(),
        authority.public_key_hex.clone(),
        outsider.public_key_hex.clone(),
    )
}

fn baseline_network_grant() -> ScopeGrant {
    ScopeGrant {
        level: ParticipationLevel::Network,
        target_id: None,
        granted_at_ms: 1,
        grantor_pubkey: "network-open-join".to_string(),
        expires_at_ms: None,
        authorization_basis: "challenge_response".to_string(),
        revoked: false,
    }
}

fn insert_participant(
    state: &mut NetworkLedgerState,
    key: &KeypairMaterial,
    grants: Vec<ScopeGrant>,
    status: ParticipationStatus,
) {
    let participant_id = derive_participant_id(&key.public_key_hex);
    let node_id = derive_node_id(&format!("{}-node", key.public_key_hex));
    let mut scope = ParticipationScope {
        levels: Default::default(),
        grants,
        validator_eligible: false,
    };
    scope.recompute_levels(10);
    let participant = ParticipantRecord {
        participant_id: participant_id.clone(),
        public_key_hex: key.public_key_hex.clone(),
        node_id: node_id.clone(),
        node_pubkey_hex: format!("{}-node", key.public_key_hex),
        display_name: participant_id.clone(),
        node_kind: NodeKind::FullNode,
        status,
        scope: scope.clone(),
        joined_at_ms: 1,
        last_seen_ms: 1,
    };
    let node = NodeRecord {
        node_id: node_id.clone(),
        node_pubkey_hex: format!("{}-node", key.public_key_hex),
        participant_id: Some(participant_id.clone()),
        node_kind: NodeKind::FullNode,
        advertised_addresses: vec![],
        protocol_version: PROTOCOL_VERSION.to_string(),
        sync_height: state.height,
        healthy: true,
        validator_eligible: false,
        scopes: scope.levels.into_iter().collect(),
        last_seen_ms: 1,
    };
    state.participants.insert(participant_id, participant);
    state.nodes.insert(node_id, node);
}

#[test]
fn ordinary_network_membership_is_not_network_governance() {
    let (mut state, ordinary, _, _) = state_with_participants();
    let target_id = state.participants.keys().next().unwrap().clone();
    let result = apply_grant_participant_scope(
        &mut state,
        &target_id,
        "NETWORK",
        None,
        None,
        &ordinary,
        20,
    );
    assert!(matches!(result, Err(VNetworkError::Authorization(_))));
}

#[test]
fn only_explicit_network_authority_can_remove_membership_and_removal_is_recorded() {
    let (mut state, ordinary, authority, _) = state_with_participants();
    let ordinary_id = state
        .participants
        .values()
        .find(|participant| participant.public_key_hex == ordinary)
        .unwrap()
        .participant_id
        .clone();
    let before_events = state.events.len();

    let denied = apply_revoke_participant_scope(
        &mut state,
        &ordinary_id,
        "NETWORK",
        None,
        &ordinary,
        20,
    );
    assert!(matches!(denied, Err(VNetworkError::Authorization(_))));
    assert_eq!(state.participants[&ordinary_id].status, ParticipationStatus::Active);
    assert_eq!(state.events.len(), before_events);

    let (removed, event) = apply_revoke_participant_scope(
        &mut state,
        &ordinary_id,
        "NETWORK",
        None,
        &authority,
        21,
    )
    .expect("governance authority can remove a member");
    assert_eq!(removed.status, ParticipationStatus::Revoked);
    assert_eq!(state.events.len(), before_events + 1);
    assert_eq!(event.operation, "PARTICIPANT_SCOPE_REVOKE");
    assert_eq!(state.events.last().unwrap().event_hash, event.event_hash);
}

#[test]
fn targeted_revoke_preserves_unscoped_legacy_baseline_grant() {
    let (mut state, _, authority, _) = state_with_participants();
    let target_id = state
        .participants
        .values()
        .find(|participant| participant.public_key_hex == authority)
        .unwrap()
        .participant_id
        .clone();
    let participant = state.participants.get_mut(&target_id).unwrap();
    participant.scope.grants.push(ScopeGrant {
        level: ParticipationLevel::Space,
        target_id: None,
        granted_at_ms: 2,
        grantor_pubkey: "legacy-grantor".to_string(),
        expires_at_ms: None,
        authorization_basis: "legacy_baseline".to_string(),
        revoked: false,
    });
    participant.scope.grants.push(ScopeGrant {
        level: ParticipationLevel::Space,
        target_id: Some("space-a".to_string()),
        granted_at_ms: 3,
        grantor_pubkey: authority.clone(),
        expires_at_ms: None,
        authorization_basis: "explicit_grant".to_string(),
        revoked: false,
    });
    participant.scope.levels.insert(ParticipationLevel::Space);

    apply_revoke_participant_scope(
        &mut state,
        &target_id,
        "SPACE",
        Some("space-a"),
        &authority,
        30,
    )
    .expect("authority can revoke the matching targeted grant");

    let grants = &state.participants[&target_id].scope.grants;
    assert!(grants.iter().any(|grant| {
        grant.level == ParticipationLevel::Space && grant.target_id.is_none() && !grant.revoked
    }));
    assert!(grants.iter().any(|grant| {
        grant.level == ParticipationLevel::Space
            && grant.target_id.as_deref() == Some("space-a")
            && grant.revoked
    }));
}

#[test]
fn validators_and_unknown_or_revoked_authorities_cannot_delegate_network_scope() {
    let (mut state, _, _, outsider) = state_with_participants();
    let target_id = state.participants.keys().next().unwrap().clone();
    assert!(matches!(
        apply_grant_participant_scope(
            &mut state,
            &target_id,
            "NETWORK",
            None,
            None,
            &outsider,
            20,
        ),
        Err(VNetworkError::Authorization(_))
    ));

    let authority_id = state
        .participants
        .values()
        .find(|participant| {
            participant.scope.grants.iter().any(|grant| {
                grant.authorization_basis == "genesis_governance"
            })
        })
        .unwrap()
        .participant_id
        .clone();
    let authority = state.participants.get_mut(&authority_id).unwrap();
    authority.scope.grants[0].revoked = true;
    authority.scope.recompute_levels(20);
    let authority_pubkey = authority.public_key_hex.clone();
    assert!(matches!(
        apply_grant_participant_scope(
            &mut state,
            &target_id,
            "NETWORK",
            None,
            None,
            &authority_pubkey,
            21,
        ),
        Err(VNetworkError::Authorization(_))
    ));
}

#[test]
fn network_grants_are_not_delegable_for_non_network_targets() {
    let (mut state, _, authority, _) = state_with_participants();
    let target_id = state.participants.keys().next().unwrap().clone();
    let result = apply_grant_participant_scope(
        &mut state,
        &target_id,
        "NETWORK",
        Some("space-a".to_string()),
        None,
        &authority,
        20,
    );
    assert!(matches!(result, Err(VNetworkError::Authorization(_))));
}
