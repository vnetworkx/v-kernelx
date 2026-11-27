use crate::state::NetworkLedgerState;
use rand_core::{OsRng, RngCore};
use std::collections::BTreeSet;
use vnetwork_types::*;

pub fn issue_participant_challenge(
    state: &mut NetworkLedgerState,
    timestamp_ms: u64,
) -> ParticipantChallenge {
    let mut random_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut random_bytes);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"vnetwork/participant-challenge/v1:");
    hasher.update(state.network_id.as_bytes());
    hasher.update(b":");
    hasher.update(&random_bytes);
    let nonce = hasher.finalize().to_hex().to_string();
    let challenge_id = format!("chl_{}", &nonce[..24]);
    let challenge = ParticipantChallenge {
        challenge_id: challenge_id.clone(),
        network_id: state.network_id.clone(),
        nonce,
        issued_at_ms: timestamp_ms,
        expires_at_ms: timestamp_ms.checked_add(300_000).unwrap_or(u64::MAX),
    };
    state.challenges.insert(challenge_id, challenge.clone());
    challenge
}

pub fn canonical_join_signing_bytes(
    challenge: &ParticipantChallenge,
    participant_pubkey: &str,
    node_pubkey: &str,
    requested_scopes: &[ParticipationLevel],
) -> VResult<Vec<u8>> {
    let scopes_str: Vec<&str> = requested_scopes.iter().map(|s| s.as_str()).collect();
    let obj = serde_json::json!({
        "challenge_id": challenge.challenge_id,
        "network_id": challenge.network_id,
        "node_pubkey": node_pubkey,
        "nonce": challenge.nonce,
        "participant_pubkey": participant_pubkey,
        "requested_scopes": scopes_str,
    });
    canonical_json_bytes(&obj)
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedScopeAuthorization {
    pub target_participant_pubkey: String,
    pub grantor_pubkey: String,
    pub scopes: Vec<ParticipationLevel>,
    #[serde(default)]
    pub target_id: Option<String>,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    pub authorization_basis: String,
    pub signature: String,
}

impl SignedScopeAuthorization {
    pub fn canonical_signing_bytes(&self, network_id: &str) -> VResult<Vec<u8>> {
        let scopes_str: Vec<&str> = self.scopes.iter().map(|s| s.as_str()).collect();
        let obj = serde_json::json!({
            "authorization_basis": self.authorization_basis,
            "expires_at_ms": self.expires_at_ms,
            "grantor_pubkey": self.grantor_pubkey,
            "network_id": network_id,
            "protocol_version": PROTOCOL_VERSION,
            "scopes": scopes_str,
            "target_id": self.target_id,
            "target_participant_pubkey": self.target_participant_pubkey,
        });
        canonical_json_bytes(&obj)
    }

    pub fn verify_signature(&self, network_id: &str) -> VResult<()> {
        let bytes = self.canonical_signing_bytes(network_id)?;
        verify_ed25519(&self.grantor_pubkey, &bytes, &self.signature)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JoinNetworkRequest {
    pub challenge_id: String,
    pub participant_pubkey: String,
    pub node_pubkey: String,
    pub display_name: String,
    pub node_kind: NodeKind,
    pub requested_scopes: Vec<ParticipationLevel>,
    pub advertised_addresses: Vec<String>,
    pub participant_signature: String,
    pub node_signature: String,
    #[serde(default)]
    pub scope_authorizations: Vec<SignedScopeAuthorization>,
}

const NETWORK_GOVERNANCE_BASES: [&str; 2] = ["network_governance", "genesis_governance"];

fn has_network_governance_authority(
    state: &NetworkLedgerState,
    grantor_pubkey: &str,
    now_ms: u64,
) -> bool {
    state.participants.values().any(|participant| {
        participant.public_key_hex == grantor_pubkey
            && participant.status == ParticipationStatus::Active
            && participant.scope.grants.iter().any(|grant| {
                grant.level == ParticipationLevel::Network
                    && grant.target_id.is_none()
                    && grant.is_active_at(now_ms)
                    && NETWORK_GOVERNANCE_BASES
                        .iter()
                        .any(|basis| grant.authorization_basis.eq_ignore_ascii_case(basis))
            })
    })
}

/// Require an active, explicit Network-governance grant. Plain Network membership
/// is not enough to create the first Space or administer Network membership.
pub fn require_network_governance_at(
    state: &NetworkLedgerState,
    actor_pubkey: &str,
    now_ms: u64,
) -> VResult<()> {
    if has_network_governance_authority(state, actor_pubkey, now_ms) {
        Ok(())
    } else {
        Err(VNetworkError::Authorization(format!(
            "actor `{actor_pubkey}` lacks active Network governance authority"
        )))
    }
}

fn is_active_participant(state: &NetworkLedgerState, pubkey: &str) -> bool {
    state.participants.values().any(|participant| {
        participant.public_key_hex == pubkey && participant.status == ParticipationStatus::Active
    })
}

/// Returns whether a participant can delegate/revoke the specified authority.
/// A normal open-enrollment NETWORK grant is membership only, never governance.
fn grantor_can_delegate_level(
    state: &NetworkLedgerState,
    grantor_pubkey: &str,
    level: ParticipationLevel,
    target_id: Option<&str>,
    now_ms: u64,
) -> bool {
    if grantor_pubkey.trim().is_empty() || !is_active_participant(state, grantor_pubkey) {
        return false;
    }

    match level {
        ParticipationLevel::Network => {
            // Network membership is intentionally insufficient. Only an explicit,
            // active governance grant confers authority over membership transitions.
            target_id.is_none()
                && has_network_governance_authority(state, grantor_pubkey, now_ms)
        }
        ParticipationLevel::Space => {
            let Some(space_id) = target_id else {
                return false;
            };
            state.participants.values().any(|participant| {
                participant.public_key_hex == grantor_pubkey
                    && participant.status == ParticipationStatus::Active
                    && participant.scope.has_active_scope(
                        ParticipationLevel::Space,
                        Some(space_id),
                        now_ms,
                    )
            })
        }
        ParticipationLevel::Region => {
            let Some(space_id) = target_id else {
                return false;
            };
            state
                .spaces
                .values()
                .any(|space| space.owner_pubkey == grantor_pubkey && space.space_id == space_id)
        }
        ParticipationLevel::Wallet => {
            let Some(entity_id) = target_id else {
                return false;
            };
            state.regions.values().any(|region| {
                region.creator_pubkey == grantor_pubkey && region.region_id == entity_id
            }) || state.wallets.values().any(|wallet| {
                wallet.owner_pubkey == grantor_pubkey && wallet.wallet_id == entity_id
            })
        }
        ParticipationLevel::Token => {
            let Some(wallet_id) = target_id else {
                return false;
            };
            state.wallets.values().any(|wallet| {
                wallet.owner_pubkey == grantor_pubkey && wallet.wallet_id == wallet_id
            })
        }
    }
}

fn can_authorize_join_scope(
    state: &NetworkLedgerState,
    auth: &SignedScopeAuthorization,
    level: ParticipationLevel,
    now_ms: u64,
) -> bool {
    if grantor_can_delegate_level(
        state,
        &auth.grantor_pubkey,
        level,
        auth.target_id.as_deref(),
        now_ms,
    ) {
        return true;
    }

    // Preserve the existing genesis onboarding path, but never treat validator
    // status alone as ongoing authority. Genesis authorization is an explicit,
    // signed, one-time join grant and remains subject to consensus commitment.
    state.height == 0
        && auth.target_id.is_none()
        && auth.authorization_basis.trim().to_ascii_lowercase().starts_with("genesis")
        && state.validators.iter().any(|validator| {
            validator.active
                && validator.joined_epoch == state.validator_epoch
                && validator.validator_pubkey_hex == auth.grantor_pubkey
        })
}

pub fn verify_and_register_participant(
    state: &mut NetworkLedgerState,
    req: &JoinNetworkRequest,
    timestamp_ms: u64,
) -> VResult<(ParticipantRecord, NodeRecord, LedgerEvent)> {
    let challenge = state
        .challenges
        .remove(&req.challenge_id)
        .ok_or_else(|| VNetworkError::Authorization("unknown or already used challenge_id".to_string()))?;

    if timestamp_ms > challenge.expires_at_ms {
        return Err(VNetworkError::Authorization("participant challenge expired".to_string()));
    }

    if req.participant_pubkey == req.node_pubkey {
        return Err(VNetworkError::Authorization(
            "participant key and node identity key must be distinct".to_string(),
        ));
    }

    // Never allow a join request to self-promote directly to ValidatorNode
    let effective_node_kind = match req.node_kind {
        NodeKind::ValidatorNode => NodeKind::FullNode,
        other => other,
    };

    let msg = canonical_join_signing_bytes(
        &challenge,
        &req.participant_pubkey,
        &req.node_pubkey,
        &req.requested_scopes,
    )?;
    verify_ed25519(&req.participant_pubkey, &msg, &req.participant_signature)?;
    verify_ed25519(&req.node_pubkey, &msg, &req.node_signature)?;

    let participant_id = derive_participant_id(&req.participant_pubkey);
    let node_id = derive_node_id(&req.node_pubkey);

    // Enrollment must never overwrite historical identity records. Reinstatement
    // and key rotation require their own authorized, auditable transitions.
    if state.participants.contains_key(&participant_id) {
        return Err(VNetworkError::Authorization(
            "participant identity already exists; rejoining requires explicit governance reinstatement"
                .to_string(),
        ));
    }
    if state.nodes.contains_key(&node_id) {
        return Err(VNetworkError::Authorization(
            "node identity already exists; key reuse requires an authorized identity-rotation transition"
                .to_string(),
        ));
    }

    // Open enrollment creates membership only. It never grants governance.
    let mut grants = vec![ScopeGrant {
        level: ParticipationLevel::Network,
        target_id: None,
        granted_at_ms: timestamp_ms,
        grantor_pubkey: "network-open-join".to_string(),
        expires_at_ms: None,
        authorization_basis: "challenge_response".to_string(),
        revoked: false,
    }];

    for auth in &req.scope_authorizations {
        if auth.target_participant_pubkey != req.participant_pubkey {
            return Err(VNetworkError::Authorization(
                "scope authorization target_participant_pubkey mismatch".to_string(),
            ));
        }
        if let Some(exp) = auth.expires_at_ms {
            if timestamp_ms >= exp {
                return Err(VNetworkError::Authorization(
                    "scope authorization is expired".to_string(),
                ));
            }
        }
        auth.verify_signature(&state.network_id)?;
        for &lvl in &auth.scopes {
            if !can_authorize_join_scope(state, auth, lvl, timestamp_ms) {
                return Err(VNetworkError::Authorization(format!(
                    "grantor `{}` is not authorized to delegate `{}` scope",
                    auth.grantor_pubkey,
                    lvl.as_str()
                )));
            }
            grants.push(ScopeGrant {
                level: lvl,
                target_id: auth.target_id.clone(),
                granted_at_ms: timestamp_ms,
                grantor_pubkey: auth.grantor_pubkey.clone(),
                expires_at_ms: auth.expires_at_ms,
                authorization_basis: auth.authorization_basis.clone(),
                revoked: false,
            });
        }
    }

    let mut scope = ParticipationScope {
        levels: BTreeSet::new(),
        grants,
        validator_eligible: false,
    };
    scope.recompute_levels(timestamp_ms);
    let levels = scope.levels.clone();

    let participant = ParticipantRecord {
        participant_id: participant_id.clone(),
        public_key_hex: req.participant_pubkey.clone(),
        node_id: node_id.clone(),
        node_pubkey_hex: req.node_pubkey.clone(),
        display_name: if req.display_name.trim().is_empty() {
            participant_id.clone()
        } else {
            req.display_name.trim().to_string()
        },
        node_kind: effective_node_kind,
        status: ParticipationStatus::Active,
        scope,
        joined_at_ms: timestamp_ms,
        last_seen_ms: timestamp_ms,
    };

    let node = NodeRecord {
        node_id: node_id.clone(),
        node_pubkey_hex: req.node_pubkey.clone(),
        participant_id: Some(participant_id.clone()),
        node_kind: effective_node_kind,
        advertised_addresses: req.advertised_addresses.clone(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        sync_height: state.height,
        healthy: true,
        validator_eligible: false,
        scopes: levels.into_iter().collect(),
        last_seen_ms: timestamp_ms,
    };

    state.participants.insert(participant_id.clone(), participant.clone());
    state.nodes.insert(node_id.clone(), node.clone());

    state.logical_clock = state
        .logical_clock
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
    let sequence = (state.events.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
    let parents = state.latest_event_hash().into_iter().collect();
    let after_hash = blake3_hex(&canonical_json_bytes(&participant)?);
    let event = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "participant",
        &participant_id,
        "PARTICIPANT_JOIN",
        &req.participant_pubkey,
        state.logical_clock,
        timestamp_ms,
        serde_json::json!({
            "participant": participant,
            "node": node,
        }),
        "",
        after_hash,
    )?;
    state.events.push(event.clone());

    Ok((participant, node, event))
}

pub fn apply_grant_participant_scope(
    state: &mut NetworkLedgerState,
    target_participant_ref: &str,
    level_str: &str,
    target_id: Option<String>,
    expires_at_ms: Option<u64>,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(ParticipantRecord, LedgerEvent)> {
    let level = ParticipationLevel::parse(level_str).ok_or_else(|| {
        VNetworkError::Validation(format!("invalid participation level `{level_str}`"))
    })?;
    if let Some(exp) = expires_at_ms {
        if timestamp_ms >= exp {
            return Err(VNetworkError::Validation(
                "scope grant expires_at_ms must be in the future".to_string(),
            ));
        }
    }
    if !grantor_can_delegate_level(state, actor_pubkey, level, target_id.as_deref(), timestamp_ms) {
        return Err(VNetworkError::Authorization(format!(
            "actor `{actor_pubkey}` is not authorized to grant `{}` scope for the requested target",
            level.as_str()
        )));
    }

    let mut participant = state
        .participants
        .get(target_participant_ref)
        .or_else(|| {
            state
                .participants
                .values()
                .find(|p| p.public_key_hex == target_participant_ref)
        })
        .cloned()
        .ok_or_else(|| {
            VNetworkError::NotFound(format!("participant `{target_participant_ref}` not found"))
        })?;

    if participant.status != ParticipationStatus::Active {
        return Err(VNetworkError::Authorization(
            "cannot grant scope to non-active participant".to_string(),
        ));
    }

    let before_hash = blake3_hex(&canonical_json_bytes(&participant)?);
    participant.scope.grants.push(ScopeGrant {
        level,
        target_id,
        granted_at_ms: timestamp_ms,
        grantor_pubkey: actor_pubkey.to_string(),
        expires_at_ms,
        authorization_basis: "explicit_grant".to_string(),
        revoked: false,
    });
    participant.scope.recompute_levels(timestamp_ms);
    participant.last_seen_ms = timestamp_ms;

    state
        .participants
        .insert(participant.participant_id.clone(), participant.clone());
    if let Some(node) = state.nodes.get_mut(&participant.node_id) {
        node.scopes = participant.scope.levels.iter().copied().collect();
        node.last_seen_ms = timestamp_ms;
    }

    state.logical_clock = state
        .logical_clock
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
    let sequence = (state.events.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
    let parents = state.latest_event_hash().into_iter().collect();
    let after_hash = blake3_hex(&canonical_json_bytes(&participant)?);
    let event = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "participant",
        &participant.participant_id,
        "PARTICIPANT_SCOPE_GRANT",
        actor_pubkey,
        state.logical_clock,
        timestamp_ms,
        serde_json::json!({
            "participant": participant,
            "node": state.nodes.get(&participant.node_id).cloned(),
        }),
        before_hash,
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((participant, event))
}

pub fn apply_revoke_participant_scope(
    state: &mut NetworkLedgerState,
    target_participant_ref: &str,
    level_str: &str,
    target_id: Option<&str>,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(ParticipantRecord, LedgerEvent)> {
    let level = ParticipationLevel::parse(level_str).ok_or_else(|| {
        VNetworkError::Validation(format!("invalid participation level `{level_str}`"))
    })?;
    if !grantor_can_delegate_level(state, actor_pubkey, level, target_id, timestamp_ms) {
        return Err(VNetworkError::Authorization(format!(
            "actor `{actor_pubkey}` is not authorized to revoke `{}` scope for the requested target",
            level.as_str()
        )));
    }

    let mut participant = state
        .participants
        .get(target_participant_ref)
        .or_else(|| {
            state
                .participants
                .values()
                .find(|p| p.public_key_hex == target_participant_ref)
        })
        .cloned()
        .ok_or_else(|| {
            VNetworkError::NotFound(format!("participant `{target_participant_ref}` not found"))
        })?;

    let before_hash = blake3_hex(&canonical_json_bytes(&participant)?);
    let mut matched = false;
    for grant in &mut participant.scope.grants {
        // Exact target matching is intentional: a targeted revocation must never
        // consume an unscoped baseline grant or another entity's authorization.
        if grant.level == level && !grant.revoked && grant.target_id.as_deref() == target_id {
            grant.revoked = true;
            matched = true;
        }
    }
    if !matched {
        return Err(VNetworkError::NotFound(format!(
            "no active `{}` grant found for participant `{}` at the requested target",
            level.as_str(),
            participant.participant_id
        )));
    }

    // NETWORK scope revocation is the membership-removal transition. It can only
    // be performed by an explicit governance authority, checked above. Marking
    // status revoked also invalidates any remaining scopes and node credentials.
    if level == ParticipationLevel::Network {
        participant.status = ParticipationStatus::Revoked;
    }
    participant.scope.recompute_levels(timestamp_ms);
    participant.last_seen_ms = timestamp_ms;

    state
        .participants
        .insert(participant.participant_id.clone(), participant.clone());
    if let Some(node) = state.nodes.get_mut(&participant.node_id) {
        node.scopes = participant.scope.levels.iter().copied().collect();
        node.last_seen_ms = timestamp_ms;
    }

    state.logical_clock = state
        .logical_clock
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
    let sequence = (state.events.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
    let parents = state.latest_event_hash().into_iter().collect();
    let after_hash = blake3_hex(&canonical_json_bytes(&participant)?);
    let event = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "participant",
        &participant.participant_id,
        "PARTICIPANT_SCOPE_REVOKE",
        actor_pubkey,
        state.logical_clock,
        timestamp_ms,
        serde_json::json!({
            "participant": participant,
            "node": state.nodes.get(&participant.node_id).cloned(),
        }),
        before_hash,
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((participant, event))
}

pub fn require_participant_scope_at(
    state: &NetworkLedgerState,
    actor_pubkey: &str,
    required_level: ParticipationLevel,
    target_id: Option<&str>,
    now_ms: u64,
) -> VResult<()> {
    if let Some(p) = state
        .participants
        .values()
        .find(|p| p.public_key_hex == actor_pubkey)
    {
        if p.status != ParticipationStatus::Active {
            return Err(VNetworkError::Authorization(
                "participant status is not active".to_string(),
            ));
        }
        if !p.scope.has_active_scope(required_level, target_id, now_ms) {
            return Err(VNetworkError::Authorization(format!(
                "participant `{}` lacks active `{}` scope",
                p.participant_id,
                required_level.as_str()
            )));
        }
        return Ok(());
    }

    Err(VNetworkError::Authorization(format!(
        "actor `{actor_pubkey}` is not an active joined participant with `{}` scope",
        required_level.as_str()
    )))
}

pub fn require_participant_scope(
    state: &NetworkLedgerState,
    actor_pubkey: &str,
    required_level: ParticipationLevel,
) -> VResult<()> {
    require_participant_scope_at(state, actor_pubkey, required_level, None, 0)
}


#[cfg(test)]
mod onboarding_regressions {
    use super::{
        can_authorize_join_scope, canonical_join_signing_bytes, issue_participant_challenge,
        verify_and_register_participant, JoinNetworkRequest, SignedScopeAuthorization,
    };
    use crate::state::{GenesisConfig, NetworkLedgerState};
    use vnetwork_types::*;

    fn test_state() -> (NetworkLedgerState, KeypairMaterial) {
        let validator = KeypairMaterial::generate("onboarding-validator");
        let genesis = GenesisConfig::for_profile(
            NetworkProfile::Development,
            "onboarding-regression",
            "Onboarding Regression",
            vec![ConsensusValidator {
                validator_id: "validator-1".to_string(),
                node_id: "node-1".to_string(),
                validator_pubkey_hex: validator.public_key_hex.clone(),
                weight: 100,
                active: true,
                joined_epoch: 1,
            }],
        );
        (NetworkLedgerState::try_new(&genesis).expect("valid genesis"), validator)
    }

    fn join_request(
        state: &mut NetworkLedgerState,
        participant: &KeypairMaterial,
        node: &KeypairMaterial,
        timestamp_ms: u64,
    ) -> JoinNetworkRequest {
        let challenge = issue_participant_challenge(state, timestamp_ms);
        let requested_scopes = Vec::new();
        let message = canonical_join_signing_bytes(
            &challenge,
            &participant.public_key_hex,
            &node.public_key_hex,
            &requested_scopes,
        )
        .expect("canonical join message");
        JoinNetworkRequest {
            challenge_id: challenge.challenge_id,
            participant_pubkey: participant.public_key_hex.clone(),
            node_pubkey: node.public_key_hex.clone(),
            display_name: "regression-participant".to_string(),
            node_kind: NodeKind::FullNode,
            requested_scopes,
            advertised_addresses: Vec::new(),
            participant_signature: participant.sign(&message),
            node_signature: node.sign(&message),
            scope_authorizations: Vec::new(),
        }
    }

    #[test]
    fn genesis_validator_join_delegation_is_only_available_at_bootstrap() {
        let (mut state, validator) = test_state();
        let authorization = SignedScopeAuthorization {
            target_participant_pubkey: "participant".to_string(),
            grantor_pubkey: validator.public_key_hex,
            scopes: vec![ParticipationLevel::Network],
            target_id: None,
            expires_at_ms: None,
            authorization_basis: "genesis_test".to_string(),
            signature: String::new(),
        };
        assert!(can_authorize_join_scope(
            &state,
            &authorization,
            ParticipationLevel::Network,
            1,
        ));
        state.height = 1;
        assert!(!can_authorize_join_scope(
            &state,
            &authorization,
            ParticipationLevel::Network,
            1,
        ));
    }

    #[test]
    fn enrollment_cannot_overwrite_existing_participant_identity() {
        let (mut state, _) = test_state();
        let participant = KeypairMaterial::generate("repeat-participant");
        let node = KeypairMaterial::generate("repeat-node");
        let first = join_request(&mut state, &participant, &node, 10);
        verify_and_register_participant(&mut state, &first, 10).expect("first join succeeds");
        let second = join_request(&mut state, &participant, &node, 20);
        assert!(matches!(
            verify_and_register_participant(&mut state, &second, 20),
            Err(VNetworkError::Authorization(_))
        ));
        assert_eq!(state.participants.len(), 1);
        assert_eq!(state.nodes.len(), 1);
    }

    #[test]
    fn enrollment_cannot_overwrite_existing_node_identity() {
        let (mut state, _) = test_state();
        let first_participant = KeypairMaterial::generate("first-node-owner");
        let second_participant = KeypairMaterial::generate("second-node-owner");
        let node = KeypairMaterial::generate("reused-node");
        let first = join_request(&mut state, &first_participant, &node, 10);
        verify_and_register_participant(&mut state, &first, 10).expect("first join succeeds");
        let second = join_request(&mut state, &second_participant, &node, 20);
        assert!(matches!(
            verify_and_register_participant(&mut state, &second, 20),
            Err(VNetworkError::Authorization(_))
        ));
        assert_eq!(state.participants.len(), 1);
        assert_eq!(state.nodes.len(), 1);
    }
}
