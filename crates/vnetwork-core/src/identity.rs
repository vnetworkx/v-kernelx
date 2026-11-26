use crate::state::NetworkLedgerState;
use std::collections::BTreeSet;
use vnetwork_types::*;

pub fn issue_participant_challenge(
    state: &mut NetworkLedgerState,
    timestamp_ms: u64,
) -> ParticipantChallenge {
    let nonce_seed = format!(
        "{}:{}:{}",
        state.network_id,
        state.challenges.len() + 1,
        timestamp_ms
    );
    let nonce = blake3_hex(nonce_seed.as_bytes());
    let challenge_id = format!("chl_{}", &nonce[..20]);
    let challenge = ParticipantChallenge {
        challenge_id: challenge_id.clone(),
        network_id: state.network_id.clone(),
        nonce,
        issued_at_ms: timestamp_ms,
        expires_at_ms: timestamp_ms.saturating_add(300_000),
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

fn grantor_can_delegate_level(
    state: &NetworkLedgerState,
    grantor_pubkey: &str,
    level: ParticipationLevel,
    target_id: Option<&str>,
    now_ms: u64,
) -> bool {
    if grantor_pubkey.trim().is_empty() {
        return false;
    }
    if state
        .validators
        .iter()
        .any(|v| v.active && v.validator_pubkey_hex == grantor_pubkey)
    {
        return true;
    }
    match level {
        ParticipationLevel::Network => true,
        ParticipationLevel::Space => state
            .participants
            .values()
            .any(|p| {
                p.public_key_hex == grantor_pubkey
                    && p.status == ParticipationStatus::Active
                    && p.scope.has_active_scope(ParticipationLevel::Space, target_id, now_ms)
            }),
        ParticipationLevel::Region => state.spaces.values().any(|s| {
            s.owner_pubkey == grantor_pubkey
                && target_id.map_or(false, |tid| tid == s.space_id)
        }),
        ParticipationLevel::Wallet => state.regions.values().any(|r| {
            r.creator_pubkey == grantor_pubkey
                && target_id.map_or(false, |tid| tid == r.region_id)
        }) || state.wallets.values().any(|w| {
            w.owner_pubkey == grantor_pubkey
                && target_id.map_or(false, |tid| tid == w.wallet_id)
        }),
        ParticipationLevel::Token => state.wallets.values().any(|w| {
            w.owner_pubkey == grantor_pubkey
                && target_id.map_or(false, |tid| tid == w.wallet_id)
        }),
    }
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

    // Open join grants Network scope ONLY; any elevated scope requires an explicit verified ScopeAuthorization.
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
            if !grantor_can_delegate_level(
                state,
                &auth.grantor_pubkey,
                lvl,
                auth.target_id.as_deref(),
                timestamp_ms,
            ) {
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

    state.logical_clock += 1;
    let sequence = (state.events.len() as u64) + 1;
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
            "actor `{actor_pubkey}` is not authorized to grant `{}` scope",
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

    state.logical_clock += 1;
    let sequence = (state.events.len() as u64) + 1;
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
            "actor `{actor_pubkey}` is not authorized to revoke `{}` scope",
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
    for g in &mut participant.scope.grants {
        if g.level == level && !g.revoked {
            let target_matches = match target_id {
                None => true,
                Some(t) => g.target_id.as_deref() == Some(t) || g.target_id.is_none(),
            };
            if target_matches {
                g.revoked = true;
                matched = true;
            }
        }
    }
    if !matched {
        return Err(VNetworkError::NotFound(format!(
            "no active `{}` grant found for participant `{}`",
            level.as_str(),
            participant.participant_id
        )));
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

    state.logical_clock += 1;
    let sequence = (state.events.len() as u64) + 1;
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
    // Active genesis/epoch validators hold bootstrap authority on the network
    if state
        .validators
        .iter()
        .any(|v| v.active && v.validator_pubkey_hex == actor_pubkey)
    {
        return Ok(());
    }

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
