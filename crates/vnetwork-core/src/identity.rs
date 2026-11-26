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

    // Never allow a join request to self-promote directly to unrestricted ValidatorNode
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

    let mut levels = BTreeSet::new();
    levels.insert(ParticipationLevel::Network);
    for s in &req.requested_scopes {
        levels.insert(*s);
    }

    let grants = levels
        .iter()
        .map(|lvl| ScopeGrant {
            level: *lvl,
            target_id: None,
            granted_at_ms: timestamp_ms,
        })
        .collect();

    let scope = ParticipationScope {
        levels: levels.clone(),
        grants,
        validator_eligible: false,
    };

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

pub fn require_participant_scope(
    state: &NetworkLedgerState,
    actor_pubkey: &str,
    required_level: ParticipationLevel,
) -> VResult<()> {
    // Genesis/validator operators or active registered participants with matching scope
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
        if !p.scope.has_level(required_level) {
            return Err(VNetworkError::Authorization(format!(
                "participant `{}` lacks required `{}` scope",
                p.participant_id,
                required_level.as_str()
            )));
        }
        return Ok(());
    }
    // Also allow if actor owns an already-registered wallet authorized key
    if state
        .wallets
        .values()
        .any(|w| w.is_authorized_signer(actor_pubkey))
    {
        if matches!(required_level, ParticipationLevel::Wallet | ParticipationLevel::Token) {
            return Ok(());
        }
    }
    Err(VNetworkError::Authorization(format!(
        "actor `{actor_pubkey}` is not an active joined participant with `{}` scope",
        required_level.as_str()
    )))
}
