use crate::hierarchy::{verify_region_exists, verify_wallet_exists};
use crate::identity::require_participant_scope_at;
use crate::state::NetworkLedgerState;
use std::collections::BTreeMap;
use vnetwork_types::*;

// The explicit parameters mirror the canonical signed payload fields.
#[allow(clippy::too_many_arguments)]
pub fn canonical_wallet_pop_bytes(
    network_id: &str,
    wallet_id: &str,
    participant_identity: &str,
    authorized_pubkey: &str,
    purpose: &str,
    nonce: &str,
    expires_at_ms: Option<u64>,
    protocol_version: &str,
) -> VResult<Vec<u8>> {
    let obj = serde_json::json!({
        "authorized_pubkey": authorized_pubkey,
        "expires_at_ms": expires_at_ms,
        "network_id": network_id,
        "nonce": nonce,
        "participant_identity": participant_identity,
        "protocol_version": protocol_version,
        "purpose": purpose,
        "wallet_id": wallet_id,
    });
    canonical_json_bytes(&obj)
}

#[allow(clippy::too_many_arguments)]
pub fn apply_create_wallet(
    state: &mut NetworkLedgerState,
    region_ref: &str,
    name: &str,
    ghost: bool,
    approval_threshold: Option<u16>,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(WalletEntity, LedgerEvent)> {
    let (parent_region_id, parent_space_id, parent_label, id_seed) =
        if ghost && region_ref.trim().is_empty() {
            require_participant_scope_at(
                state,
                actor_pubkey,
                ParticipationLevel::Network,
                None,
                timestamp_ms,
            )?;
            (
                String::new(),
                String::new(),
                "NETWORK".to_string(),
                "__network_ghost__".to_string(),
            )
        } else {
            let parent_region = verify_region_exists(state, region_ref)?.clone();
            let is_region_creator = parent_region.creator_pubkey == actor_pubkey
                && require_participant_scope_at(
                    state,
                    actor_pubkey,
                    ParticipationLevel::Network,
                    None,
                    timestamp_ms,
                )
                .is_ok();
            if !is_region_creator {
                require_participant_scope_at(
                    state,
                    actor_pubkey,
                    ParticipationLevel::Wallet,
                    Some(&parent_region.region_id),
                    timestamp_ms,
                )?;
            }

            if parent_region.visibility == Visibility::Private
                && parent_region.creator_pubkey != actor_pubkey
            {
                return Err(VNetworkError::Authorization(format!(
                    "cannot create wallet in private region `{}`",
                    parent_region.name
                )));
            }
            let r_id = parent_region.region_id.clone();
            (
                parent_region.region_id,
                parent_region.space_id,
                parent_region.name,
                r_id,
            )
        };

    let clean_name = name.trim();
    if clean_name.is_empty() {
        return Err(VNetworkError::Validation("wallet name cannot be empty".to_string()));
    }

    let threshold = approval_threshold.unwrap_or(1);
    if threshold == 0 {
        return Err(VNetworkError::Validation(
            "wallet approval_threshold must be >= 1".to_string(),
        ));
    }

    let wallet_id = derive_named_wallet_id(&id_seed, clean_name, actor_pubkey);
    if state.wallets.contains_key(&wallet_id)
        || state
            .wallets
            .values()
            .any(|w| w.region_id == parent_region_id && w.name.eq_ignore_ascii_case(clean_name))
    {
        return Err(VNetworkError::AlreadyExists(format!(
            "wallet `{clean_name}` already exists in `{parent_label}`",
        )));
    }

    let mut authorized_keys = BTreeMap::new();
    authorized_keys.insert(
        actor_pubkey.to_string(),
        WalletKeyBinding {
            public_key_hex: actor_pubkey.to_string(),
            role: "owner".to_string(),
            permissions: WalletPermission::for_role("owner"),
            allowed_token_ids: Vec::new(),
            max_amount_per_op: None,
            expires_at_ms: None,
            revoked: false,
            revoked_at_ms: None,
            pop_nonce: None,
            added_by: actor_pubkey.to_string(),
            added_at_ms: timestamp_ms,
        },
    );

    let wallet = WalletEntity {
        wallet_id: wallet_id.clone(),
        name: clean_name.to_string(),
        region_id: parent_region_id,
        space_id: parent_space_id,
        ghost,
        owner_pubkey: actor_pubkey.to_string(),
        authorized_keys,
        approval_threshold: threshold,
        receive_policy: WalletReceivePolicy::Open,
        created_at_ms: timestamp_ms,
        version: 1,
    };

    state.wallets.insert(wallet_id.clone(), wallet.clone());
    state.logical_clock = state
        .logical_clock
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
    let sequence = (state.events.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
    let parents = state.latest_event_hash().into_iter().collect();
    let after_hash = blake3_hex(&canonical_json_bytes(&wallet)?);
    let event = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "wallet",
        &wallet_id,
        if ghost { "GHOST_WALLET_CREATE" } else { "WALLET_CREATE" },
        actor_pubkey,
        state.logical_clock,
        timestamp_ms,
        serde_json::to_value(&wallet).map_err(|e| VNetworkError::Serialization(e.to_string()))?,
        "",
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((wallet, event))
}

#[allow(clippy::too_many_arguments)]
pub fn apply_authorize_wallet_key(
    state: &mut NetworkLedgerState,
    wallet_ref: &str,
    new_pubkey: &str,
    role: &str,
    permissions: &[String],
    allowed_token_ids: &[String],
    max_amount_per_op: Option<u128>,
    expires_at_ms: Option<u64>,
    pop_nonce: Option<&str>,
    pop_signature: Option<&str>,
    participant_identity: Option<&str>,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(WalletEntity, LedgerEvent)> {
    let mut wallet = verify_wallet_exists(state, wallet_ref)?.clone();
    wallet.verify_permission(
        actor_pubkey,
        WalletPermission::ManageKeys,
        None,
        None,
        timestamp_ms,
    )?;

    let clean_pk = new_pubkey.trim();
    let pk_bytes = hex::decode(clean_pk).map_err(|_| {
        VNetworkError::Validation("authorized key must be 32-byte hex Ed25519 pubkey".to_string())
    })?;
    if pk_bytes.len() != 32 {
        return Err(VNetworkError::Validation(
            "authorized key must be 32 bytes".to_string(),
        ));
    }

    if let Some(exp) = expires_at_ms {
        if timestamp_ms >= exp {
            return Err(VNetworkError::Validation(
                "authorized key expires_at_ms must be in the future".to_string(),
            ));
        }
    }

    // Proof of Possession (PoP) signature by the newly added key over domain-separated payload
    let nonce = pop_nonce
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            VNetworkError::Authorization(
                "wallet key authorization requires a non-empty pop_nonce".to_string(),
            )
        })?;
    let sig = pop_signature
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            VNetworkError::Authorization(
                "wallet key authorization requires a proof-of-possession signature (pop_signature)"
                    .to_string(),
            )
        })?;

    let nonce_key = format!("{}::{clean_pk}::{nonce}", wallet.wallet_id);
    if state.used_wallet_pop_nonces.contains(&nonce_key) {
        return Err(VNetworkError::ReplayRejected(format!(
            "wallet PoP nonce `{nonce}` has already been consumed"
        )));
    }

    let p_ident = participant_identity
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| derive_participant_id(actor_pubkey));

    let pop_bytes = canonical_wallet_pop_bytes(
        &state.network_id,
        &wallet.wallet_id,
        &p_ident,
        clean_pk,
        "wallet_key_authorization",
        nonce,
        expires_at_ms,
        &state.protocol_version,
    )?;
    verify_ed25519(clean_pk, &pop_bytes, sig)?;

    let clean_role = if role.trim().is_empty() {
        "signer"
    } else {
        role.trim()
    };
    let resolved_perms = if !permissions.is_empty() {
        let mut parsed = Vec::with_capacity(permissions.len());
        for p in permissions {
            let perm = WalletPermission::parse(p).ok_or_else(|| {
                VNetworkError::Validation(format!("unknown wallet permission `{p}`"))
            })?;
            parsed.push(perm);
        }
        parsed
    } else {
        let by_role = WalletPermission::for_role(clean_role);
        if by_role.is_empty() {
            return Err(VNetworkError::Validation(format!(
                "unknown wallet role `{clean_role}` with no explicit permissions"
            )));
        }
        by_role
    };

    let before_hash = blake3_hex(&canonical_json_bytes(&wallet)?);
    state.used_wallet_pop_nonces.insert(nonce_key);
    wallet.authorized_keys.insert(
        clean_pk.to_string(),
        WalletKeyBinding {
            public_key_hex: clean_pk.to_string(),
            role: clean_role.to_string(),
            permissions: resolved_perms,
            allowed_token_ids: allowed_token_ids.to_vec(),
            max_amount_per_op,
            expires_at_ms,
            revoked: false,
            revoked_at_ms: None,
            pop_nonce: Some(nonce.to_string()),
            added_by: actor_pubkey.to_string(),
            added_at_ms: timestamp_ms,
        },
    );
    wallet.version = wallet
        .version
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("wallet version overflow".to_string()))?;
    state.wallets.insert(wallet.wallet_id.clone(), wallet.clone());

    state.logical_clock = state
        .logical_clock
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
    let sequence = (state.events.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
    let parents = state.latest_event_hash().into_iter().collect();
    let after_hash = blake3_hex(&canonical_json_bytes(&wallet)?);
    let event = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "wallet",
        &wallet.wallet_id,
        "WALLET_KEY_AUTHORIZE",
        actor_pubkey,
        state.logical_clock,
        timestamp_ms,
        serde_json::to_value(&wallet).map_err(|e| VNetworkError::Serialization(e.to_string()))?,
        before_hash,
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((wallet, event))
}

pub fn apply_revoke_wallet_key(
    state: &mut NetworkLedgerState,
    wallet_ref: &str,
    target_pubkey: &str,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(WalletEntity, LedgerEvent)> {
    let mut wallet = verify_wallet_exists(state, wallet_ref)?.clone();
    wallet.verify_permission(
        actor_pubkey,
        WalletPermission::ManageKeys,
        None,
        None,
        timestamp_ms,
    )?;

    let clean_target = target_pubkey.trim();
    if clean_target == wallet.owner_pubkey {
        return Err(VNetworkError::Authorization(
            "cannot revoke owner key directly; use key rotation".to_string(),
        ));
    }
    let binding = wallet.authorized_keys.get_mut(clean_target).ok_or_else(|| {
        VNetworkError::NotFound(format!(
            "key `{clean_target}` is not bound on wallet `{}`",
            wallet.wallet_id
        ))
    })?;
    if binding.revoked {
        return Err(VNetworkError::Validation(format!(
            "key `{clean_target}` is already revoked"
        )));
    }

    let before_hash = blake3_hex(&canonical_json_bytes(&wallet)?);
    if let Some(b) = wallet.authorized_keys.get_mut(clean_target) {
        b.revoked = true;
        b.revoked_at_ms = Some(timestamp_ms);
    }
    wallet.version = wallet
        .version
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("wallet version overflow".to_string()))?;
    state.wallets.insert(wallet.wallet_id.clone(), wallet.clone());

    state.logical_clock = state
        .logical_clock
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
    let sequence = (state.events.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
    let parents = state.latest_event_hash().into_iter().collect();
    let after_hash = blake3_hex(&canonical_json_bytes(&wallet)?);
    let event = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "wallet",
        &wallet.wallet_id,
        "WALLET_KEY_REVOKE",
        actor_pubkey,
        state.logical_clock,
        timestamp_ms,
        serde_json::to_value(&wallet).map_err(|e| VNetworkError::Serialization(e.to_string()))?,
        before_hash,
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((wallet, event))
}

#[allow(clippy::too_many_arguments)]
pub fn apply_rotate_wallet_key(
    state: &mut NetworkLedgerState,
    wallet_ref: &str,
    old_pubkey: &str,
    new_pubkey: &str,
    role_override: Option<&str>,
    pop_nonce: Option<&str>,
    pop_signature: Option<&str>,
    participant_identity: Option<&str>,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(WalletEntity, LedgerEvent)> {
    let mut wallet = verify_wallet_exists(state, wallet_ref)?.clone();
    wallet.verify_permission(
        actor_pubkey,
        WalletPermission::ManageKeys,
        None,
        None,
        timestamp_ms,
    )?;

    let clean_old = old_pubkey.trim();
    let clean_new = new_pubkey.trim();
    if clean_old == clean_new {
        return Err(VNetworkError::Validation(
            "old_pubkey and new_pubkey must differ".to_string(),
        ));
    }
    let pk_bytes = hex::decode(clean_new).map_err(|_| {
        VNetworkError::Validation("new_pubkey must be 32-byte hex Ed25519 pubkey".to_string())
    })?;
    if pk_bytes.len() != 32 {
        return Err(VNetworkError::Validation(
            "new_pubkey must be 32 bytes".to_string(),
        ));
    }

    if clean_old == wallet.owner_pubkey && actor_pubkey != wallet.owner_pubkey {
        return Err(VNetworkError::Authorization(
            "only current wallet owner can rotate the owner key".to_string(),
        ));
    }

    let old_binding = wallet.authorized_keys.get(clean_old).cloned().ok_or_else(|| {
        VNetworkError::NotFound(format!("old key `{clean_old}` not found on wallet"))
    })?;
    if old_binding.revoked {
        return Err(VNetworkError::Authorization(format!(
            "cannot rotate already revoked key `{clean_old}`"
        )));
    }

    let nonce = pop_nonce
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            VNetworkError::Authorization(
                "wallet key rotation requires a non-empty pop_nonce".to_string(),
            )
        })?;
    let sig = pop_signature
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            VNetworkError::Authorization(
                "wallet key rotation requires pop_signature by new_pubkey".to_string(),
            )
        })?;
    let nonce_key = format!("{}::{clean_new}::{nonce}", wallet.wallet_id);
    if state.used_wallet_pop_nonces.contains(&nonce_key) {
        return Err(VNetworkError::ReplayRejected(format!(
            "wallet PoP nonce `{nonce}` has already been consumed"
        )));
    }

    let p_ident = participant_identity
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| derive_participant_id(actor_pubkey));

    let pop_bytes = canonical_wallet_pop_bytes(
        &state.network_id,
        &wallet.wallet_id,
        &p_ident,
        clean_new,
        "wallet_key_rotation",
        nonce,
        old_binding.expires_at_ms,
        &state.protocol_version,
    )?;
    verify_ed25519(clean_new, &pop_bytes, sig)?;

    let before_hash = blake3_hex(&canonical_json_bytes(&wallet)?);
    state.used_wallet_pop_nonces.insert(nonce_key);

    if let Some(prev) = wallet.authorized_keys.get_mut(clean_old) {
        prev.revoked = true;
        prev.revoked_at_ms = Some(timestamp_ms);
    }

    let new_role = role_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&old_binding.role)
        .to_string();
    let new_perms = if new_role == old_binding.role {
        old_binding.effective_permissions()
    } else {
        let p = WalletPermission::for_role(&new_role);
        if p.is_empty() {
            old_binding.effective_permissions()
        } else {
            p
        }
    };

    if clean_old == wallet.owner_pubkey {
        wallet.owner_pubkey = clean_new.to_string();
    }

    wallet.authorized_keys.insert(
        clean_new.to_string(),
        WalletKeyBinding {
            public_key_hex: clean_new.to_string(),
            role: new_role,
            permissions: new_perms,
            allowed_token_ids: old_binding.allowed_token_ids,
            max_amount_per_op: old_binding.max_amount_per_op,
            expires_at_ms: old_binding.expires_at_ms,
            revoked: false,
            revoked_at_ms: None,
            pop_nonce: Some(nonce.to_string()),
            added_by: actor_pubkey.to_string(),
            added_at_ms: timestamp_ms,
        },
    );
    wallet.version = wallet
        .version
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("wallet version overflow".to_string()))?;
    state.wallets.insert(wallet.wallet_id.clone(), wallet.clone());

    state.logical_clock = state
        .logical_clock
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
    let sequence = (state.events.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
    let parents = state.latest_event_hash().into_iter().collect();
    let after_hash = blake3_hex(&canonical_json_bytes(&wallet)?);
    let event = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "wallet",
        &wallet.wallet_id,
        "WALLET_KEY_ROTATE",
        actor_pubkey,
        state.logical_clock,
        timestamp_ms,
        serde_json::to_value(&wallet).map_err(|e| VNetworkError::Serialization(e.to_string()))?,
        before_hash,
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((wallet, event))
}

pub fn apply_update_wallet_receive_policy(
    state: &mut NetworkLedgerState,
    wallet_ref: &str,
    mode: &str,
    allowed_senders: &[String],
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(WalletEntity, LedgerEvent)> {
    let mut wallet = verify_wallet_exists(state, wallet_ref)?.clone();
    wallet.verify_permission(
        actor_pubkey,
        WalletPermission::ManageKeys,
        None,
        None,
        timestamp_ms,
    )?;

    let norm_mode = mode.trim().to_ascii_uppercase();
    let new_policy = match norm_mode.as_str() {
        "OPEN" => WalletReceivePolicy::Open,
        "FROZEN" => WalletReceivePolicy::Frozen,
        "RESTRICTED" => {
            let mut set = std::collections::BTreeSet::new();
            for s in allowed_senders {
                let clean = s.trim();
                if !clean.is_empty() {
                    set.insert(clean.to_string());
                }
            }
            if set.is_empty() {
                return Err(VNetworkError::Validation(
                    "RESTRICTED wallet receive policy requires at least one allowed sender"
                        .to_string(),
                ));
            }
            WalletReceivePolicy::Restricted {
                allowed_senders: set,
            }
        }
        other => {
            return Err(VNetworkError::Validation(format!(
                "unsupported wallet receive policy mode `{other}` (expected OPEN, RESTRICTED, or FROZEN)"
            )));
        }
    };

    let before_hash = blake3_hex(&canonical_json_bytes(&wallet)?);
    wallet.receive_policy = new_policy;
    wallet.version = wallet
        .version
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("wallet version overflow".to_string()))?;
    state.wallets.insert(wallet.wallet_id.clone(), wallet.clone());

    state.logical_clock = state
        .logical_clock
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
    let sequence = (state.events.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
    let parents = state.latest_event_hash().into_iter().collect();
    let after_hash = blake3_hex(&canonical_json_bytes(&wallet)?);
    let event = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "wallet",
        &wallet.wallet_id,
        "WALLET_RECEIVE_POLICY_UPDATE",
        actor_pubkey,
        state.logical_clock,
        timestamp_ms,
        serde_json::to_value(&wallet).map_err(|e| VNetworkError::Serialization(e.to_string()))?,
        before_hash,
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((wallet, event))
}
