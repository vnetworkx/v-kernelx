use crate::hierarchy::{verify_region_exists, verify_wallet_exists};
use crate::identity::require_participant_scope;
use crate::state::NetworkLedgerState;
use std::collections::BTreeMap;
use vnetwork_types::*;

pub fn apply_create_wallet(
    state: &mut NetworkLedgerState,
    region_ref: &str,
    name: &str,
    ghost: bool,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(WalletEntity, LedgerEvent)> {
    require_participant_scope(state, actor_pubkey, ParticipationLevel::Wallet)?;

    let parent_region = verify_region_exists(state, region_ref)?.clone();
    if parent_region.visibility == Visibility::Private && parent_region.creator_pubkey != actor_pubkey {
        return Err(VNetworkError::Authorization(format!(
            "cannot create wallet in private region `{}`",
            parent_region.name
        )));
    }

    let clean_name = name.trim();
    if clean_name.is_empty() {
        return Err(VNetworkError::Validation("wallet name cannot be empty".to_string()));
    }

    let wallet_id = derive_named_wallet_id(&parent_region.region_id, clean_name, actor_pubkey);
    if state.wallets.contains_key(&wallet_id)
        || state
            .wallets
            .values()
            .any(|w| w.region_id == parent_region.region_id && w.name.eq_ignore_ascii_case(clean_name))
    {
        return Err(VNetworkError::AlreadyExists(format!(
            "wallet `{clean_name}` already exists in region `{}`",
            parent_region.name
        )));
    }

    let mut authorized_keys = BTreeMap::new();
    authorized_keys.insert(
        actor_pubkey.to_string(),
        WalletKeyBinding {
            public_key_hex: actor_pubkey.to_string(),
            role: "owner".to_string(),
            added_by: actor_pubkey.to_string(),
            added_at_ms: timestamp_ms,
        },
    );

    let wallet = WalletEntity {
        wallet_id: wallet_id.clone(),
        name: clean_name.to_string(),
        region_id: parent_region.region_id.clone(),
        space_id: parent_region.space_id.clone(),
        ghost,
        owner_pubkey: actor_pubkey.to_string(),
        authorized_keys,
        created_at_ms: timestamp_ms,
        version: 1,
    };

    state.wallets.insert(wallet_id.clone(), wallet.clone());
    state.logical_clock += 1;
    let sequence = (state.events.len() as u64) + 1;
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
        serde_json::to_value(&wallet).unwrap_or_default(),
        "",
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((wallet, event))
}

pub fn apply_authorize_wallet_key(
    state: &mut NetworkLedgerState,
    wallet_ref: &str,
    new_pubkey: &str,
    role: &str,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(WalletEntity, LedgerEvent)> {
    let mut wallet = verify_wallet_exists(state, wallet_ref)?.clone();
    if !wallet.is_authorized_signer(actor_pubkey) {
        return Err(VNetworkError::Authorization(format!(
            "actor `{actor_pubkey}` is not authorized to manage keys for wallet `{}`",
            wallet.wallet_id
        )));
    }
    let pk_bytes = hex::decode(new_pubkey.trim())
        .map_err(|_| VNetworkError::Validation("authorized key must be 32-byte hex Ed25519 pubkey".to_string()))?;
    if pk_bytes.len() != 32 {
        return Err(VNetworkError::Validation(
            "authorized key must be 32 bytes".to_string(),
        ));
    }

    let before_hash = blake3_hex(&canonical_json_bytes(&wallet)?);
    wallet.authorized_keys.insert(
        new_pubkey.trim().to_string(),
        WalletKeyBinding {
            public_key_hex: new_pubkey.trim().to_string(),
            role: if role.trim().is_empty() {
                "co-signer".to_string()
            } else {
                role.trim().to_string()
            },
            added_by: actor_pubkey.to_string(),
            added_at_ms: timestamp_ms,
        },
    );
    wallet.version += 1;
    state.wallets.insert(wallet.wallet_id.clone(), wallet.clone());

    state.logical_clock += 1;
    let sequence = (state.events.len() as u64) + 1;
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
        serde_json::to_value(&wallet).unwrap_or_default(),
        before_hash,
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((wallet, event))
}
