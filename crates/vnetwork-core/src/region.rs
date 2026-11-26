use crate::hierarchy::verify_space_exists;
use crate::identity::require_participant_scope_at;
use crate::state::NetworkLedgerState;
use std::collections::BTreeMap;
use vnetwork_types::*;

#[allow(clippy::too_many_arguments)]
pub fn apply_create_region(
    state: &mut NetworkLedgerState,
    space_ref: &str,
    name: &str,
    prefix: Option<String>,
    title: Option<String>,
    visibility: Visibility,
    section: u64,
    ghost: bool,
    actor_pubkey: &str,
    metadata: BTreeMap<String, String>,
    timestamp_ms: u64,
) -> VResult<(RegionEntity, LedgerEvent)> {
    let parent_space = verify_space_exists(state, space_ref)?.clone();
    let is_parent_owner = parent_space.owner_pubkey == actor_pubkey
        && require_participant_scope_at(
            state,
            actor_pubkey,
            ParticipationLevel::Space,
            Some(&parent_space.space_id),
            timestamp_ms,
        )
        .is_ok();
    if !is_parent_owner {
        require_participant_scope_at(
            state,
            actor_pubkey,
            ParticipationLevel::Region,
            Some(&parent_space.space_id),
            timestamp_ms,
        )?;
    }

    if parent_space.visibility == Visibility::Private && parent_space.owner_pubkey != actor_pubkey {
        return Err(VNetworkError::Authorization(format!(
            "cannot create region in private space `{}` owned by another key",
            parent_space.name
        )));
    }

    let clean_name = name.trim();
    if clean_name.is_empty() {
        return Err(VNetworkError::Validation("region name cannot be empty".to_string()));
    }
    if clean_name.eq_ignore_ascii_case("ATLAS") && !state.profile.allows_dev_atlas_fixture() {
        return Err(VNetworkError::ProfileMismatch(
            "development ATLAS fixture cannot be created in PRODUCTION profile".to_string(),
        ));
    }

    let norm_prefix = prefix
        .as_ref()
        .map(|p| p.trim().to_ascii_uppercase())
        .filter(|p| !p.is_empty());

    if state.regions.values().any(|r| {
        r.space_id == parent_space.space_id
            && r.name.eq_ignore_ascii_case(clean_name)
            && r.prefix == norm_prefix
    }) {
        return Err(VNetworkError::AlreadyExists(format!(
            "region `{clean_name}` already exists in space `{}`",
            parent_space.name
        )));
    }

    let region_id = derive_region_id(&parent_space.space_id, clean_name, norm_prefix.as_deref());
    let region = RegionEntity {
        region_id: region_id.clone(),
        space_id: parent_space.space_id.clone(),
        name: clean_name.to_string(),
        prefix: norm_prefix,
        title: title.filter(|t| !t.trim().is_empty()),
        visibility,
        section: section.max(1),
        ghost,
        auth_ratio_bps: 1_000,
        creator_pubkey: actor_pubkey.to_string(),
        created_at_ms: timestamp_ms,
        version: 1,
        metadata,
    };

    state.regions.insert(region_id.clone(), region.clone());
    state.logical_clock = state
        .logical_clock
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
    let sequence = (state.events.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
    let parents = state.latest_event_hash().into_iter().collect();
    let after_hash = blake3_hex(&canonical_json_bytes(&region)?);
    let event = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "region",
        &region_id,
        if ghost { "GHOST_REGION_CREATE" } else { "REGION_CREATE" },
        actor_pubkey,
        state.logical_clock,
        timestamp_ms,
        serde_json::to_value(&region).map_err(|e| VNetworkError::Serialization(e.to_string()))?,
        "",
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((region, event))
}
