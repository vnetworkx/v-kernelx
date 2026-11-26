use crate::identity::require_participant_scope;
use crate::state::NetworkLedgerState;
use std::collections::BTreeMap;
use vnetwork_types::*;

pub fn apply_create_space(
    state: &mut NetworkLedgerState,
    name: &str,
    visibility: Visibility,
    ghost: bool,
    actor_pubkey: &str,
    metadata: BTreeMap<String, String>,
    timestamp_ms: u64,
) -> VResult<(SpaceEntity, LedgerEvent)> {
    require_participant_scope(state, actor_pubkey, ParticipationLevel::Space)?;

    let clean_name = name.trim();
    if clean_name.is_empty() {
        return Err(VNetworkError::Validation("space name cannot be empty".to_string()));
    }
    if state
        .spaces
        .values()
        .any(|s| s.name.eq_ignore_ascii_case(clean_name))
    {
        return Err(VNetworkError::AlreadyExists(format!(
            "space `{clean_name}` already exists"
        )));
    }

    let space_id = derive_space_id(clean_name, actor_pubkey);
    let space = SpaceEntity {
        space_id: space_id.clone(),
        name: clean_name.to_string(),
        visibility,
        ghost,
        owner_pubkey: actor_pubkey.to_string(),
        created_at_ms: timestamp_ms,
        version: 1,
        metadata,
    };

    state.spaces.insert(space_id.clone(), space.clone());
    state.logical_clock += 1;
    let sequence = (state.events.len() as u64) + 1;
    let parents = state.latest_event_hash().into_iter().collect();
    let after_hash = blake3_hex(&canonical_json_bytes(&space)?);
    let event = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "space",
        &space_id,
        if ghost { "GHOST_SPACE_CREATE" } else { "SPACE_CREATE" },
        actor_pubkey,
        state.logical_clock,
        timestamp_ms,
        serde_json::to_value(&space).unwrap_or_default(),
        "",
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((space, event))
}
