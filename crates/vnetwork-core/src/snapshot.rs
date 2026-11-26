use crate::state::{NetworkLedgerState, StateSnapshot};
use vnetwork_types::*;

pub fn create_snapshot(state: &mut NetworkLedgerState, timestamp_ms: u64) -> VResult<StateSnapshot> {
    let state_root = state.compute_state_root()?;
    let replay_hash = state.compute_replay_hash();
    let seed = format!(
        "{}:{}:{}:{}",
        state.network_id, state.height, state.logical_clock, state_root
    );
    let snapshot_id = format!("snap_{}", &blake3_hex(seed.as_bytes())[..20]);
    let snap = StateSnapshot {
        snapshot_id,
        height: state.height,
        logical_clock: state.logical_clock,
        state_root,
        replay_hash,
        event_count: state.events.len(),
        created_at_ms: timestamp_ms,
    };
    state.snapshots.push(snap.clone());
    Ok(snap)
}
