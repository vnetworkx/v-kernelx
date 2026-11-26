use vnetwork_core::engine::ProtocolEngine;
use vnetwork_types::*;

pub fn replica_summary(engine: &ProtocolEngine) -> VResult<serde_json::Value> {
    Ok(serde_json::json!({
        "network_id": engine.state.network_id,
        "height": engine.state.height,
        "logical_clock": engine.state.logical_clock,
        "event_count": engine.state.events.len(),
        "state_root": engine.state.compute_state_root()?,
        "replay_hash": engine.state.compute_replay_hash(),
    }))
}
