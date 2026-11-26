use crate::transactions::atomic_write_json;
use std::fs;
use std::path::Path;
use vnetwork_core::state::NetworkLedgerState;
use vnetwork_types::*;

pub fn save_full_state_snapshot(data_dir: &Path, state: &NetworkLedgerState) -> VResult<()> {
    atomic_write_json(&data_dir.join("state.snapshot.json"), state)
}

pub fn load_full_state_snapshot(data_dir: &Path) -> VResult<Option<NetworkLedgerState>> {
    let path = data_dir.join("state.snapshot.json");
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)
        .map_err(|e| VNetworkError::Storage(format!("read state.snapshot.json failed: {e}")))?;
    let state: NetworkLedgerState = serde_json::from_str(&raw)
        .map_err(|e| VNetworkError::Storage(format!("parse state.snapshot.json failed: {e}")))?;
    Ok(Some(state))
}
