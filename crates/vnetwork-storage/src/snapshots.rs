use crate::transactions::atomic_write_json;
use std::fs;
use std::path::Path;
use vnetwork_core::snapshot::CertifiedCheckpoint;
use vnetwork_core::state::{GenesisConfig, NetworkLedgerState};
use vnetwork_types::*;

pub const CERTIFIED_CHECKPOINT_FILE: &str = "certified.checkpoint.json";
pub const LEGACY_UNCERTIFIED_SNAPSHOT_FILE: &str = "state.snapshot.json";

pub fn save_certified_checkpoint(data_dir: &Path, checkpoint: &CertifiedCheckpoint) -> VResult<()> {
    if checkpoint.checkpoint_version != CHECKPOINT_VERSION || checkpoint.height == 0 {
        return Err(VNetworkError::Storage(
            "refusing to persist invalid or height-0 certified checkpoint".to_string(),
        ));
    }
    atomic_write_json(&data_dir.join(CERTIFIED_CHECKPOINT_FILE), checkpoint)
}

pub fn save_certified_checkpoint_from_state(
    data_dir: &Path,
    state: &NetworkLedgerState,
    latest_qc: &QuorumCertificate,
    proposal_digest: &str,
    parent_commitment: &str,
    timestamp_ms: u64,
) -> VResult<CertifiedCheckpoint> {
    let ckpt = CertifiedCheckpoint::build(
        state,
        latest_qc,
        proposal_digest,
        parent_commitment,
        timestamp_ms,
    )?;
    save_certified_checkpoint(data_dir, &ckpt)?;
    Ok(ckpt)
}

pub fn load_certified_checkpoint(
    data_dir: &Path,
    expected_genesis: &GenesisConfig,
) -> VResult<Option<CertifiedCheckpoint>> {
    let legacy_path = data_dir.join(LEGACY_UNCERTIFIED_SNAPSHOT_FILE);
    let cert_path = data_dir.join(CERTIFIED_CHECKPOINT_FILE);

    if legacy_path.exists() && !cert_path.exists() {
        return Err(VNetworkError::Storage(
            "uncertified legacy `state.snapshot.json` present without `certified.checkpoint.json`; failing closed"
                .to_string(),
        ));
    }
    if !cert_path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(&cert_path)
        .map_err(|e| VNetworkError::Storage(format!("read {CERTIFIED_CHECKPOINT_FILE} failed: {e}")))?;
    let ckpt: CertifiedCheckpoint = serde_json::from_str(&raw)
        .map_err(|e| VNetworkError::Storage(format!("parse {CERTIFIED_CHECKPOINT_FILE} failed: {e}")))?;
    ckpt.verify(expected_genesis)?;
    Ok(Some(ckpt))
}
