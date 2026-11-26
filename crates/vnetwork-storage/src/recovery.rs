use crate::events::EventWal;
use crate::indexes::persist_entity_index;
use crate::snapshots::{load_full_state_snapshot, save_full_state_snapshot};
use crate::transactions::{
    save_transactions_and_programs, CommittedCommitMarker, ConsensusWal, PendingCommitRecord,
};
use std::fs;
use std::path::{Path, PathBuf};
use vnetwork_core::consensus_gate::commit_verified_proposal;
use vnetwork_core::state::{GenesisConfig, NetworkLedgerState, TransactionReceipt};
use vnetwork_types::*;

#[derive(Debug, Clone)]
pub struct RecoveryReport {
    pub recovered_from_snapshot: bool,
    pub rolled_back_uncommitted: usize,
    pub wal_events_verified: usize,
    pub proposals_replayed: usize,
    pub final_height: u64,
    pub state_root: String,
}

fn wal_tx_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("wal_tx")
}

pub fn pending_tx_path(data_dir: &Path, height: u64) -> PathBuf {
    wal_tx_dir(data_dir).join(format!("tx_{height:012}_pending.json"))
}

pub fn committed_tx_path(data_dir: &Path, height: u64) -> PathBuf {
    wal_tx_dir(data_dir).join(format!("tx_{height:012}_committed.marker"))
}

pub fn recover_state_from_disk(
    data_dir: &Path,
    expected_genesis: &GenesisConfig,
) -> VResult<(NetworkLedgerState, RecoveryReport)> {
    let genesis_path = data_dir.join("genesis.json");
    if genesis_path.exists() {
        let raw = fs::read_to_string(&genesis_path)
            .map_err(|e| VNetworkError::Storage(e.to_string()))?;
        let stored: GenesisConfig =
            serde_json::from_str(&raw).map_err(|e| VNetworkError::Storage(e.to_string()))?;
        let stored_hash = stored.commitment_hash()?;
        let expected_hash = expected_genesis.commitment_hash()?;
        if stored_hash != expected_hash {
            return Err(VNetworkError::ProfileMismatch(format!(
                "persisted storage genesis commitment `{stored_hash}` ({}, {}) != node genesis `{expected_hash}` ({}, {})",
                stored.network_id,
                stored.profile.as_str(),
                expected_genesis.network_id,
                expected_genesis.profile.as_str()
            )));
        }
    }

    // 1. Inspect incomplete WAL transactions before trusting snapshots or WAL tails
    let tx_dir = wal_tx_dir(data_dir);
    let mut rolled_back_uncommitted = 0usize;
    let mut invalidated_min_height: Option<u64> = None;
    let mut rollback_event_limit: Option<usize> = None;

    if tx_dir.exists() {
        let mut pending_files = Vec::new();
        for entry in fs::read_dir(&tx_dir).map_err(|e| VNetworkError::Storage(e.to_string()))? {
            let path = entry.map_err(|e| VNetworkError::Storage(e.to_string()))?.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.ends_with("_pending.json") {
                    pending_files.push(path);
                }
            }
        }
        pending_files.sort();
        for p_path in pending_files {
            let raw = fs::read_to_string(&p_path)
                .map_err(|e| VNetworkError::Storage(format!("read pending tx {:?}: {e}", p_path)))?;
            let pending: PendingCommitRecord = serde_json::from_str(&raw)
                .map_err(|e| VNetworkError::Storage(format!("parse pending tx {:?}: {e}", p_path)))?;
            let c_path = committed_tx_path(data_dir, pending.height);
            if !c_path.exists() {
                // Uncommitted crash: mark for rollback
                rolled_back_uncommitted += 1;
                invalidated_min_height = Some(
                    invalidated_min_height
                        .map_or(pending.height, |m| m.min(pending.height)),
                );
                rollback_event_limit = Some(
                    rollback_event_limit
                        .map_or(pending.prior_event_count, |m| m.min(pending.prior_event_count)),
                );
                fs::remove_file(&p_path).map_err(|e| {
                    VNetworkError::Storage(format!("remove uncommitted pending marker {:?}: {e}", p_path))
                })?;
            }
        }
    }

    let mut committed_proposals = ConsensusWal::new(data_dir).read_all()?;
    let mut wal_events = EventWal::new(data_dir).read_all()?;

    if let Some(min_h) = invalidated_min_height {
        let orig_commits = committed_proposals.len();
        committed_proposals.retain(|c| c.proposal.height < min_h);
        if committed_proposals.len() != orig_commits {
            ConsensusWal::new(data_dir).rewrite_all(&committed_proposals)?;
        }
        if let Some(limit) = rollback_event_limit {
            if wal_events.len() > limit {
                wal_events.truncate(limit);
                EventWal::new(data_dir).rewrite_all(&wal_events)?;
            }
        }
    }

    // 2. Verify consensus_commits WAL and committed markers
    let expected_certified_events: usize =
        committed_proposals.iter().map(|c| c.proposal.events.len()).sum();
    if wal_events.len() > expected_certified_events {
        return Err(VNetworkError::Storage(format!(
            "uncertified WAL event tail detected: {} events in WAL vs {} certified by QuorumCertificates",
            wal_events.len(),
            expected_certified_events
        )));
    }

    if tx_dir.exists() {
        for entry in fs::read_dir(&tx_dir).map_err(|e| VNetworkError::Storage(e.to_string()))? {
            let path = entry.map_err(|e| VNetworkError::Storage(e.to_string()))?.path();
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .map_or(false, |s| s.ends_with("_committed.marker"))
            {
                let raw = fs::read_to_string(&path)
                    .map_err(|e| VNetworkError::Storage(e.to_string()))?;
                let marker: CommittedCommitMarker = serde_json::from_str(&raw)
                    .map_err(|e| VNetworkError::Storage(format!("corrupt committed marker: {e}")))?;
                let found = committed_proposals
                    .iter()
                    .any(|c| c.proposal.height == marker.height && c.certificate.post_state_root == marker.post_state_root);
                if !found {
                    return Err(VNetworkError::Storage(format!(
                        "committed marker at height {} lacks matching consensus WAL entry",
                        marker.height
                    )));
                }
            }
        }
    }

    let snap = load_full_state_snapshot(data_dir)?;
    let expected_genesis_hash = expected_genesis.commitment_hash()?;

    let (mut state, recovered_from_snapshot) = match snap {
        Some(s) if invalidated_min_height.map_or(true, |min_h| s.height < min_h) => {
            if !s.genesis_commitment.is_empty() && s.genesis_commitment != expected_genesis_hash {
                return Err(VNetworkError::Storage(
                    "snapshot genesis_commitment does not match expected genesis".to_string(),
                ));
            }
            let snap_root = s.compute_state_root()?;
            if s.height == 0 {
                let clean_root = NetworkLedgerState::new(expected_genesis).compute_state_root()?;
                if snap_root != clean_root {
                    return Err(VNetworkError::Storage(
                        "height-0 snapshot root does not match clean genesis root".to_string(),
                    ));
                }
            } else {
                let matching_commit = committed_proposals
                    .iter()
                    .find(|c| c.proposal.height == s.height)
                    .ok_or_else(|| {
                        VNetworkError::Storage(format!(
                            "snapshot at height {} has no certified QuorumCertificate in consensus WAL",
                            s.height
                        ))
                    })?;
                if snap_root != matching_commit.proposal.post_state_root {
                    return Err(VNetworkError::Storage(format!(
                        "snapshot tampering detected at height {}: state_root `{snap_root}` != certified QC root `{}`",
                        s.height, matching_commit.proposal.post_state_root
                    )));
                }
            }
            (s, true)
        }
        _ => (NetworkLedgerState::new(expected_genesis), false),
    };

    // 3. Replay all certified commits above current verified state height
    let mut proposals_replayed = 0usize;
    for rec in &committed_proposals {
        if rec.proposal.height > state.height {
            let vals = state.validators.clone();
            commit_verified_proposal(&mut state, &rec.proposal, &rec.certificate, &vals)?;
            proposals_replayed += 1;
        }
    }

    if let Some(last) = committed_proposals.last() {
        let final_root = state.compute_state_root()?;
        if state.height != last.proposal.height || final_root != last.proposal.post_state_root {
            return Err(VNetworkError::Storage(format!(
                "recovered state root `{final_root}` at height {} != last certified root `{}` at height {}",
                state.height, last.proposal.post_state_root, last.proposal.height
            )));
        }
    }

    // Load programs/transactions only for non-tampered metadata supplementation
    let programs_path = data_dir.join("programs.json");
    if programs_path.exists() {
        let raw = fs::read_to_string(&programs_path)
            .map_err(|e| VNetworkError::Storage(e.to_string()))?;
        let programs: std::collections::BTreeMap<String, ProgramSubmission> =
            serde_json::from_str(&raw).map_err(|e| VNetworkError::Storage(e.to_string()))?;
        for (k, v) in programs {
            if v.status == ProgramLifecycleStatus::Committed
                || invalidated_min_height.is_none()
            {
                state.programs.entry(k).or_insert(v);
            }
        }
    }

    let txs_path = data_dir.join("transactions.json");
    if txs_path.exists() {
        let raw = fs::read_to_string(&txs_path)
            .map_err(|e| VNetworkError::Storage(e.to_string()))?;
        let txs: std::collections::BTreeMap<String, TransactionReceipt> =
            serde_json::from_str(&raw).map_err(|e| VNetworkError::Storage(e.to_string()))?;
        for (k, v) in txs {
            if v.status == ProgramLifecycleStatus::Committed
                || invalidated_min_height.is_none()
            {
                state.transactions.entry(k).or_insert(v);
            }
        }
    }

    // Clean up committed/rolled-back derived artifact inconsistencies if needed
    if rolled_back_uncommitted > 0 || proposals_replayed > 0 {
        save_full_state_snapshot(data_dir, &state)?;
        save_transactions_and_programs(data_dir, &state.programs, &state.transactions)?;
        persist_entity_index(data_dir, &state)?;
    }

    if tx_dir.exists() {
        for entry in fs::read_dir(&tx_dir).map_err(|e| VNetworkError::Storage(e.to_string()))? {
            let path = entry.map_err(|e| VNetworkError::Storage(e.to_string()))?.path();
            if path.is_file() {
                fs::remove_file(&path).map_err(|e| VNetworkError::Storage(e.to_string()))?;
            }
        }
    }

    let root = state.compute_state_root()?;
    let report = RecoveryReport {
        recovered_from_snapshot,
        rolled_back_uncommitted,
        wal_events_verified: state.events.len(),
        proposals_replayed,
        final_height: state.height,
        state_root: root,
    };

    Ok((state, report))
}
