use crate::events::EventWal;
use crate::snapshots::load_full_state_snapshot;
use crate::transactions::ConsensusWal;
use std::fs;
use std::path::Path;
use vnetwork_core::consensus_gate::commit_verified_proposal;
use vnetwork_core::replay::replay_from_events;
use vnetwork_core::state::{GenesisConfig, NetworkLedgerState, TransactionReceipt};
use vnetwork_types::*;

#[derive(Debug, Clone)]
pub struct RecoveryReport {
    pub recovered_from_snapshot: bool,
    pub wal_events_verified: usize,
    pub proposals_replayed: usize,
    pub final_height: u64,
    pub state_root: String,
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
        if stored.network_id != expected_genesis.network_id
            || stored.profile != expected_genesis.profile
        {
            return Err(VNetworkError::ProfileMismatch(format!(
                "persisted storage belongs to network `{}` ({}), node configured for `{}` ({})",
                stored.network_id,
                stored.profile.as_str(),
                expected_genesis.network_id,
                expected_genesis.profile.as_str()
            )));
        }
    }

    let wal_events = EventWal::new(data_dir).read_all()?;
    let committed_proposals = ConsensusWal::new(data_dir).read_all()?;
    let snap = load_full_state_snapshot(data_dir)?;

    let mut state = match snap {
        Some(mut s) => {
            if s.events.len() < wal_events.len() {
                // Rebuild deterministically from genesis + full verified WAL or apply missing commits
                let mut rebuilt = replay_from_events(expected_genesis, &wal_events)?;
                rebuilt.programs = s.programs;
                rebuilt.transactions = s.transactions;
                rebuilt.certificates = s.certificates;
                rebuilt.snapshots = s.snapshots;
                rebuilt.actor_nonces = s.actor_nonces;
                rebuilt.seen_request_ids = s.seen_request_ids;
                rebuilt
            } else {
                // Verify snapshot against WAL
                if !wal_events.is_empty() && s.events.len() == wal_events.len() {
                    let s_hash = s.compute_replay_hash();
                    let replayed = replay_from_events(expected_genesis, &wal_events)?;
                    if replayed.compute_replay_hash() != s_hash {
                        return Err(VNetworkError::Storage(
                            "snapshot replay hash mismatch against event WAL".to_string(),
                        ));
                    }
                }
                s.height = committed_proposals
                    .last()
                    .map(|p| p.proposal.height)
                    .unwrap_or(s.height);
                s
            }
        }
        None => {
            if !committed_proposals.is_empty() {
                let mut base = NetworkLedgerState::new(expected_genesis);
                for rec in &committed_proposals {
                    commit_verified_proposal(
                        &mut base,
                        &rec.proposal,
                        &rec.certificate,
                        &expected_genesis.initial_validators,
                    )?;
                }
                base
            } else if !wal_events.is_empty() {
                replay_from_events(expected_genesis, &wal_events)?
            } else {
                NetworkLedgerState::new(expected_genesis)
            }
        }
    };

    // Replay any consensus commits strictly above recovered height
    let mut proposals_replayed = 0usize;
    for rec in &committed_proposals {
        if rec.proposal.height > state.height {
            commit_verified_proposal(
                &mut state,
                &rec.proposal,
                &rec.certificate,
                &expected_genesis.initial_validators,
            )?;
            proposals_replayed += 1;
        } else if !state
            .certificates
            .contains_key(&rec.certificate.certificate_id)
        {
            state
                .certificates
                .insert(rec.certificate.certificate_id.clone(), rec.certificate.clone());
        }
    }

    let programs_path = data_dir.join("programs.json");
    if programs_path.exists() {
        let raw = fs::read_to_string(&programs_path)
            .map_err(|e| VNetworkError::Storage(e.to_string()))?;
        let programs: std::collections::BTreeMap<String, ProgramSubmission> =
            serde_json::from_str(&raw).map_err(|e| VNetworkError::Storage(e.to_string()))?;
        for (k, v) in programs {
            state.programs.entry(k).or_insert(v);
        }
    }

    let txs_path = data_dir.join("transactions.json");
    if txs_path.exists() {
        let raw = fs::read_to_string(&txs_path)
            .map_err(|e| VNetworkError::Storage(e.to_string()))?;
        let txs: std::collections::BTreeMap<String, TransactionReceipt> =
            serde_json::from_str(&raw).map_err(|e| VNetworkError::Storage(e.to_string()))?;
        for (k, v) in txs {
            state.transactions.entry(k).or_insert(v);
        }
    }

    let root = state.compute_state_root()?;
    let report = RecoveryReport {
        recovered_from_snapshot: load_full_state_snapshot(data_dir)?.is_some(),
        wal_events_verified: state.events.len(),
        proposals_replayed,
        final_height: state.height,
        state_root: root,
    };

    Ok((state, report))
}
