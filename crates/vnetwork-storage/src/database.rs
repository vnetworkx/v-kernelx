use crate::events::EventWal;
use crate::indexes::{persist_entity_index, StorageIndex};
use crate::migrations::run_migrations;
use crate::recovery::{committed_tx_path, pending_tx_path, recover_state_from_disk, RecoveryReport};
use crate::snapshots::save_full_state_snapshot;
use crate::transactions::{
    atomic_write_json, save_transactions_and_programs, CommittedCommitMarker,
    CommittedProposalRecord, ConsensusWal, PendingCommitRecord, PersistFailpoint,
};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use vnetwork_core::state::{GenesisConfig, NetworkLedgerState};
use vnetwork_types::*;

#[derive(Debug, Clone)]
pub struct StorageDatabase {
    data_dir: PathBuf,
}

impl StorageDatabase {
    pub fn open_and_recover(
        data_dir: impl AsRef<Path>,
        genesis: &GenesisConfig,
    ) -> VResult<(Self, NetworkLedgerState, RecoveryReport)> {
        let dir = data_dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)
            .map_err(|e| VNetworkError::Storage(format!("create storage dir failed: {e}")))?;

        let now = now_ms();
        run_migrations(&dir, now)?;

        let genesis_path = dir.join("genesis.json");
        if !genesis_path.exists() {
            atomic_write_json(&genesis_path, genesis)?;
        }

        let (state, report) = recover_state_from_disk(&dir, genesis)?;
        persist_entity_index(&dir, &state)?;

        Ok((Self { data_dir: dir }, state, report))
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn check_health(&self) -> VResult<()> {
        if !self.data_dir.join("genesis.json").exists() {
            return Err(VNetworkError::Storage(
                "missing genesis.json in storage directory".to_string(),
            ));
        }
        let probe = self.data_dir.join(".health_probe");
        {
            let mut f = File::create(&probe)
                .map_err(|e| VNetworkError::Storage(format!("storage not writable: {e}")))?;
            f.write_all(b"ok")
                .map_err(|e| VNetworkError::Storage(format!("storage write probe failed: {e}")))?;
            f.sync_all()
                .map_err(|e| VNetworkError::Storage(format!("storage sync probe failed: {e}")))?;
        }
        fs::remove_file(&probe)
            .map_err(|e| VNetworkError::Storage(format!("storage cleanup probe failed: {e}")))?;
        ConsensusWal::new(&self.data_dir).read_all()?;
        EventWal::new(&self.data_dir).read_all()?;
        Ok(())
    }

    pub fn persist_commit(
        &self,
        state: &NetworkLedgerState,
        proposal: &ConsensusProposal,
        qc: &QuorumCertificate,
    ) -> VResult<StorageIndex> {
        self.persist_commit_with_failpoint(state, proposal, qc, PersistFailpoint::None)
    }

    pub fn persist_commit_with_failpoint(
        &self,
        state: &NetworkLedgerState,
        proposal: &ConsensusProposal,
        qc: &QuorumCertificate,
        failpoint: PersistFailpoint,
    ) -> VResult<StorageIndex> {
        let computed_root = state.compute_state_root()?;
        if state.height != proposal.height || computed_root != proposal.post_state_root {
            return Err(VNetworkError::Storage(format!(
                "persist_commit mismatch: state height/root ({}, {computed_root}) != proposal ({}, {})",
                state.height, proposal.height, proposal.post_state_root
            )));
        }

        let p_path = pending_tx_path(&self.data_dir, proposal.height);
        let c_path = committed_tx_path(&self.data_dir, proposal.height);
        let prior_events = state.events.len().saturating_sub(proposal.events.len());
        let pending = PendingCommitRecord {
            height: proposal.height,
            proposal_id: proposal.proposal_id.clone(),
            certificate_id: qc.certificate_id.clone(),
            post_state_root: proposal.post_state_root.clone(),
            prior_event_count: prior_events,
            event_count: state.events.len(),
        };
        atomic_write_json(&p_path, &pending)?;
        if failpoint == PersistFailpoint::AfterPendingRecord {
            return Err(VNetworkError::Storage(
                "simulated crash AfterPendingRecord".to_string(),
            ));
        }

        EventWal::new(&self.data_dir).append_events(&proposal.events)?;
        if failpoint == PersistFailpoint::AfterEventWal {
            return Err(VNetworkError::Storage(
                "simulated crash AfterEventWal".to_string(),
            ));
        }

        ConsensusWal::new(&self.data_dir).append(proposal, qc)?;
        if failpoint == PersistFailpoint::AfterConsensusWal {
            return Err(VNetworkError::Storage(
                "simulated crash AfterConsensusWal".to_string(),
            ));
        }

        let marker = CommittedCommitMarker {
            height: proposal.height,
            proposal_id: proposal.proposal_id.clone(),
            certificate_id: qc.certificate_id.clone(),
            post_state_root: proposal.post_state_root.clone(),
            event_count: state.events.len(),
        };
        atomic_write_json(&c_path, &marker)?;
        if failpoint == PersistFailpoint::AfterCommittedMarker {
            return Err(VNetworkError::Storage(
                "simulated crash AfterCommittedMarker".to_string(),
            ));
        }

        save_full_state_snapshot(&self.data_dir, state)?;
        if failpoint == PersistFailpoint::AfterSnapshot {
            return Err(VNetworkError::Storage(
                "simulated crash AfterSnapshot".to_string(),
            ));
        }

        save_transactions_and_programs(&self.data_dir, &state.programs, &state.transactions)?;
        if failpoint == PersistFailpoint::AfterTransactions {
            return Err(VNetworkError::Storage(
                "simulated crash AfterTransactions".to_string(),
            ));
        }

        let idx = persist_entity_index(&self.data_dir, state)?;
        if failpoint == PersistFailpoint::AfterEntityIndex {
            return Err(VNetworkError::Storage(
                "simulated crash AfterEntityIndex".to_string(),
            ));
        }

        let _ = fs::remove_file(&p_path);
        let _ = fs::remove_file(&c_path);
        Ok(idx)
    }

    pub fn persist_metadata_only(&self, state: &NetworkLedgerState) -> VResult<()> {
        save_transactions_and_programs(&self.data_dir, &state.programs, &state.transactions)?;
        save_full_state_snapshot(&self.data_dir, state)?;
        persist_entity_index(&self.data_dir, state)?;
        Ok(())
    }

    pub fn load_committed_proposals(&self) -> VResult<Vec<CommittedProposalRecord>> {
        ConsensusWal::new(&self.data_dir).read_all()
    }

    pub fn rewrite_full_state(
        &self,
        state: &NetworkLedgerState,
        commits: &[CommittedProposalRecord],
    ) -> VResult<StorageIndex> {
        EventWal::new(&self.data_dir).rewrite_all(&state.events)?;
        ConsensusWal::new(&self.data_dir).rewrite_all(commits)?;
        save_full_state_snapshot(&self.data_dir, state)?;
        save_transactions_and_programs(&self.data_dir, &state.programs, &state.transactions)?;
        persist_entity_index(&self.data_dir, state)
    }
}
