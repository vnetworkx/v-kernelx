use crate::events::EventWal;
use crate::indexes::{persist_entity_index, StorageIndex};
use crate::migrations::run_migrations;
use crate::recovery::{
    committed_tx_path, pending_tx_path, recover_state_from_disk, verify_wal_exact_alignment,
    RecoveryReport,
};
use crate::snapshots::{load_certified_checkpoint, save_certified_checkpoint_from_state};
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
        let genesis_path = self.data_dir.join("genesis.json");
        if !genesis_path.exists() {
            return Err(VNetworkError::Storage(
                "missing genesis.json in storage directory".to_string(),
            ));
        }
        let raw_genesis = fs::read_to_string(&genesis_path)
            .map_err(|e| VNetworkError::Storage(format!("read genesis.json failed: {e}")))?;
        let genesis: GenesisConfig = serde_json::from_str(&raw_genesis)
            .map_err(|e| VNetworkError::Storage(format!("parse genesis.json failed: {e}")))?;
        genesis.validate()?;

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

        let commits = ConsensusWal::new(&self.data_dir).read_all()?;
        let wal_events = EventWal::new(&self.data_dir).read_all()?;
        verify_wal_exact_alignment(&commits, &wal_events, &genesis)?;
        let _ = load_certified_checkpoint(&self.data_dir, &genesis)?;
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
        proposal.verify_digest_and_metadata()?;
        let computed_root = state.compute_state_root()?;
        if state.height != proposal.height || computed_root != proposal.post_state_root {
            return Err(VNetworkError::Storage(format!(
                "persist_commit mismatch: state height/root ({}, {computed_root}) != proposal ({}, {})",
                state.height, proposal.height, proposal.post_state_root
            )));
        }

        let p_path = pending_tx_path(&self.data_dir, proposal.height);
        let c_path = committed_tx_path(&self.data_dir, proposal.height);
        let prior_events = state
            .events
            .len()
            .checked_sub(proposal.events.len())
            .ok_or_else(|| {
                VNetworkError::Storage(
                    "persist_commit invariant violated: state event count < proposal event count"
                        .to_string(),
                )
            })?;
        let pending = PendingCommitRecord {
            height: proposal.height,
            proposal_id: proposal.proposal_id.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
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
            proposal_digest: proposal.proposal_digest.clone(),
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

        if state.height > 0 {
            save_certified_checkpoint_from_state(
                &self.data_dir,
                state,
                qc,
                &proposal.proposal_digest,
                &proposal.parent_commitment,
                qc.finalized_at_ms,
            )?;
        }
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

        if p_path.exists() {
            fs::remove_file(&p_path).map_err(|e| {
                VNetworkError::Storage(format!("remove pending WAL marker {:?}: {e}", p_path))
            })?;
        }
        if c_path.exists() {
            fs::remove_file(&c_path).map_err(|e| {
                VNetworkError::Storage(format!("remove committed WAL marker {:?}: {e}", c_path))
            })?;
        }
        Ok(idx)
    }

    pub fn persist_metadata_only(&self, state: &NetworkLedgerState) -> VResult<()> {
        save_transactions_and_programs(&self.data_dir, &state.programs, &state.transactions)?;
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
        if state.height > 0 {
            let last = commits.last().ok_or_else(|| {
                VNetworkError::Storage(
                    "rewrite_full_state with non-zero height requires certified commit record"
                        .to_string(),
                )
            })?;
            save_certified_checkpoint_from_state(
                &self.data_dir,
                state,
                &last.certificate,
                &last.proposal.proposal_digest,
                &last.proposal.parent_commitment,
                last.certificate.finalized_at_ms,
            )?;
        }
        save_transactions_and_programs(&self.data_dir, &state.programs, &state.transactions)?;
        persist_entity_index(&self.data_dir, state)
    }
}
