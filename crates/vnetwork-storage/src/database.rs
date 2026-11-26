use crate::events::EventWal;
use crate::indexes::{persist_entity_index, StorageIndex};
use crate::migrations::run_migrations;
use crate::recovery::{recover_state_from_disk, RecoveryReport};
use crate::snapshots::save_full_state_snapshot;
use crate::transactions::{atomic_write_json, save_transactions_and_programs, CommittedProposalRecord, ConsensusWal};
use std::fs;
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

    pub fn persist_commit(
        &self,
        state: &NetworkLedgerState,
        proposal: &ConsensusProposal,
        qc: &QuorumCertificate,
    ) -> VResult<StorageIndex> {
        EventWal::new(&self.data_dir).append_events(&proposal.events)?;
        ConsensusWal::new(&self.data_dir).append(proposal, qc)?;
        save_full_state_snapshot(&self.data_dir, state)?;
        save_transactions_and_programs(&self.data_dir, &state.programs, &state.transactions)?;
        persist_entity_index(&self.data_dir, state)
    }

    pub fn persist_metadata_only(&self, state: &NetworkLedgerState) -> VResult<()> {
        save_transactions_and_programs(&self.data_dir, &state.programs, &state.transactions)?;
        save_full_state_snapshot(&self.data_dir, state)?;
        let _ = persist_entity_index(&self.data_dir, state)?;
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
