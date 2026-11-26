use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use vnetwork_core::state::TransactionReceipt;
use vnetwork_types::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistFailpoint {
    None,
    AfterPendingRecord,
    AfterEventWal,
    AfterConsensusWal,
    AfterCommittedMarker,
    AfterSnapshot,
    AfterTransactions,
    AfterEntityIndex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingCommitRecord {
    pub height: u64,
    pub proposal_id: String,
    pub certificate_id: String,
    pub post_state_root: String,
    pub prior_event_count: usize,
    pub event_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommittedCommitMarker {
    pub height: u64,
    pub proposal_id: String,
    pub certificate_id: String,
    pub post_state_root: String,
    pub event_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommittedProposalRecord {
    pub proposal: ConsensusProposal,
    pub certificate: QuorumCertificate,
}

pub struct ConsensusWal {
    path: PathBuf,
}

impl ConsensusWal {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join("consensus_commits.wal"),
        }
    }

    pub fn append(&self, proposal: &ConsensusProposal, certificate: &QuorumCertificate) -> VResult<()> {
        let rec = CommittedProposalRecord {
            proposal: proposal.clone(),
            certificate: certificate.clone(),
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| VNetworkError::Storage(format!("open consensus_commits.wal failed: {e}")))?;
        let line = serde_json::to_string(&rec)
            .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
        writeln!(file, "{line}")
            .map_err(|e| VNetworkError::Storage(format!("write consensus_commits.wal failed: {e}")))?;
        file.sync_all()
            .map_err(|e| VNetworkError::Storage(format!("sync consensus_commits.wal failed: {e}")))?;
        Ok(())
    }

    pub fn read_all(&self) -> VResult<Vec<CommittedProposalRecord>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(&self.path)
            .map_err(|e| VNetworkError::Storage(format!("read consensus_commits.wal failed: {e}")))?;
        let reader = BufReader::new(file);
        let mut out = Vec::new();
        for (idx, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| VNetworkError::Storage(e.to_string()))?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let rec: CommittedProposalRecord = serde_json::from_str(trimmed).map_err(|e| {
                VNetworkError::Storage(format!("corrupt consensus_commits.wal line {}: {e}", idx + 1))
            })?;
            out.push(rec);
        }
        Ok(out)
    }

    pub fn rewrite_all(&self, recs: &[CommittedProposalRecord]) -> VResult<()> {
        let tmp = self.path.with_extension("wal.tmp");
        {
            let mut file = File::create(&tmp)
                .map_err(|e| VNetworkError::Storage(format!("create consensus_commits.wal.tmp failed: {e}")))?;
            for rec in recs {
                let line = serde_json::to_string(rec)
                    .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
                writeln!(file, "{line}")
                    .map_err(|e| VNetworkError::Storage(e.to_string()))?;
            }
            file.sync_all().map_err(|e| VNetworkError::Storage(e.to_string()))?;
        }
        fs::rename(&tmp, &self.path).map_err(|e| VNetworkError::Storage(e.to_string()))?;
        Ok(())
    }
}

pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> VResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| VNetworkError::Storage(format!("create parent dir {:?} failed: {e}", parent)))?;
    }
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
    {
        let mut f = File::create(&tmp)
            .map_err(|e| VNetworkError::Storage(format!("create {:?} failed: {e}", tmp)))?;
        f.write_all(&bytes)
            .map_err(|e| VNetworkError::Storage(format!("write {:?} failed: {e}", tmp)))?;
        f.sync_all()
            .map_err(|e| VNetworkError::Storage(format!("sync {:?} failed: {e}", tmp)))?;
    }
    fs::rename(&tmp, path)
        .map_err(|e| VNetworkError::Storage(format!("rename {:?} failed: {e}", path)))?;
    Ok(())
}

pub fn save_transactions_and_programs(
    data_dir: &Path,
    programs: &std::collections::BTreeMap<String, ProgramSubmission>,
    transactions: &std::collections::BTreeMap<String, TransactionReceipt>,
) -> VResult<()> {
    atomic_write_json(&data_dir.join("programs.json"), programs)?;
    atomic_write_json(&data_dir.join("transactions.json"), transactions)?;
    Ok(())
}
