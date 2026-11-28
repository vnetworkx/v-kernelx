use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use vnetwork_core::state::TransactionReceipt;
use vnetwork_types::*;

static STORAGE_TMP_SEQ: AtomicU64 = AtomicU64::new(1);

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
    #[serde(default)]
    pub proposal_digest: String,
    pub certificate_id: String,
    pub post_state_root: String,
    pub prior_event_count: usize,
    pub event_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommittedCommitMarker {
    pub height: u64,
    pub proposal_id: String,
    #[serde(default)]
    pub proposal_digest: String,
    pub certificate_id: String,
    pub post_state_root: String,
    pub event_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommittedProposalRecord {
    pub proposal: ConsensusProposal,
    pub certificate: QuorumCertificate,
}

pub(crate) fn quarantine_bytes(
    data_dir: &Path,
    tag: &str,
    orig_name: &str,
    bytes: &[u8],
) -> VResult<String> {
    let qdir = data_dir.join("forensic_quarantine");
    fs::create_dir_all(&qdir)
        .map_err(|e| VNetworkError::Storage(format!("create forensic_quarantine failed: {e}")))?;
    let seq = STORAGE_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let dest = qdir.join(format!(
        "{}_{}_{}_{}.partial",
        now_ms(),
        seq,
        tag,
        orig_name
    ));
    atomic_write_bytes(&dest, bytes)?;
    Ok(dest.display().to_string())
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

    pub fn append(
        &self,
        proposal: &ConsensusProposal,
        certificate: &QuorumCertificate,
    ) -> VResult<()> {
        let rec = CommittedProposalRecord {
            proposal: proposal.clone(),
            certificate: certificate.clone(),
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| {
                VNetworkError::Storage(format!("open consensus_commits.wal failed: {e}"))
            })?;
        let line =
            serde_json::to_string(&rec).map_err(|e| VNetworkError::Serialization(e.to_string()))?;
        writeln!(file, "{line}").map_err(|e| {
            VNetworkError::Storage(format!("write consensus_commits.wal failed: {e}"))
        })?;
        file.sync_all().map_err(|e| {
            VNetworkError::Storage(format!("sync consensus_commits.wal failed: {e}"))
        })?;
        Ok(())
    }

    pub fn read_all(&self) -> VResult<Vec<CommittedProposalRecord>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(&self.path).map_err(|e| {
            VNetworkError::Storage(format!("read consensus_commits.wal failed: {e}"))
        })?;
        let reader = BufReader::new(file);
        let mut out = Vec::new();
        for (idx, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| VNetworkError::Storage(e.to_string()))?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let rec: CommittedProposalRecord = serde_json::from_str(trimmed).map_err(|e| {
                VNetworkError::Storage(format!(
                    "corrupt consensus_commits.wal line {}: {e}",
                    idx + 1
                ))
            })?;
            out.push(rec);
        }
        Ok(out)
    }

    /// Reads consensus WAL records. If a crash interrupted the final trailing line without a newline,
    /// quarantines the incomplete trailing fragment into `forensic_quarantine/` and safely truncates
    /// back to the last complete `\n`-terminated record. Complete lines with corrupt JSON always fail closed.
    pub fn read_all_with_trailing_recovery(
        &self,
        data_dir: &Path,
    ) -> VResult<(Vec<CommittedProposalRecord>, Vec<String>)> {
        if !self.path.exists() {
            return Ok((Vec::new(), Vec::new()));
        }
        let raw_bytes = fs::read(&self.path).map_err(|e| {
            VNetworkError::Storage(format!("read consensus_commits.wal failed: {e}"))
        })?;
        if raw_bytes.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let ends_with_newline = raw_bytes.ends_with(b"\n");
        let last_nl_pos = raw_bytes.iter().rposition(|&b| b == b'\n');

        let text = match std::str::from_utf8(&raw_bytes) {
            Ok(s) => s.to_string(),
            Err(_) => {
                // Only salvage if corruption is strictly inside an unterminated trailing line after last '\n'
                if let Some(pos) = last_nl_pos {
                    let prefix_str = std::str::from_utf8(&raw_bytes[..=pos]).map_err(|e| {
                        VNetworkError::Storage(format!(
                            "corrupt UTF-8 inside committed consensus_commits.wal prefix: {e}"
                        ))
                    })?;
                    let mut out = Vec::new();
                    for (idx, line) in prefix_str.lines().enumerate() {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        let rec: CommittedProposalRecord =
                            serde_json::from_str(trimmed).map_err(|e| {
                                VNetworkError::Storage(format!(
                                    "corrupt consensus_commits.wal line {}: {e}",
                                    idx + 1
                                ))
                            })?;
                        out.push(rec);
                    }
                    let q = quarantine_bytes(
                        data_dir,
                        "trailing_incomplete_utf8",
                        "consensus_commits.wal",
                        &raw_bytes[pos + 1..],
                    )?;
                    self.rewrite_all(&out)?;
                    return Ok((out, vec![q]));
                }
                return Err(VNetworkError::Storage(
                    "corrupt UTF-8 in consensus_commits.wal with no complete newline delimiter"
                        .to_string(),
                ));
            }
        };

        let mut out = Vec::new();
        let mut quarantined = Vec::new();
        let segments: Vec<&str> = text.split_inclusive('\n').collect();
        let total = segments.len();
        for (idx, seg) in segments.into_iter().enumerate() {
            let is_final = idx + 1 == total;
            let has_newline = seg.ends_with('\n');
            let trimmed = seg.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<CommittedProposalRecord>(trimmed) {
                Ok(rec) => out.push(rec),
                Err(e) => {
                    if is_final && !ends_with_newline && !has_newline {
                        let q = quarantine_bytes(
                            data_dir,
                            "trailing_incomplete_json",
                            "consensus_commits.wal",
                            seg.as_bytes(),
                        )?;
                        quarantined.push(q);
                        self.rewrite_all(&out)?;
                        return Ok((out, quarantined));
                    }
                    return Err(VNetworkError::Storage(format!(
                        "corrupt consensus_commits.wal line {}: {e}",
                        idx + 1
                    )));
                }
            }
        }
        Ok((out, quarantined))
    }

    pub fn rewrite_all(&self, recs: &[CommittedProposalRecord]) -> VResult<()> {
        let mut buf = Vec::new();
        for rec in recs {
            let line = serde_json::to_string(rec)
                .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
            writeln!(buf, "{line}").map_err(|e| VNetworkError::Storage(e.to_string()))?;
        }
        atomic_write_bytes(&self.path, &buf)
    }
}

pub(crate) fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> VResult<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| {
                VNetworkError::Storage(format!("create parent dir {:?} failed: {e}", parent))
            })?;
        }
    }
    let seq = STORAGE_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("storage.tmp");
    let tmp = path.with_file_name(format!("{fname}.tmp.{}.{seq}", std::process::id()));

    let write_res: VResult<()> = (|| {
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)
            .map_err(|e| {
                VNetworkError::Storage(format!("create exclusive tmp {:?} failed: {e}", tmp))
            })?;
        f.write_all(bytes)
            .map_err(|e| VNetworkError::Storage(format!("write {:?} failed: {e}", tmp)))?;
        f.sync_all()
            .map_err(|e| VNetworkError::Storage(format!("sync {:?} failed: {e}", tmp)))?;
        drop(f);
        fs::rename(&tmp, path)
            .map_err(|e| VNetworkError::Storage(format!("rename {:?} failed: {e}", path)))?;
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }

    #[cfg(unix)]
    {
        let parent_dir = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let dir = File::open(parent_dir).map_err(|e| {
            VNetworkError::Storage(format!(
                "open parent dir {:?} for fsync failed: {e}",
                parent_dir
            ))
        })?;
        dir.sync_all().map_err(|e| {
            VNetworkError::Storage(format!("fsync parent dir {:?} failed: {e}", parent_dir))
        })?;
    }
    Ok(())
}

pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> VResult<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
    atomic_write_bytes(path, &bytes)
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
