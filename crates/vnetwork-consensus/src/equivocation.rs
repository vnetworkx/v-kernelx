use crate::membership::ValidatorMembership;
use crate::vote::verify_consensus_vote;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use vnetwork_types::*;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VoteSlotKey {
    pub network_id: String,
    pub genesis_commitment: String,
    pub validator_id: String,
    pub pubkey_fingerprint: String,
    pub epoch: u64,
    pub height: u64,
    pub round: u64,
    pub vote_phase: VotePhase,
    pub protocol_version: String,
}

impl VoteSlotKey {
    pub fn from_vote(vote: &ConsensusVote) -> VResult<Self> {
        let fp = pubkey_fingerprint(&vote.validator_pubkey_hex)?;
        Ok(Self {
            network_id: vote.network_id.clone(),
            genesis_commitment: vote.genesis_commitment.clone(),
            validator_id: vote.validator_id.clone(),
            pubkey_fingerprint: fp,
            epoch: vote.epoch,
            height: vote.height,
            round: vote.round,
            vote_phase: vote.vote_phase,
            protocol_version: vote.protocol_version.clone(),
        })
    }

    pub fn from_proposal(
        proposal: &ConsensusProposal,
        validator: &ConsensusValidator,
        vote_phase: VotePhase,
    ) -> VResult<Self> {
        let fp = validator.pubkey_fingerprint()?;
        Ok(Self {
            network_id: proposal.network_id.clone(),
            genesis_commitment: proposal.genesis_commitment.clone(),
            validator_id: validator.validator_id.clone(),
            pubkey_fingerprint: fp,
            epoch: proposal.epoch,
            height: proposal.height,
            round: proposal.round,
            vote_phase,
            protocol_version: proposal.protocol_version.clone(),
        })
    }

    pub fn slot_id(&self) -> VResult<String> {
        let bytes = canonical_json_bytes(self)?;
        Ok(blake3_hex(&bytes))
    }
}

#[allow(clippy::too_many_arguments)]
fn votes_conflict(
    a_prop_id: &str,
    a_prop_digest: &str,
    a_post_root: &str,
    a_vset_hash: &str,
    a_params_hash: &str,
    a_parent: &str,
    a_approve: bool,
    b_prop_id: &str,
    b_prop_digest: &str,
    b_post_root: &str,
    b_vset_hash: &str,
    b_params_hash: &str,
    b_parent: &str,
    b_approve: bool,
) -> bool {
    a_prop_id != b_prop_id
        || a_prop_digest != b_prop_digest
        || a_post_root != b_post_root
        || a_vset_hash != b_vset_hash
        || a_params_hash != b_params_hash
        || a_parent != b_parent
        || a_approve != b_approve
}

fn verify_standalone_vote_signature_and_fields(vote: &ConsensusVote) -> VResult<VoteSlotKey> {
    if vote.network_id.trim().is_empty()
        || vote.genesis_commitment.trim().is_empty()
        || vote.protocol_version.trim().is_empty()
        || vote.validator_id.trim().is_empty()
        || vote.proposal_id.trim().is_empty()
        || vote.proposal_digest.trim().is_empty()
        || vote.validator_set_hash.trim().is_empty()
        || vote.consensus_parameters_hash.trim().is_empty()
        || vote.parent_commitment.trim().is_empty()
        || vote.pre_state_root.trim().is_empty()
        || vote.post_state_root.trim().is_empty()
    {
        return Err(VNetworkError::Consensus(
            "observed vote missing required binding metadata".to_string(),
        ));
    }
    let slot = VoteSlotKey::from_vote(vote)?;
    let bytes = vote.canonical_signing_bytes()?;
    verify_ed25519(&vote.validator_pubkey_hex, &bytes, &vote.signature)?;
    Ok(slot)
}

#[derive(Debug, Default, Clone)]
pub struct EquivocationDetector {
    seen_votes: BTreeMap<String, ConsensusVote>,
    pub evidence: Vec<EquivocationEvidence>,
    pub incidents: Vec<SigningConflictIncident>,
}

impl EquivocationDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check_and_record(&mut self, vote: &ConsensusVote, timestamp_ms: u64) -> VResult<()> {
        let slot = match verify_standalone_vote_signature_and_fields(vote) {
            Ok(s) => s,
            Err(err) => {
                let incident = SigningConflictIncident {
                    classification: VoteEvidenceClassification::InvalidObservedVote,
                    network_id: vote.network_id.clone(),
                    genesis_commitment: vote.genesis_commitment.clone(),
                    protocol_version: vote.protocol_version.clone(),
                    validator_id: vote.validator_id.clone(),
                    pubkey_fingerprint: pubkey_fingerprint(&vote.validator_pubkey_hex)
                        .unwrap_or_default(),
                    epoch: vote.epoch,
                    height: vote.height,
                    round: vote.round,
                    vote_phase: vote.vote_phase,
                    existing_proposal_id: String::new(),
                    existing_proposal_digest: String::new(),
                    conflicting_proposal_id: vote.proposal_id.clone(),
                    conflicting_proposal_digest: vote.proposal_digest.clone(),
                    observed_vote: Some(vote.clone()),
                    reason: format!(
                        "invalid observed vote rejected without fabricating evidence: {err}"
                    ),
                    detected_at_ms: timestamp_ms,
                };
                self.incidents.push(incident);
                return Err(err);
            }
        };
        let slot_id = slot.slot_id()?;
        if let Some(prev) = self.seen_votes.get(&slot_id) {
            if votes_conflict(
                &prev.proposal_id,
                &prev.proposal_digest,
                &prev.post_state_root,
                &prev.validator_set_hash,
                &prev.consensus_parameters_hash,
                &prev.parent_commitment,
                prev.approve,
                &vote.proposal_id,
                &vote.proposal_digest,
                &vote.post_state_root,
                &vote.validator_set_hash,
                &vote.consensus_parameters_hash,
                &vote.parent_commitment,
                vote.approve,
            ) {
                let ev = EquivocationEvidence {
                    network_id: vote.network_id.clone(),
                    genesis_commitment: vote.genesis_commitment.clone(),
                    protocol_version: vote.protocol_version.clone(),
                    validator_id: vote.validator_id.clone(),
                    pubkey_fingerprint: slot.pubkey_fingerprint,
                    epoch: vote.epoch,
                    height: vote.height,
                    round: vote.round,
                    vote_phase: vote.vote_phase,
                    reason: "conflicting signed vote observed for same validator signing slot"
                        .to_string(),
                    vote_a: prev.clone(),
                    vote_b: vote.clone(),
                    detected_at_ms: timestamp_ms,
                };
                ev.verify_cryptographic_conflict()?;
                self.evidence.push(ev);
                return Err(VNetworkError::Consensus(format!(
                    "equivocation detected from validator `{}` at height {} round {}",
                    vote.validator_id, vote.height, vote.round
                )));
            }
        } else {
            self.seen_votes.insert(slot_id, vote.clone());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PersistedVoteStatus {
    IntentPending,
    Signed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedVoteRecord {
    pub slot_id: String,
    pub slot: VoteSlotKey,
    pub status: PersistedVoteStatus,
    pub proposal_id: String,
    pub proposal_digest: String,
    pub validator_set_hash: String,
    #[serde(default)]
    pub consensus_parameters_hash: String,
    pub parent_commitment: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub operation_scope: String,
    pub approve: bool,
    pub recorded_at_ms: u64,
    pub signed_vote: Option<ConsensusVote>,
    pub record_hash: String,
}

impl PersistedVoteRecord {
    fn compute_record_hash(&self) -> VResult<String> {
        let obj = serde_json::json!({
            "approve": self.approve,
            "consensus_parameters_hash": self.consensus_parameters_hash,
            "domain": DOM_EQUIVOCATION_RECORD_V1,
            "operation_scope": self.operation_scope,
            "parent_commitment": self.parent_commitment,
            "post_state_root": self.post_state_root,
            "pre_state_root": self.pre_state_root,
            "proposal_digest": self.proposal_digest,
            "proposal_id": self.proposal_id,
            "recorded_at_ms": self.recorded_at_ms,
            "signed_vote": self.signed_vote,
            "slot": self.slot,
            "slot_id": self.slot_id,
            "status": self.status,
            "validator_set_hash": self.validator_set_hash,
        });
        Ok(blake3_hex(&canonical_json_bytes(&obj)?))
    }

    fn verify_integrity(&self) -> VResult<()> {
        if self.slot.network_id.trim().is_empty()
            || self.slot.genesis_commitment.trim().is_empty()
            || self.slot.protocol_version.trim().is_empty()
            || self.slot.validator_id.trim().is_empty()
            || self.proposal_id.trim().is_empty()
            || self.proposal_digest.trim().is_empty()
            || self.validator_set_hash.trim().is_empty()
            || self.consensus_parameters_hash.trim().is_empty()
            || self.parent_commitment.trim().is_empty()
            || self.pre_state_root.trim().is_empty()
            || self.post_state_root.trim().is_empty()
        {
            return Err(VNetworkError::Storage(
                "corrupt equivocation record: missing required binding metadata".to_string(),
            ));
        }
        let expected_slot_id = self.slot.slot_id()?;
        if self.slot_id != expected_slot_id {
            return Err(VNetworkError::Storage(format!(
                "corrupt equivocation record slot_id `{}` != expected `{expected_slot_id}`",
                self.slot_id
            )));
        }
        let expected_hash = self.compute_record_hash()?;
        if self.record_hash != expected_hash {
            return Err(VNetworkError::Storage(format!(
                "corrupt equivocation record checksum at slot `{}`",
                self.slot_id
            )));
        }
        if self.status == PersistedVoteStatus::Signed {
            let vote = self.signed_vote.as_ref().ok_or_else(|| {
                VNetworkError::Storage(
                    "corrupt equivocation record: Signed status missing signed_vote".to_string(),
                )
            })?;
            if vote.proposal_id != self.proposal_id
                || vote.proposal_digest != self.proposal_digest
                || vote.network_id != self.slot.network_id
                || vote.genesis_commitment != self.slot.genesis_commitment
                || vote.protocol_version != self.slot.protocol_version
                || vote.validator_id != self.slot.validator_id
                || vote.height != self.slot.height
                || vote.round != self.slot.round
                || vote.epoch != self.slot.epoch
                || vote.vote_phase != self.slot.vote_phase
                || vote.validator_set_hash != self.validator_set_hash
                || vote.consensus_parameters_hash != self.consensus_parameters_hash
                || vote.parent_commitment != self.parent_commitment
                || vote.pre_state_root != self.pre_state_root
                || vote.post_state_root != self.post_state_root
                || vote.operation_scope != self.operation_scope
                || vote.approve != self.approve
            {
                return Err(VNetworkError::Storage(
                    "corrupt equivocation record: embedded signed_vote diverges from slot metadata"
                        .to_string(),
                ));
            }
            let fp = pubkey_fingerprint(&vote.validator_pubkey_hex)?;
            if fp != self.slot.pubkey_fingerprint {
                return Err(VNetworkError::Storage(
                    "corrupt equivocation record: embedded vote pubkey fingerprint diverges from slot"
                        .to_string(),
                ));
            }
            let signing_bytes = vote.canonical_signing_bytes()?;
            verify_ed25519(&vote.validator_pubkey_hex, &signing_bytes, &vote.signature).map_err(
                |e| {
                    VNetworkError::Storage(format!(
                        "corrupt equivocation record: embedded vote signature verification failed: {e}"
                    ))
                },
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct StoreLockMetadata {
    pid: u32,
    created_at_ms: u64,
}

/// Exclusive cross-process and cross-instance OS lockfile (`O_CREAT | O_EXCL` via `create_new(true)`).
#[derive(Debug)]
struct EquivocationLockGuard {
    lock_path: PathBuf,
}

impl EquivocationLockGuard {
    fn acquire(dir: &Path) -> VResult<Self> {
        let lock_path = dir.join("equivocation_store.lock");
        let mut attempts = 0u8;
        loop {
            attempts += 1;
            let open_res = {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&lock_path)
                }
                #[cfg(not(unix))]
                {
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&lock_path)
                }
            };
            match open_res {
                Ok(mut f) => {
                    let meta = StoreLockMetadata {
                        pid: std::process::id(),
                        created_at_ms: now_ms(),
                    };
                    let bytes = serde_json::to_vec(&meta)
                        .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
                    f.write_all(&bytes).map_err(|e| {
                        VNetworkError::Storage(format!("write equivocation lock failed: {e}"))
                    })?;
                    f.sync_all().map_err(|e| {
                        VNetworkError::Storage(format!("fsync equivocation lock failed: {e}"))
                    })?;
                    return Ok(Self { lock_path });
                }
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    // Only reclaim an orphaned lock from a different PID that is verifiably dead on Linux.
                    // Same-PID concurrent opens MUST always fail closed.
                    #[cfg(target_os = "linux")]
                    if attempts == 1 {
                        if let Ok(raw) = fs::read_to_string(&lock_path) {
                            if let Ok(existing) = serde_json::from_str::<StoreLockMetadata>(&raw) {
                                if existing.pid != std::process::id()
                                    && Path::new("/proc").exists()
                                    && !Path::new(&format!("/proc/{}", existing.pid)).exists()
                                {
                                    let _ = fs::remove_file(&lock_path);
                                    continue;
                                }
                            }
                        }
                    }
                    let _ = attempts;
                    return Err(VNetworkError::Storage(format!(
                        "equivocation store `{:?}` is already locked by an active writer",
                        lock_path
                    )));
                }
                Err(e) => {
                    return Err(VNetworkError::Storage(format!(
                        "acquire equivocation store lock `{:?}` failed: {e}",
                        lock_path
                    )));
                }
            }
        }
    }
}

impl Drop for EquivocationLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

/// Durable fail-closed anti-equivocation store backed by an OS exclusive writer lock and fsynced WAL files inside `storage_dir`.
#[derive(Debug, Clone)]
pub struct EquivocationStore {
    storage_dir: PathBuf,
    votes_wal_path: PathBuf,
    evidence_wal_path: PathBuf,
    incidents_wal_path: PathBuf,
    _lock: Arc<EquivocationLockGuard>,
    slots: BTreeMap<String, PersistedVoteRecord>,
    evidence: Vec<EquivocationEvidence>,
    incidents: Vec<SigningConflictIncident>,
}

impl EquivocationStore {
    pub fn open(storage_dir: impl AsRef<Path>) -> VResult<Self> {
        let dir = storage_dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).map_err(|e| {
            VNetworkError::Storage(format!(
                "failed creating durable equivocation store directory {:?}: {e}",
                dir
            ))
        })?;
        let lock = Arc::new(EquivocationLockGuard::acquire(&dir)?);
        let votes_wal_path = dir.join("equivocation_votes.wal");
        let evidence_wal_path = dir.join("equivocation_evidence.wal");
        let incidents_wal_path = dir.join("equivocation_incidents.wal");

        let mut store = Self {
            storage_dir: dir,
            votes_wal_path,
            evidence_wal_path,
            incidents_wal_path,
            _lock: lock,
            slots: BTreeMap::new(),
            evidence: Vec::new(),
            incidents: Vec::new(),
        };
        store.reload_strict()?;
        Ok(store)
    }

    fn read_and_verify_from_disk(
        votes_wal_path: &Path,
        evidence_wal_path: &Path,
        incidents_wal_path: &Path,
    ) -> VResult<(
        BTreeMap<String, PersistedVoteRecord>,
        Vec<EquivocationEvidence>,
        Vec<SigningConflictIncident>,
    )> {
        let mut slots: BTreeMap<String, PersistedVoteRecord> = BTreeMap::new();
        if votes_wal_path.exists() {
            let file = File::open(votes_wal_path).map_err(|e| {
                VNetworkError::Storage(format!("open equivocation_votes.wal failed: {e}"))
            })?;
            let reader = BufReader::new(file);
            for (idx, line) in reader.lines().enumerate() {
                let line = line.map_err(|e| VNetworkError::Storage(e.to_string()))?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let rec: PersistedVoteRecord = serde_json::from_str(trimmed).map_err(|e| {
                    VNetworkError::Storage(format!(
                        "corrupt equivocation_votes.wal line {}: {e}",
                        idx + 1
                    ))
                })?;
                rec.verify_integrity()?;
                if let Some(prev) = slots.get(&rec.slot_id) {
                    if votes_conflict(
                        &prev.proposal_id,
                        &prev.proposal_digest,
                        &prev.post_state_root,
                        &prev.validator_set_hash,
                        &prev.consensus_parameters_hash,
                        &prev.parent_commitment,
                        prev.approve,
                        &rec.proposal_id,
                        &rec.proposal_digest,
                        &rec.post_state_root,
                        &rec.validator_set_hash,
                        &rec.consensus_parameters_hash,
                        &rec.parent_commitment,
                        rec.approve,
                    ) {
                        return Err(VNetworkError::Storage(format!(
                            "equivocation_votes.wal corruption: conflicting proposals in same slot {}",
                            rec.slot_id
                        )));
                    }
                    // Allow IntentPending -> Signed upgrade or idempotent Signed repeat
                    if prev.status == PersistedVoteStatus::Signed
                        && rec.status == PersistedVoteStatus::IntentPending
                    {
                        continue;
                    }
                }
                slots.insert(rec.slot_id.clone(), rec);
            }
        }

        let mut evidence = Vec::new();
        if evidence_wal_path.exists() {
            let file = File::open(evidence_wal_path).map_err(|e| {
                VNetworkError::Storage(format!("open equivocation_evidence.wal failed: {e}"))
            })?;
            let reader = BufReader::new(file);
            for (idx, line) in reader.lines().enumerate() {
                let line = line.map_err(|e| VNetworkError::Storage(e.to_string()))?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let ev: EquivocationEvidence = serde_json::from_str(trimmed).map_err(|e| {
                    VNetworkError::Storage(format!(
                        "corrupt equivocation_evidence.wal line {}: {e}",
                        idx + 1
                    ))
                })?;
                ev.verify_cryptographic_conflict().map_err(|e| {
                    VNetworkError::Storage(format!(
                        "corrupt equivocation_evidence.wal line {}: {e}",
                        idx + 1
                    ))
                })?;
                evidence.push(ev);
            }
        }

        let mut incidents = Vec::new();
        if incidents_wal_path.exists() {
            let file = File::open(incidents_wal_path).map_err(|e| {
                VNetworkError::Storage(format!("open equivocation_incidents.wal failed: {e}"))
            })?;
            let reader = BufReader::new(file);
            for (idx, line) in reader.lines().enumerate() {
                let line = line.map_err(|e| VNetworkError::Storage(e.to_string()))?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let inc: SigningConflictIncident = serde_json::from_str(trimmed).map_err(|e| {
                    VNetworkError::Storage(format!(
                        "corrupt equivocation_incidents.wal line {}: {e}",
                        idx + 1
                    ))
                })?;
                incidents.push(inc);
            }
        }

        Ok((slots, evidence, incidents))
    }

    pub fn reload_strict(&mut self) -> VResult<()> {
        let (slots, evidence, incidents) = Self::read_and_verify_from_disk(
            &self.votes_wal_path,
            &self.evidence_wal_path,
            &self.incidents_wal_path,
        )?;
        self.slots = slots;
        self.evidence = evidence;
        self.incidents = incidents;
        Ok(())
    }

    /// Full content-and-cryptographic health comparison between in-memory state and on-disk WALs.
    pub fn check_health(&self) -> VResult<()> {
        let (disk_slots, disk_evidence, disk_incidents) = Self::read_and_verify_from_disk(
            &self.votes_wal_path,
            &self.evidence_wal_path,
            &self.incidents_wal_path,
        )?;
        if disk_slots != self.slots {
            return Err(VNetworkError::Storage(
                "in-memory equivocation slot map diverged from disk WAL contents".to_string(),
            ));
        }
        if disk_evidence != self.evidence {
            return Err(VNetworkError::Storage(
                "in-memory equivocation evidence log diverged from disk WAL contents".to_string(),
            ));
        }
        if disk_incidents != self.incidents {
            return Err(VNetworkError::Storage(
                "in-memory signing conflict incidents diverged from disk WAL contents".to_string(),
            ));
        }
        Ok(())
    }

    pub fn storage_dir(&self) -> &Path {
        &self.storage_dir
    }

    pub fn evidence(&self) -> &[EquivocationEvidence] {
        &self.evidence
    }

    pub fn incidents(&self) -> &[SigningConflictIncident] {
        &self.incidents
    }

    pub fn recorded_slots_count(&self) -> usize {
        self.slots.len()
    }

    fn append_vote_record_fsync(&self, record: &PersistedVoteRecord) -> VResult<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.votes_wal_path)
            .map_err(|e| {
                VNetworkError::Storage(format!("open equivocation_votes.wal failed: {e}"))
            })?;
        let line = serde_json::to_string(record)
            .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
        writeln!(file, "{line}").map_err(|e| {
            VNetworkError::Storage(format!("write equivocation_votes.wal failed: {e}"))
        })?;
        file.sync_all().map_err(|e| {
            VNetworkError::Storage(format!("fsync equivocation_votes.wal failed: {e}"))
        })?;
        Ok(())
    }

    fn append_evidence_fsync(&mut self, ev: EquivocationEvidence) -> VResult<()> {
        ev.verify_cryptographic_conflict()?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.evidence_wal_path)
            .map_err(|e| {
                VNetworkError::Storage(format!("open equivocation_evidence.wal failed: {e}"))
            })?;
        let line =
            serde_json::to_string(&ev).map_err(|e| VNetworkError::Serialization(e.to_string()))?;
        writeln!(file, "{line}").map_err(|e| {
            VNetworkError::Storage(format!("write equivocation_evidence.wal failed: {e}"))
        })?;
        file.sync_all().map_err(|e| {
            VNetworkError::Storage(format!("fsync equivocation_evidence.wal failed: {e}"))
        })?;
        self.evidence.push(ev);
        Ok(())
    }

    fn append_incident_fsync(&mut self, inc: SigningConflictIncident) -> VResult<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.incidents_wal_path)
            .map_err(|e| {
                VNetworkError::Storage(format!("open equivocation_incidents.wal failed: {e}"))
            })?;
        let line =
            serde_json::to_string(&inc).map_err(|e| VNetworkError::Serialization(e.to_string()))?;
        writeln!(file, "{line}").map_err(|e| {
            VNetworkError::Storage(format!("write equivocation_incidents.wal failed: {e}"))
        })?;
        file.sync_all().map_err(|e| {
            VNetworkError::Storage(format!("fsync equivocation_incidents.wal failed: {e}"))
        })?;
        self.incidents.push(inc);
        Ok(())
    }

    /// Strict fail-closed durable anti-equivocation sequence:
    /// 1. Validate validator membership and signer key identity
    /// 2. Validate full proposal digest and metadata
    /// 3. Check durable store before signing:
    ///    - Reject any conflicting proposal at `(network_id, genesis_commitment, validator_id, pubkey_fingerprint, epoch, height, round, vote_phase, protocol_version)`
    ///    - Return identical signed vote if idempotent exact retry after already completing
    /// 4. Persist & fsync `IntentPending` record BEFORE calling `signer.sign(...)`
    /// 5. Invoke `signer.sign(...)` and verify produced signature
    /// 6. Persist & fsync `Signed` record BEFORE returning the vote for broadcast
    pub fn sign_vote_safely(
        &mut self,
        validator: &ConsensusValidator,
        signer: &dyn SigningProvider,
        proposal: &ConsensusProposal,
        approve: bool,
        vote_phase: VotePhase,
        timestamp_ms: u64,
    ) -> VResult<ConsensusVote> {
        self.sign_vote_safely_with_failpoint(
            validator,
            signer,
            proposal,
            approve,
            vote_phase,
            timestamp_ms,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_vote_safely_with_failpoint(
        &mut self,
        validator: &ConsensusValidator,
        signer: &dyn SigningProvider,
        proposal: &ConsensusProposal,
        approve: bool,
        vote_phase: VotePhase,
        timestamp_ms: u64,
        fail_after_intent_before_sign: bool,
    ) -> VResult<ConsensusVote> {
        if !validator.active || validator.weight == 0 {
            return Err(VNetworkError::Consensus(format!(
                "validator `{}` is inactive or zero-weight",
                validator.validator_id
            )));
        }
        let val_pk = validator.canonical_pubkey_bytes()?;
        let signer_pk = canonical_ed25519_pubkey_bytes(signer.public_key_hex())?;
        if val_pk != signer_pk {
            return Err(VNetworkError::Authorization(
                "signing provider public key does not match validator public key".to_string(),
            ));
        }

        proposal.verify_digest_and_metadata()?;

        let slot = VoteSlotKey::from_proposal(proposal, validator, vote_phase)?;
        let slot_id = slot.slot_id()?;

        let mut need_intent_write = true;
        if let Some(existing) = self.slots.get(&slot_id).cloned() {
            if votes_conflict(
                &existing.proposal_id,
                &existing.proposal_digest,
                &existing.post_state_root,
                &existing.validator_set_hash,
                &existing.consensus_parameters_hash,
                &existing.parent_commitment,
                existing.approve,
                &proposal.proposal_id,
                &proposal.proposal_digest,
                &proposal.post_state_root,
                &proposal.validator_set_hash,
                &proposal.consensus_parameters_hash,
                &proposal.parent_commitment,
                approve,
            ) {
                let incident = SigningConflictIncident {
                    classification: VoteEvidenceClassification::ConflictingSigningIntent,
                    network_id: proposal.network_id.clone(),
                    genesis_commitment: proposal.genesis_commitment.clone(),
                    protocol_version: proposal.protocol_version.clone(),
                    validator_id: validator.validator_id.clone(),
                    pubkey_fingerprint: slot.pubkey_fingerprint.clone(),
                    epoch: proposal.epoch,
                    height: proposal.height,
                    round: proposal.round,
                    vote_phase,
                    existing_proposal_id: existing.proposal_id.clone(),
                    existing_proposal_digest: existing.proposal_digest.clone(),
                    conflicting_proposal_id: proposal.proposal_id.clone(),
                    conflicting_proposal_digest: proposal.proposal_digest.clone(),
                    observed_vote: None,
                    reason: format!(
                        "local signing conflict refused against existing {:?} slot `{}`",
                        existing.status, existing.proposal_id
                    ),
                    detected_at_ms: timestamp_ms,
                };
                self.append_incident_fsync(incident)?;
                return Err(VNetworkError::Consensus(format!(
                    "equivocation refused: validator `{}` already committed slot (epoch={}, height={}, round={}, phase={}) to proposal `{}` (digest {})",
                    validator.validator_id,
                    proposal.epoch,
                    proposal.height,
                    proposal.round,
                    vote_phase.as_str(),
                    existing.proposal_id,
                    existing.proposal_digest
                )));
            }
            if existing.status == PersistedVoteStatus::Signed {
                if let Some(vote) = &existing.signed_vote {
                    return Ok(vote.clone());
                }
            }
            // Resuming exact-same proposal intent after crash between intent & sign
            need_intent_write = false;
        }

        if need_intent_write {
            let mut intent = PersistedVoteRecord {
                slot_id: slot_id.clone(),
                slot: slot.clone(),
                status: PersistedVoteStatus::IntentPending,
                proposal_id: proposal.proposal_id.clone(),
                proposal_digest: proposal.proposal_digest.clone(),
                validator_set_hash: proposal.validator_set_hash.clone(),
                consensus_parameters_hash: proposal.consensus_parameters_hash.clone(),
                parent_commitment: proposal.parent_commitment.clone(),
                pre_state_root: proposal.pre_state_root.clone(),
                post_state_root: proposal.post_state_root.clone(),
                operation_scope: proposal.operation_scope.clone(),
                approve,
                recorded_at_ms: timestamp_ms,
                signed_vote: None,
                record_hash: String::new(),
            };
            intent.record_hash = intent.compute_record_hash()?;
            self.append_vote_record_fsync(&intent)?;
            self.slots.insert(slot_id.clone(), intent);
        }

        if fail_after_intent_before_sign {
            return Err(VNetworkError::Storage(
                "simulated crash after persisting vote signing intent".to_string(),
            ));
        }

        let mut vote = ConsensusVote {
            proposal_id: proposal.proposal_id.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            network_id: proposal.network_id.clone(),
            genesis_commitment: proposal.genesis_commitment.clone(),
            protocol_version: proposal.protocol_version.clone(),
            height: proposal.height,
            round: proposal.round,
            epoch: proposal.epoch,
            validator_set_hash: proposal.validator_set_hash.clone(),
            consensus_parameters_hash: proposal.consensus_parameters_hash.clone(),
            parent_commitment: proposal.parent_commitment.clone(),
            pre_state_root: proposal.pre_state_root.clone(),
            post_state_root: proposal.post_state_root.clone(),
            operation_scope: proposal.operation_scope.clone(),
            vote_phase,
            validator_id: validator.validator_id.clone(),
            validator_pubkey_hex: validator.validator_pubkey_hex.clone(),
            approve,
            timestamp_ms,
            signature: String::new(),
        };
        let bytes = vote.canonical_signing_bytes()?;
        vote.signature = signer.sign(&bytes)?;
        vote.verify(validator)?;

        let mut signed_rec = PersistedVoteRecord {
            slot_id: slot_id.clone(),
            slot,
            status: PersistedVoteStatus::Signed,
            proposal_id: proposal.proposal_id.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            validator_set_hash: proposal.validator_set_hash.clone(),
            consensus_parameters_hash: proposal.consensus_parameters_hash.clone(),
            parent_commitment: proposal.parent_commitment.clone(),
            pre_state_root: proposal.pre_state_root.clone(),
            post_state_root: proposal.post_state_root.clone(),
            operation_scope: proposal.operation_scope.clone(),
            approve,
            recorded_at_ms: timestamp_ms,
            signed_vote: Some(vote.clone()),
            record_hash: String::new(),
        };
        signed_rec.record_hash = signed_rec.compute_record_hash()?;
        self.append_vote_record_fsync(&signed_rec)?;
        self.slots.insert(slot_id, signed_rec);

        Ok(vote)
    }

    /// Record an observed vote after verifying historical membership, consensus parameters,
    /// optional proposal binding, and Ed25519 signature before any conflict/evidence persistence.
    pub fn record_verified_observed_vote(
        &mut self,
        membership: &ValidatorMembership,
        expected_proposal: Option<&ConsensusProposal>,
        vote: &ConsensusVote,
        timestamp_ms: u64,
    ) -> VResult<()> {
        if let Err(err) = (|| -> VResult<()> {
            let _val = verify_consensus_vote(membership, vote)?;
            let expected_vhash = membership.validator_set_hash()?;
            if vote.validator_set_hash != expected_vhash {
                return Err(VNetworkError::Consensus(format!(
                    "observed vote validator_set_hash `{}` != historical `{expected_vhash}`",
                    vote.validator_set_hash
                )));
            }
            let expected_params_hash = membership.consensus_parameters_hash()?;
            if vote.consensus_parameters_hash != expected_params_hash {
                return Err(VNetworkError::Consensus(format!(
                    "observed vote consensus_parameters_hash `{}` != historical `{expected_params_hash}`",
                    vote.consensus_parameters_hash
                )));
            }
            if let Some(prop) = expected_proposal {
                prop.verify_digest_and_metadata()?;
                if vote.proposal_id == prop.proposal_id
                    && (vote.proposal_digest != prop.proposal_digest
                        || vote.network_id != prop.network_id
                        || vote.genesis_commitment != prop.genesis_commitment
                        || vote.protocol_version != prop.protocol_version
                        || vote.height != prop.height
                        || vote.round != prop.round
                        || vote.epoch != prop.epoch)
                {
                    return Err(VNetworkError::Consensus(
                        "observed vote commitments diverge from expected proposal".to_string(),
                    ));
                }
            }
            Ok(())
        })() {
            let inc = SigningConflictIncident {
                classification: VoteEvidenceClassification::InvalidObservedVote,
                network_id: vote.network_id.clone(),
                genesis_commitment: vote.genesis_commitment.clone(),
                protocol_version: vote.protocol_version.clone(),
                validator_id: vote.validator_id.clone(),
                pubkey_fingerprint: pubkey_fingerprint(&vote.validator_pubkey_hex)
                    .unwrap_or_default(),
                epoch: vote.epoch,
                height: vote.height,
                round: vote.round,
                vote_phase: vote.vote_phase,
                existing_proposal_id: String::new(),
                existing_proposal_digest: String::new(),
                conflicting_proposal_id: vote.proposal_id.clone(),
                conflicting_proposal_digest: vote.proposal_digest.clone(),
                observed_vote: Some(vote.clone()),
                reason: format!("invalid observed vote failed membership/signature check: {err}"),
                detected_at_ms: timestamp_ms,
            };
            self.append_incident_fsync(inc)?;
            return Err(err);
        }
        self.record_observed_vote(vote, timestamp_ms)
    }

    pub fn record_observed_vote(&mut self, vote: &ConsensusVote, timestamp_ms: u64) -> VResult<()> {
        let slot = match verify_standalone_vote_signature_and_fields(vote) {
            Ok(s) => s,
            Err(err) => {
                let inc = SigningConflictIncident {
                    classification: VoteEvidenceClassification::InvalidObservedVote,
                    network_id: vote.network_id.clone(),
                    genesis_commitment: vote.genesis_commitment.clone(),
                    protocol_version: vote.protocol_version.clone(),
                    validator_id: vote.validator_id.clone(),
                    pubkey_fingerprint: pubkey_fingerprint(&vote.validator_pubkey_hex)
                        .unwrap_or_default(),
                    epoch: vote.epoch,
                    height: vote.height,
                    round: vote.round,
                    vote_phase: vote.vote_phase,
                    existing_proposal_id: String::new(),
                    existing_proposal_digest: String::new(),
                    conflicting_proposal_id: vote.proposal_id.clone(),
                    conflicting_proposal_digest: vote.proposal_digest.clone(),
                    observed_vote: Some(vote.clone()),
                    reason: format!(
                        "invalid observed vote rejected without creating evidence: {err}"
                    ),
                    detected_at_ms: timestamp_ms,
                };
                self.append_incident_fsync(inc)?;
                return Err(err);
            }
        };
        let slot_id = slot.slot_id()?;
        if let Some(prev) = self.slots.get(&slot_id).cloned() {
            if votes_conflict(
                &prev.proposal_id,
                &prev.proposal_digest,
                &prev.post_state_root,
                &prev.validator_set_hash,
                &prev.consensus_parameters_hash,
                &prev.parent_commitment,
                prev.approve,
                &vote.proposal_id,
                &vote.proposal_digest,
                &vote.post_state_root,
                &vote.validator_set_hash,
                &vote.consensus_parameters_hash,
                &vote.parent_commitment,
                vote.approve,
            ) {
                match prev.signed_vote {
                    Some(prev_vote) if prev.status == PersistedVoteStatus::Signed => {
                        let ev = EquivocationEvidence {
                            network_id: vote.network_id.clone(),
                            genesis_commitment: vote.genesis_commitment.clone(),
                            protocol_version: vote.protocol_version.clone(),
                            validator_id: vote.validator_id.clone(),
                            pubkey_fingerprint: slot.pubkey_fingerprint,
                            epoch: vote.epoch,
                            height: vote.height,
                            round: vote.round,
                            vote_phase: vote.vote_phase,
                            reason: format!(
                                "equivocation detected against durable signed vote `{}`",
                                prev.proposal_id
                            ),
                            vote_a: prev_vote,
                            vote_b: vote.clone(),
                            detected_at_ms: timestamp_ms,
                        };
                        self.append_evidence_fsync(ev)?;
                        return Err(VNetworkError::Consensus(format!(
                            "equivocation detected from validator `{}` at height {} round {}",
                            vote.validator_id, vote.height, vote.round
                        )));
                    }
                    _ => {
                        // Existing slot is an unsigned IntentPending reservation: preserve original intent
                        // and record a ConflictingSigningIntent incident WITHOUT fabricating an empty-sig vote.
                        let inc = SigningConflictIncident {
                            classification: VoteEvidenceClassification::ConflictingSigningIntent,
                            network_id: vote.network_id.clone(),
                            genesis_commitment: vote.genesis_commitment.clone(),
                            protocol_version: vote.protocol_version.clone(),
                            validator_id: vote.validator_id.clone(),
                            pubkey_fingerprint: slot.pubkey_fingerprint,
                            epoch: vote.epoch,
                            height: vote.height,
                            round: vote.round,
                            vote_phase: vote.vote_phase,
                            existing_proposal_id: prev.proposal_id.clone(),
                            existing_proposal_digest: prev.proposal_digest.clone(),
                            conflicting_proposal_id: vote.proposal_id.clone(),
                            conflicting_proposal_digest: vote.proposal_digest.clone(),
                            observed_vote: Some(vote.clone()),
                            reason: format!(
                                "observed signed vote `{}` conflicts with unsigned local IntentPending slot `{}`",
                                vote.proposal_id, prev.proposal_id
                            ),
                            detected_at_ms: timestamp_ms,
                        };
                        self.append_incident_fsync(inc)?;
                        return Err(VNetworkError::Consensus(format!(
                            "conflicting vote for validator `{}` against durable IntentPending slot `{}` at height {} round {}",
                            vote.validator_id, prev.proposal_id, vote.height, vote.round
                        )));
                    }
                }
            }
            return Ok(());
        }

        let mut rec = PersistedVoteRecord {
            slot_id: slot_id.clone(),
            slot,
            status: PersistedVoteStatus::Signed,
            proposal_id: vote.proposal_id.clone(),
            proposal_digest: vote.proposal_digest.clone(),
            validator_set_hash: vote.validator_set_hash.clone(),
            consensus_parameters_hash: vote.consensus_parameters_hash.clone(),
            parent_commitment: vote.parent_commitment.clone(),
            pre_state_root: vote.pre_state_root.clone(),
            post_state_root: vote.post_state_root.clone(),
            operation_scope: vote.operation_scope.clone(),
            approve: vote.approve,
            recorded_at_ms: timestamp_ms,
            signed_vote: Some(vote.clone()),
            record_hash: String::new(),
        };
        rec.record_hash = rec.compute_record_hash()?;
        self.append_vote_record_fsync(&rec)?;
        self.slots.insert(slot_id, rec);
        Ok(())
    }
}
