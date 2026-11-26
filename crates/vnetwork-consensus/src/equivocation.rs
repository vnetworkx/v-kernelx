use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
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

fn votes_conflict(
    a_prop_id: &str,
    a_prop_digest: &str,
    a_post_root: &str,
    a_vset_hash: &str,
    a_parent: &str,
    a_approve: bool,
    b_prop_id: &str,
    b_prop_digest: &str,
    b_post_root: &str,
    b_vset_hash: &str,
    b_parent: &str,
    b_approve: bool,
) -> bool {
    a_prop_id != b_prop_id
        || a_prop_digest != b_prop_digest
        || a_post_root != b_post_root
        || a_vset_hash != b_vset_hash
        || a_parent != b_parent
        || a_approve != b_approve
}

#[derive(Debug, Default, Clone)]
pub struct EquivocationDetector {
    seen_votes: BTreeMap<String, ConsensusVote>,
    pub evidence: Vec<EquivocationEvidence>,
}

impl EquivocationDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check_and_record(
        &mut self,
        vote: &ConsensusVote,
        timestamp_ms: u64,
    ) -> Result<(), EquivocationEvidence> {
        let slot = match VoteSlotKey::from_vote(vote) {
            Ok(s) => s,
            Err(_) => {
                let ev = EquivocationEvidence {
                    network_id: vote.network_id.clone(),
                    genesis_commitment: vote.genesis_commitment.clone(),
                    protocol_version: vote.protocol_version.clone(),
                    validator_id: vote.validator_id.clone(),
                    pubkey_fingerprint: String::new(),
                    epoch: vote.epoch,
                    height: vote.height,
                    round: vote.round,
                    vote_phase: vote.vote_phase,
                    reason: "vote has invalid canonical public key for equivocation slot".to_string(),
                    vote_a: vote.clone(),
                    vote_b: vote.clone(),
                    detected_at_ms: timestamp_ms,
                };
                self.evidence.push(ev.clone());
                return Err(ev);
            }
        };
        let slot_id = slot.slot_id().unwrap_or_else(|_| {
            format!(
                "{}:{}:{}:{}:{}",
                slot.network_id, slot.validator_id, slot.epoch, slot.height, slot.round
            )
        });
        if let Some(prev) = self.seen_votes.get(&slot_id) {
            if votes_conflict(
                &prev.proposal_id,
                &prev.proposal_digest,
                &prev.post_state_root,
                &prev.validator_set_hash,
                &prev.parent_commitment,
                prev.approve,
                &vote.proposal_id,
                &vote.proposal_digest,
                &vote.post_state_root,
                &vote.validator_set_hash,
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
                    reason: "conflicting vote observed for same validator signing slot".to_string(),
                    vote_a: prev.clone(),
                    vote_b: vote.clone(),
                    detected_at_ms: timestamp_ms,
                };
                self.evidence.push(ev.clone());
                return Err(ev);
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
                || vote.post_state_root != self.post_state_root
                || vote.validator_id != self.slot.validator_id
                || vote.height != self.slot.height
                || vote.round != self.slot.round
                || vote.epoch != self.slot.epoch
            {
                return Err(VNetworkError::Storage(
                    "corrupt equivocation record: embedded signed_vote diverges from slot metadata"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// Durable fail-closed anti-equivocation store backed by fsynced WAL files inside `storage_path`.
#[derive(Debug, Clone)]
pub struct EquivocationStore {
    storage_dir: PathBuf,
    votes_wal_path: PathBuf,
    evidence_wal_path: PathBuf,
    slots: BTreeMap<String, PersistedVoteRecord>,
    evidence: Vec<EquivocationEvidence>,
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
        let votes_wal_path = dir.join("equivocation_votes.wal");
        let evidence_wal_path = dir.join("equivocation_evidence.wal");

        let mut store = Self {
            storage_dir: dir,
            votes_wal_path,
            evidence_wal_path,
            slots: BTreeMap::new(),
            evidence: Vec::new(),
        };
        store.reload_strict()?;
        Ok(store)
    }

    pub fn reload_strict(&mut self) -> VResult<()> {
        let mut slots: BTreeMap<String, PersistedVoteRecord> = BTreeMap::new();
        if self.votes_wal_path.exists() {
            let file = File::open(&self.votes_wal_path).map_err(|e| {
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
                        &prev.parent_commitment,
                        prev.approve,
                        &rec.proposal_id,
                        &rec.proposal_digest,
                        &rec.post_state_root,
                        &rec.validator_set_hash,
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
        if self.evidence_wal_path.exists() {
            let file = File::open(&self.evidence_wal_path).map_err(|e| {
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
                evidence.push(ev);
            }
        }

        self.slots = slots;
        self.evidence = evidence;
        Ok(())
    }

    pub fn check_health(&self) -> VResult<()> {
        let probe = Self::open(&self.storage_dir)?;
        if probe.slots.len() != self.slots.len() {
            return Err(VNetworkError::Storage(
                "in-memory equivocation slot map diverged from disk WAL".to_string(),
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
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.evidence_wal_path)
            .map_err(|e| {
                VNetworkError::Storage(format!("open equivocation_evidence.wal failed: {e}"))
            })?;
        let line = serde_json::to_string(&ev)
            .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
        writeln!(file, "{line}").map_err(|e| {
            VNetworkError::Storage(format!("write equivocation_evidence.wal failed: {e}"))
        })?;
        file.sync_all().map_err(|e| {
            VNetworkError::Storage(format!("fsync equivocation_evidence.wal failed: {e}"))
        })?;
        self.evidence.push(ev);
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
        if let Some(existing) = self.slots.get(&slot_id) {
            if votes_conflict(
                &existing.proposal_id,
                &existing.proposal_digest,
                &existing.post_state_root,
                &existing.validator_set_hash,
                &existing.parent_commitment,
                existing.approve,
                &proposal.proposal_id,
                &proposal.proposal_digest,
                &proposal.post_state_root,
                &proposal.validator_set_hash,
                &proposal.parent_commitment,
                approve,
            ) {
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

    pub fn record_observed_vote(
        &mut self,
        vote: &ConsensusVote,
        timestamp_ms: u64,
    ) -> VResult<()> {
        let slot = VoteSlotKey::from_vote(vote)?;
        let slot_id = slot.slot_id()?;
        if let Some(prev) = self.slots.get(&slot_id) {
            if votes_conflict(
                &prev.proposal_id,
                &prev.proposal_digest,
                &prev.post_state_root,
                &prev.validator_set_hash,
                &prev.parent_commitment,
                prev.approve,
                &vote.proposal_id,
                &vote.proposal_digest,
                &vote.post_state_root,
                &vote.validator_set_hash,
                &vote.parent_commitment,
                vote.approve,
            ) {
                let prev_vote = prev.signed_vote.clone().unwrap_or_else(|| ConsensusVote {
                    proposal_id: prev.proposal_id.clone(),
                    proposal_digest: prev.proposal_digest.clone(),
                    network_id: prev.slot.network_id.clone(),
                    genesis_commitment: prev.slot.genesis_commitment.clone(),
                    protocol_version: prev.slot.protocol_version.clone(),
                    height: prev.slot.height,
                    round: prev.slot.round,
                    epoch: prev.slot.epoch,
                    validator_set_hash: prev.validator_set_hash.clone(),
                    parent_commitment: prev.parent_commitment.clone(),
                    pre_state_root: prev.pre_state_root.clone(),
                    post_state_root: prev.post_state_root.clone(),
                    operation_scope: prev.operation_scope.clone(),
                    vote_phase: prev.slot.vote_phase,
                    validator_id: prev.slot.validator_id.clone(),
                    validator_pubkey_hex: vote.validator_pubkey_hex.clone(),
                    approve: prev.approve,
                    timestamp_ms: prev.recorded_at_ms,
                    signature: String::new(),
                });
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
                        "equivocation detected against durable slot record `{}`",
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
            return Ok(());
        }

        let mut rec = PersistedVoteRecord {
            slot_id: slot_id.clone(),
            slot,
            status: PersistedVoteStatus::Signed,
            proposal_id: vote.proposal_id.clone(),
            proposal_digest: vote.proposal_digest.clone(),
            validator_set_hash: vote.validator_set_hash.clone(),
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
