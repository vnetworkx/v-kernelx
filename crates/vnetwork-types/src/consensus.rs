use crate::canonical::{blake3_hex, canonical_json_bytes};
use crate::error::{VNetworkError, VResult};
use crate::event::LedgerEvent;
use crate::identity::{canonical_ed25519_pubkey_bytes, pubkey_fingerprint, verify_ed25519};
use crate::protocol_version::{
    COMPILER_VERSION, DOM_PROPOSAL_DIGEST_V1, DOM_PROPOSAL_SIGN_V1, DOM_QC_V1, DOM_VOTE_SIGN_V1,
    LANGUAGE_VERSION, PROPOSAL_VERSION, PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const DEFAULT_BFT_QUORUM_BPS: u16 = 6667; // 2/3+ supermajority (e.g. 3 of 4 validators)

fn default_proposal_version() -> u16 {
    PROPOSAL_VERSION
}

fn default_protocol_version() -> String {
    PROTOCOL_VERSION.to_string()
}

fn default_language_version() -> String {
    LANGUAGE_VERSION.to_string()
}

fn default_compiler_version() -> String {
    COMPILER_VERSION.to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VotePhase {
    Prepare,
    PreCommit,
    Commit,
}

impl Default for VotePhase {
    fn default() -> Self {
        Self::Commit
    }
}

impl VotePhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            VotePhase::Prepare => "PREPARE",
            VotePhase::PreCommit => "PRE_COMMIT",
            VotePhase::Commit => "COMMIT",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusValidator {
    pub validator_id: String,
    pub node_id: String,
    pub validator_pubkey_hex: String,
    pub weight: u64,
    pub active: bool,
    pub joined_epoch: u64,
}

impl ConsensusValidator {
    pub fn canonical_pubkey_bytes(&self) -> VResult<[u8; 32]> {
        canonical_ed25519_pubkey_bytes(&self.validator_pubkey_hex)
    }

    pub fn pubkey_fingerprint(&self) -> VResult<String> {
        pubkey_fingerprint(&self.validator_pubkey_hex)
    }
}

pub fn validate_validator_set(validators: &[ConsensusValidator]) -> VResult<String> {
    if validators.is_empty() {
        return Err(VNetworkError::Consensus(
            "validator set cannot be empty".to_string(),
        ));
    }
    let mut seen_ids = BTreeSet::new();
    let mut seen_pubkeys: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut active_weight: u64 = 0;

    for v in validators {
        if v.validator_id.trim().is_empty() {
            return Err(VNetworkError::Consensus(
                "validator_id cannot be empty".to_string(),
            ));
        }
        if !seen_ids.insert(v.validator_id.clone()) {
            return Err(VNetworkError::Consensus(format!(
                "duplicate validator_id `{}` in validator set",
                v.validator_id
            )));
        }
        let pk_bytes = v.canonical_pubkey_bytes()?;
        if !seen_pubkeys.insert(pk_bytes) {
            return Err(VNetworkError::Consensus(format!(
                "duplicate canonical Ed25519 public key across distinct validator_id `{}`",
                v.validator_id
            )));
        }
        if v.active {
            if v.weight == 0 {
                return Err(VNetworkError::Consensus(format!(
                    "active validator `{}` cannot have zero weight",
                    v.validator_id
                )));
            }
            active_weight = active_weight.checked_add(v.weight).ok_or_else(|| {
                VNetworkError::Consensus("active validator weight overflow".to_string())
            })?;
        }
    }
    if active_weight == 0 {
        return Err(VNetworkError::Consensus(
            "no active validators with positive weight in validator set".to_string(),
        ));
    }
    compute_validator_set_hash(validators)
}

pub fn compute_validator_set_hash(validators: &[ConsensusValidator]) -> VResult<String> {
    let mut normalized: Vec<&ConsensusValidator> = validators.iter().collect();
    normalized.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
    let bytes = canonical_json_bytes(&normalized)?;
    Ok(blake3_hex(&bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramSourceBundle {
    pub file_name: String,
    pub source_bytes: String,
    pub source_hash: String,
    pub compiled_program_hash: String,
    pub resolved_module_sources: BTreeMap<String, String>,
    #[serde(default = "default_language_version")]
    pub language_version: String,
    #[serde(default = "default_compiler_version")]
    pub compiler_version: String,
    #[serde(default)]
    pub execution_params: BTreeMap<String, serde_json::Value>,
}

impl ProgramSourceBundle {
    pub fn commitment_digest(&self) -> VResult<serde_json::Value> {
        let mut module_hashes = BTreeMap::new();
        for (path, src) in &self.resolved_module_sources {
            module_hashes.insert(path.clone(), blake3_hex(src.as_bytes()));
        }
        Ok(serde_json::json!({
            "compiler_version": self.compiler_version,
            "compiled_program_hash": self.compiled_program_hash,
            "execution_params": self.execution_params,
            "file_name": self.file_name,
            "language_version": self.language_version,
            "module_hashes": module_hashes,
            "source_hash": self.source_hash,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusProposal {
    pub proposal_id: String,
    #[serde(default = "default_proposal_version")]
    pub proposal_version: u16,
    pub network_id: String,
    #[serde(default)]
    pub genesis_commitment: String,
    #[serde(default = "default_protocol_version")]
    pub protocol_version: String,
    pub height: u64,
    pub round: u64,
    pub epoch: u64,
    #[serde(default)]
    pub validator_set_hash: String,
    pub proposer_validator_id: String,
    #[serde(default)]
    pub parent_commitment: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    #[serde(default)]
    pub proposal_digest: String,
    #[serde(default)]
    pub operation_scope: String,
    pub events: Vec<LedgerEvent>,
    pub program_id: Option<String>,
    pub tx_id: Option<String>,
    pub program_source_bundle: Option<ProgramSourceBundle>,
    #[serde(default)]
    pub nonce_binding: Option<(String, String, u64)>,
    #[serde(default)]
    pub execution_params: BTreeMap<String, serde_json::Value>,
    pub timestamp_ms: u64,
    pub proposer_signature: String,
}

impl ConsensusProposal {
    pub fn ordered_event_ids(&self) -> Vec<String> {
        self.events.iter().map(|e| e.event_id.clone()).collect()
    }

    pub fn ordered_event_hashes(&self) -> Vec<String> {
        self.events.iter().map(|e| e.event_hash.clone()).collect()
    }

    pub fn compute_expected_digest(&self) -> VResult<String> {
        let event_ids: Vec<&str> = self.events.iter().map(|e| e.event_id.as_str()).collect();
        let event_hashes: Vec<&str> = self.events.iter().map(|e| e.event_hash.as_str()).collect();
        let source_commitment = match &self.program_source_bundle {
            Some(bundle) => Some(bundle.commitment_digest()?),
            None => None,
        };
        let obj = serde_json::json!({
            "domain": DOM_PROPOSAL_DIGEST_V1,
            "epoch": self.epoch,
            "event_hashes": event_hashes,
            "event_ids": event_ids,
            "execution_params": self.execution_params,
            "genesis_commitment": self.genesis_commitment,
            "height": self.height,
            "network_id": self.network_id,
            "nonce_binding": self.nonce_binding,
            "operation_scope": self.operation_scope,
            "parent_commitment": self.parent_commitment,
            "post_state_root": self.post_state_root,
            "pre_state_root": self.pre_state_root,
            "program_id": self.program_id,
            "program_source_commitment": source_commitment,
            "proposal_version": self.proposal_version,
            "proposer_validator_id": self.proposer_validator_id,
            "protocol_version": self.protocol_version,
            "round": self.round,
            "timestamp_ms": self.timestamp_ms,
            "tx_id": self.tx_id,
            "validator_set_hash": self.validator_set_hash,
        });
        Ok(blake3_hex(&canonical_json_bytes(&obj)?))
    }

    pub fn finalize_digest_and_id(&mut self) -> VResult<()> {
        let digest = self.compute_expected_digest()?;
        self.proposal_id = format!("prop_{}_{}", self.height, digest);
        self.proposal_digest = digest;
        Ok(())
    }

    pub fn verify_digest_and_metadata(&self) -> VResult<()> {
        if self.proposal_version != PROPOSAL_VERSION {
            return Err(VNetworkError::Consensus(format!(
                "unsupported proposal_version {}; expected {PROPOSAL_VERSION}",
                self.proposal_version
            )));
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(VNetworkError::Consensus(format!(
                "proposal protocol_version `{}` != expected `{PROTOCOL_VERSION}`",
                self.protocol_version
            )));
        }
        if self.network_id.trim().is_empty()
            || self.genesis_commitment.trim().is_empty()
            || self.validator_set_hash.trim().is_empty()
            || self.parent_commitment.trim().is_empty()
            || self.operation_scope.trim().is_empty()
        {
            return Err(VNetworkError::Consensus(
                "proposal missing mandatory network_id, genesis_commitment, validator_set_hash, parent_commitment, or operation_scope"
                    .to_string(),
            ));
        }
        let expected_digest = self.compute_expected_digest()?;
        if self.proposal_digest.len() != 64 || self.proposal_digest != expected_digest {
            return Err(VNetworkError::Consensus(format!(
                "proposal_digest mismatch: expected {expected_digest}, got {}",
                self.proposal_digest
            )));
        }
        let expected_id = format!("prop_{}_{}", self.height, expected_digest);
        if self.proposal_id != expected_id {
            return Err(VNetworkError::Consensus(format!(
                "proposal_id `{}` is not canonically derived from full proposal_digest `{expected_digest}`",
                self.proposal_id
            )));
        }
        Ok(())
    }

    pub fn canonical_signing_bytes(&self) -> VResult<Vec<u8>> {
        let event_ids: Vec<&str> = self.events.iter().map(|e| e.event_id.as_str()).collect();
        let event_hashes: Vec<&str> = self.events.iter().map(|e| e.event_hash.as_str()).collect();
        let source_commitment = match &self.program_source_bundle {
            Some(bundle) => Some(bundle.commitment_digest()?),
            None => None,
        };
        let obj = serde_json::json!({
            "domain": DOM_PROPOSAL_SIGN_V1,
            "epoch": self.epoch,
            "event_hashes": event_hashes,
            "event_ids": event_ids,
            "execution_params": self.execution_params,
            "genesis_commitment": self.genesis_commitment,
            "height": self.height,
            "network_id": self.network_id,
            "nonce_binding": self.nonce_binding,
            "operation_scope": self.operation_scope,
            "parent_commitment": self.parent_commitment,
            "post_state_root": self.post_state_root,
            "pre_state_root": self.pre_state_root,
            "program_id": self.program_id,
            "program_source_commitment": source_commitment,
            "proposal_digest": self.proposal_digest,
            "proposal_id": self.proposal_id,
            "proposal_version": self.proposal_version,
            "proposer_validator_id": self.proposer_validator_id,
            "protocol_version": self.protocol_version,
            "round": self.round,
            "timestamp_ms": self.timestamp_ms,
            "tx_id": self.tx_id,
            "validator_set_hash": self.validator_set_hash,
        });
        canonical_json_bytes(&obj)
    }

    pub fn verify_proposer_signature(&self, validator: &ConsensusValidator) -> VResult<()> {
        if !validator.active || validator.weight == 0 {
            return Err(VNetworkError::Consensus(format!(
                "proposer `{}` is inactive or zero-weight",
                validator.validator_id
            )));
        }
        self.verify_digest_and_metadata()?;
        let bytes = self.canonical_signing_bytes()?;
        verify_ed25519(
            &validator.validator_pubkey_hex,
            &bytes,
            &self.proposer_signature,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusVote {
    pub proposal_id: String,
    #[serde(default)]
    pub proposal_digest: String,
    pub network_id: String,
    #[serde(default)]
    pub genesis_commitment: String,
    #[serde(default = "default_protocol_version")]
    pub protocol_version: String,
    pub height: u64,
    pub round: u64,
    pub epoch: u64,
    #[serde(default)]
    pub validator_set_hash: String,
    #[serde(default)]
    pub parent_commitment: String,
    #[serde(default)]
    pub pre_state_root: String,
    pub post_state_root: String,
    #[serde(default)]
    pub operation_scope: String,
    #[serde(default)]
    pub vote_phase: VotePhase,
    pub validator_id: String,
    pub validator_pubkey_hex: String,
    pub approve: bool,
    pub timestamp_ms: u64,
    pub signature: String,
}

impl ConsensusVote {
    pub fn canonical_signing_bytes(&self) -> VResult<Vec<u8>> {
        let obj = serde_json::json!({
            "approve": self.approve,
            "domain": DOM_VOTE_SIGN_V1,
            "epoch": self.epoch,
            "genesis_commitment": self.genesis_commitment,
            "height": self.height,
            "network_id": self.network_id,
            "operation_scope": self.operation_scope,
            "parent_commitment": self.parent_commitment,
            "post_state_root": self.post_state_root,
            "pre_state_root": self.pre_state_root,
            "proposal_digest": self.proposal_digest,
            "proposal_id": self.proposal_id,
            "protocol_version": self.protocol_version,
            "round": self.round,
            "timestamp_ms": self.timestamp_ms,
            "validator_id": self.validator_id,
            "validator_pubkey_hex": self.validator_pubkey_hex,
            "validator_set_hash": self.validator_set_hash,
            "vote_phase": self.vote_phase,
        });
        canonical_json_bytes(&obj)
    }

    pub fn verify(&self, validator: &ConsensusValidator) -> VResult<()> {
        if !validator.active || validator.weight == 0 || validator.validator_id != self.validator_id
        {
            return Err(VNetworkError::Consensus(
                "validator inactive, zero-weight, or mismatched".to_string(),
            ));
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(VNetworkError::Consensus(format!(
                "vote protocol_version `{}` != `{PROTOCOL_VERSION}`",
                self.protocol_version
            )));
        }
        if self.network_id.trim().is_empty()
            || self.genesis_commitment.trim().is_empty()
            || self.proposal_digest.len() != 64
            || self.validator_set_hash.trim().is_empty()
            || self.parent_commitment.trim().is_empty()
            || self.operation_scope.trim().is_empty()
        {
            return Err(VNetworkError::Consensus(
                "vote missing required domain/proposal binding fields".to_string(),
            ));
        }
        let expected_pk = canonical_ed25519_pubkey_bytes(&validator.validator_pubkey_hex)?;
        let actual_pk = canonical_ed25519_pubkey_bytes(&self.validator_pubkey_hex)?;
        if expected_pk != actual_pk {
            return Err(VNetworkError::Signature(
                "validator canonical public key mismatch".to_string(),
            ));
        }
        let bytes = self.canonical_signing_bytes()?;
        verify_ed25519(&self.validator_pubkey_hex, &bytes, &self.signature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub certificate_id: String,
    pub proposal_id: String,
    #[serde(default)]
    pub proposal_digest: String,
    pub network_id: String,
    #[serde(default)]
    pub genesis_commitment: String,
    #[serde(default = "default_protocol_version")]
    pub protocol_version: String,
    pub height: u64,
    pub round: u64,
    pub epoch: u64,
    #[serde(default)]
    pub validator_set_hash: String,
    #[serde(default)]
    pub parent_commitment: String,
    #[serde(default)]
    pub pre_state_root: String,
    pub post_state_root: String,
    #[serde(default)]
    pub operation_scope: String,
    #[serde(default)]
    pub vote_phase: VotePhase,
    #[serde(default)]
    pub ordered_event_ids: Vec<String>,
    pub event_hashes: Vec<String>,
    pub total_weight: u64,
    pub approving_weight: u64,
    pub quorum_threshold_bps: u16,
    pub votes: Vec<ConsensusVote>,
    pub finalized_at_ms: u64,
}

impl QuorumCertificate {
    pub fn certificate_digest(&self) -> VResult<String> {
        let mut vote_sigs: Vec<(&str, &str, &str)> = self
            .votes
            .iter()
            .map(|v| {
                (
                    v.validator_id.as_str(),
                    v.validator_pubkey_hex.as_str(),
                    v.signature.as_str(),
                )
            })
            .collect();
        vote_sigs.sort_by(|a, b| a.0.cmp(b.0));
        let obj = serde_json::json!({
            "approving_weight": self.approving_weight,
            "certificate_id": self.certificate_id,
            "domain": DOM_QC_V1,
            "epoch": self.epoch,
            "event_hashes": self.event_hashes,
            "finalized_at_ms": self.finalized_at_ms,
            "genesis_commitment": self.genesis_commitment,
            "height": self.height,
            "network_id": self.network_id,
            "operation_scope": self.operation_scope,
            "ordered_event_ids": self.ordered_event_ids,
            "parent_commitment": self.parent_commitment,
            "post_state_root": self.post_state_root,
            "pre_state_root": self.pre_state_root,
            "proposal_digest": self.proposal_digest,
            "proposal_id": self.proposal_id,
            "protocol_version": self.protocol_version,
            "quorum_threshold_bps": self.quorum_threshold_bps,
            "round": self.round,
            "total_weight": self.total_weight,
            "validator_set_hash": self.validator_set_hash,
            "vote_phase": self.vote_phase,
            "vote_signatures": vote_sigs,
        });
        Ok(blake3_hex(&canonical_json_bytes(&obj)?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    #[serde(default)]
    pub network_id: String,
    #[serde(default)]
    pub genesis_commitment: String,
    #[serde(default = "default_protocol_version")]
    pub protocol_version: String,
    pub validator_id: String,
    #[serde(default)]
    pub pubkey_fingerprint: String,
    #[serde(default)]
    pub epoch: u64,
    pub height: u64,
    pub round: u64,
    #[serde(default)]
    pub vote_phase: VotePhase,
    #[serde(default)]
    pub reason: String,
    pub vote_a: ConsensusVote,
    pub vote_b: ConsensusVote,
    pub detected_at_ms: u64,
}
