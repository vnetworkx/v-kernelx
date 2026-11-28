use crate::canonical::{blake3_hex, canonical_json_bytes};
use crate::error::{VNetworkError, VResult};
use crate::event::LedgerEvent;
use crate::identity::{canonical_ed25519_pubkey_bytes, pubkey_fingerprint, verify_ed25519};
use crate::protocol_version::{
    COMPILER_VERSION, DOM_CONSENSUS_PARAMS_V1, DOM_PROPOSAL_DIGEST_V1, DOM_PROPOSAL_SIGN_V1,
    DOM_QC_V1, DOM_VOTE_SIGN_V1, LANGUAGE_VERSION, PROPOSAL_VERSION, PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const DEFAULT_BFT_QUORUM_BPS: u16 = 6667; // 2/3+ supermajority (e.g. 3 of 4 validators)
pub const DEFAULT_CONSENSUS_ALGORITHM_VERSION: u16 = 1;
pub const DEFAULT_VALIDATOR_FAULT_ASSUMPTION: &str = "BFT_ONE_THIRD_F";

fn default_quorum_threshold_bps() -> u16 {
    DEFAULT_BFT_QUORUM_BPS
}

fn default_consensus_algorithm_version() -> u16 {
    DEFAULT_CONSENSUS_ALGORITHM_VERSION
}

fn default_fault_assumption() -> String {
    DEFAULT_VALIDATOR_FAULT_ASSUMPTION.to_string()
}

fn default_initial_region_auth_ratio_bps() -> u64 {
    0
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConsensusParameters {
    #[serde(default = "default_quorum_threshold_bps")]
    pub quorum_threshold_bps: u16,
    #[serde(default = "default_consensus_algorithm_version")]
    pub consensus_algorithm_version: u16,
    #[serde(default = "default_fault_assumption")]
    pub validator_fault_assumption: String,
    #[serde(default = "default_initial_region_auth_ratio_bps")]
    pub initial_region_auth_ratio_bps: u64,
}

impl Default for NetworkConsensusParameters {
    fn default() -> Self {
        Self {
            quorum_threshold_bps: DEFAULT_BFT_QUORUM_BPS,
            consensus_algorithm_version: DEFAULT_CONSENSUS_ALGORITHM_VERSION,
            validator_fault_assumption: DEFAULT_VALIDATOR_FAULT_ASSUMPTION.to_string(),
            initial_region_auth_ratio_bps: 0,
        }
    }
}

impl NetworkConsensusParameters {
    pub fn with_quorum_threshold_bps(quorum_threshold_bps: u16) -> VResult<Self> {
        let params = Self {
            quorum_threshold_bps,
            ..Self::default()
        };
        params.validate()?;
        Ok(params)
    }

    pub fn validate(&self) -> VResult<()> {
        if self.quorum_threshold_bps < DEFAULT_BFT_QUORUM_BPS || self.quorum_threshold_bps > 10_000 {
            return Err(VNetworkError::Consensus(format!(
                "invalid quorum_threshold_bps `{}`; must be within [{DEFAULT_BFT_QUORUM_BPS}..=10000]",
                self.quorum_threshold_bps
            )));
        }
        if self.consensus_algorithm_version != DEFAULT_CONSENSUS_ALGORITHM_VERSION {
            return Err(VNetworkError::Consensus(format!(
                "unsupported consensus_algorithm_version `{}`; expected {DEFAULT_CONSENSUS_ALGORITHM_VERSION}",
                self.consensus_algorithm_version
            )));
        }
        if self.validator_fault_assumption != DEFAULT_VALIDATOR_FAULT_ASSUMPTION {
            return Err(VNetworkError::Consensus(format!(
                "unsupported validator_fault_assumption `{}`; expected `{DEFAULT_VALIDATOR_FAULT_ASSUMPTION}`",
                self.validator_fault_assumption
            )));
        }
        if self.initial_region_auth_ratio_bps > 10_000 {
            return Err(VNetworkError::Consensus(format!(
                "invalid initial_region_auth_ratio_bps `{}`; must be <= 10000",
                self.initial_region_auth_ratio_bps
            )));
        }
        Ok(())
    }

    pub fn parameters_hash(&self) -> VResult<String> {
        self.validate()?;
        let obj = serde_json::json!({
            "consensus_algorithm_version": self.consensus_algorithm_version,
            "domain": DOM_CONSENSUS_PARAMS_V1,
            "initial_region_auth_ratio_bps": self.initial_region_auth_ratio_bps,
            "quorum_threshold_bps": self.quorum_threshold_bps,
            "validator_fault_assumption": self.validator_fault_assumption,
        });
        Ok(blake3_hex(&canonical_json_bytes(&obj)?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusVerificationContext {
    pub network_id: String,
    pub genesis_commitment: String,
    pub protocol_version: String,
    pub expected_epoch: Option<u64>,
    pub consensus_parameters: NetworkConsensusParameters,
    pub consensus_parameters_hash: String,
}

impl ConsensusVerificationContext {
    pub fn new(
        network_id: impl Into<String>,
        genesis_commitment: impl Into<String>,
        protocol_version: impl Into<String>,
        expected_epoch: Option<u64>,
        consensus_parameters: NetworkConsensusParameters,
    ) -> VResult<Self> {
        let network_id = network_id.into();
        let genesis_commitment = genesis_commitment.into();
        let protocol_version = protocol_version.into();
        if network_id.trim().is_empty() {
            return Err(VNetworkError::Consensus(
                "consensus verification context requires non-empty network_id".to_string(),
            ));
        }
        if genesis_commitment.len() != 64 || !genesis_commitment.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(VNetworkError::Consensus(
                "consensus verification context requires valid 64-hex genesis_commitment".to_string(),
            ));
        }
        if protocol_version != PROTOCOL_VERSION {
            return Err(VNetworkError::ProfileMismatch(format!(
                "consensus verification context protocol_version `{protocol_version}` != `{PROTOCOL_VERSION}`"
            )));
        }
        if let Some(epoch) = expected_epoch {
            if epoch == 0 {
                return Err(VNetworkError::Consensus(
                    "expected validator epoch must be >= 1".to_string(),
                ));
            }
        }
        let consensus_parameters_hash = consensus_parameters.parameters_hash()?;
        Ok(Self {
            network_id,
            genesis_commitment,
            protocol_version,
            expected_epoch,
            consensus_parameters,
            consensus_parameters_hash,
        })
    }

    pub fn for_epoch(&self, epoch: u64) -> VResult<Self> {
        if epoch == 0 {
            return Err(VNetworkError::Consensus(
                "validator epoch must be >= 1".to_string(),
            ));
        }
        let mut cloned = self.clone();
        cloned.expected_epoch = Some(epoch);
        Ok(cloned)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VotePhase {
    Prepare,
    PreCommit,
    #[default]
    Commit,
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
        if v.node_id.trim().is_empty() {
            return Err(VNetworkError::Consensus(format!(
                "validator `{}` has empty node_id",
                v.validator_id
            )));
        }
        if v.joined_epoch == 0 {
            return Err(VNetworkError::Consensus(format!(
                "validator `{}` joined_epoch must be >= 1",
                v.validator_id
            )));
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
    // Optional for wire compatibility with historical proposals; new proposals
    // must carry the actor's signature and bind it into the proposal digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submitter_signature: Option<String>,
}

impl ProgramSourceBundle {
    pub fn commitment_digest(&self) -> VResult<serde_json::Value> {
        let mut module_hashes = BTreeMap::new();
        for (path, src) in &self.resolved_module_sources {
            module_hashes.insert(path.clone(), blake3_hex(src.as_bytes()));
        }
        let mut commitment = serde_json::json!({
            "compiler_version": self.compiler_version,
            "compiled_program_hash": self.compiled_program_hash,
            "execution_params": self.execution_params,
            "file_name": self.file_name,
            "language_version": self.language_version,
            "module_hashes": module_hashes,
            "source_hash": self.source_hash,
        });
        if let Some(signature) = &self.submitter_signature {
            commitment["submitter_signature"] = serde_json::Value::String(signature.clone());
        }
        Ok(commitment)
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
    #[serde(default)]
    pub consensus_parameters_hash: String,
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
            "consensus_parameters_hash": self.consensus_parameters_hash,
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
        if self.consensus_parameters_hash.len() != 64
            || !self
                .consensus_parameters_hash
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        {
            return Err(VNetworkError::Consensus(
                "proposal missing valid 64-hex consensus_parameters_hash".to_string(),
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
            "consensus_parameters_hash": self.consensus_parameters_hash,
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
    pub consensus_parameters_hash: String,
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
            "consensus_parameters_hash": self.consensus_parameters_hash,
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
        if self.consensus_parameters_hash.len() != 64
            || !self
                .consensus_parameters_hash
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        {
            return Err(VNetworkError::Consensus(
                "vote missing valid 64-hex consensus_parameters_hash".to_string(),
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
    pub consensus_parameters_hash: String,
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
        let mut seen_validators = BTreeSet::new();
        let mut seen_pubkeys: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut vote_sigs: Vec<(String, String, String)> = Vec::with_capacity(self.votes.len());

        for v in &self.votes {
            if v.validator_id.trim().is_empty() {
                return Err(VNetworkError::Consensus(
                    "QC vote has empty validator_id".to_string(),
                ));
            }
            if !seen_validators.insert(v.validator_id.clone()) {
                return Err(VNetworkError::Consensus(format!(
                    "duplicate validator_id `{}` in QC certificate_digest",
                    v.validator_id
                )));
            }
            let pk_bytes = canonical_ed25519_pubkey_bytes(&v.validator_pubkey_hex)?;
            if !seen_pubkeys.insert(pk_bytes) {
                return Err(VNetworkError::Consensus(format!(
                    "duplicate canonical public key in QC certificate_digest for `{}`",
                    v.validator_id
                )));
            }
            vote_sigs.push((
                v.validator_id.clone(),
                hex::encode(pk_bytes),
                v.signature.clone(),
            ));
        }
        vote_sigs.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        let obj = serde_json::json!({
            "approving_weight": self.approving_weight,
            "consensus_parameters_hash": self.consensus_parameters_hash,
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

    pub fn compute_certificate_id(&self) -> VResult<String> {
        let digest = self.certificate_digest()?;
        Ok(format!("qc_{}_{}", self.height, &digest[..32]))
    }

    pub fn finalize_certificate_id(&mut self) -> VResult<()> {
        self.votes.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
        self.certificate_id = self.compute_certificate_id()?;
        Ok(())
    }

    pub fn verify_certificate_id(&self) -> VResult<()> {
        let expected = self.compute_certificate_id()?;
        if self.certificate_id != expected {
            return Err(VNetworkError::Consensus(format!(
                "QC certificate_id `{}` is not canonically derived from QC payload `{expected}`",
                self.certificate_id
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VoteEvidenceClassification {
    InvalidObservedVote,
    LocalSigningIntent,
    ConflictingSigningIntent,
    ValidSignedVote,
    ProvenEquivocation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningConflictIncident {
    pub classification: VoteEvidenceClassification,
    pub network_id: String,
    pub genesis_commitment: String,
    pub protocol_version: String,
    pub validator_id: String,
    pub pubkey_fingerprint: String,
    pub epoch: u64,
    pub height: u64,
    pub round: u64,
    pub vote_phase: VotePhase,
    pub existing_proposal_id: String,
    pub existing_proposal_digest: String,
    pub conflicting_proposal_id: String,
    pub conflicting_proposal_digest: String,
    #[serde(default)]
    pub observed_vote: Option<ConsensusVote>,
    pub reason: String,
    pub detected_at_ms: u64,
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

impl EquivocationEvidence {
    /// Verifies that this evidence proves genuine cryptographic double-signing:
    /// two distinct, validly signed votes by the same validator in the same signing slot
    /// with conflicting vote commitments. Unsigned intents or malformed votes cannot be
    /// promoted to `ProvenEquivocation`.
    pub fn verify_cryptographic_conflict(&self) -> VResult<()> {
        if self.network_id.trim().is_empty()
            || self.genesis_commitment.trim().is_empty()
            || self.protocol_version.trim().is_empty()
            || self.validator_id.trim().is_empty()
            || self.pubkey_fingerprint.trim().is_empty()
        {
            return Err(VNetworkError::Consensus(
                "equivocation evidence missing required network/validator binding metadata"
                    .to_string(),
            ));
        }
        for (label, v) in [("vote_a", &self.vote_a), ("vote_b", &self.vote_b)] {
            if v.signature.trim().is_empty() {
                return Err(VNetworkError::Consensus(format!(
                    "equivocation evidence {label} has empty signature (not cryptographically signed)"
                )));
            }
            if v.network_id != self.network_id
                || v.genesis_commitment != self.genesis_commitment
                || v.protocol_version != self.protocol_version
                || v.validator_id != self.validator_id
                || v.epoch != self.epoch
                || v.height != self.height
                || v.round != self.round
                || v.vote_phase != self.vote_phase
            {
                return Err(VNetworkError::Consensus(format!(
                    "equivocation evidence {label} does not match slot binding metadata"
                )));
            }
            let fp = pubkey_fingerprint(&v.validator_pubkey_hex)?;
            if fp != self.pubkey_fingerprint {
                return Err(VNetworkError::Consensus(format!(
                    "equivocation evidence {label} public key fingerprint mismatch"
                )));
            }
            let bytes = v.canonical_signing_bytes()?;
            verify_ed25519(&v.validator_pubkey_hex, &bytes, &v.signature)?;
        }

        let conflicts = self.vote_a.proposal_id != self.vote_b.proposal_id
            || self.vote_a.proposal_digest != self.vote_b.proposal_digest
            || self.vote_a.post_state_root != self.vote_b.post_state_root
            || self.vote_a.validator_set_hash != self.vote_b.validator_set_hash
            || self.vote_a.consensus_parameters_hash != self.vote_b.consensus_parameters_hash
            || self.vote_a.parent_commitment != self.vote_b.parent_commitment
            || self.vote_a.approve != self.vote_b.approve;
        if !conflicts {
            return Err(VNetworkError::Consensus(
                "equivocation evidence vote_a and vote_b do not conflict".to_string(),
            ));
        }
        Ok(())
    }
}
