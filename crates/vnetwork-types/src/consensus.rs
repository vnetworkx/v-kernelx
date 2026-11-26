use crate::canonical::canonical_json_bytes;
use crate::error::VResult;
use crate::event::LedgerEvent;
use crate::identity::verify_ed25519;
use serde::{Deserialize, Serialize};

pub const DEFAULT_BFT_QUORUM_BPS: u16 = 6667; // 2/3+ supermajority (e.g. 3 of 4 validators)

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusValidator {
    pub validator_id: String,
    pub node_id: String,
    pub validator_pubkey_hex: String,
    pub weight: u64,
    pub active: bool,
    pub joined_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusProposal {
    pub proposal_id: String,
    pub network_id: String,
    pub height: u64,
    pub round: u64,
    pub epoch: u64,
    pub proposer_validator_id: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub events: Vec<LedgerEvent>,
    pub program_id: Option<String>,
    pub tx_id: Option<String>,
    pub program_source_bundle: Option<ProgramSourceBundle>,
    #[serde(default)]
    pub nonce_binding: Option<(String, String, u64)>,
    pub timestamp_ms: u64,
    pub proposer_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramSourceBundle {
    pub file_name: String,
    pub source_bytes: String,
    pub source_hash: String,
    pub compiled_program_hash: String,
    pub resolved_module_sources: std::collections::BTreeMap<String, String>,
}

impl ConsensusProposal {
    pub fn canonical_signing_bytes(&self) -> VResult<Vec<u8>> {
        let event_hashes: Vec<&str> = self.events.iter().map(|e| e.event_hash.as_str()).collect();
        let obj = serde_json::json!({
            "epoch": self.epoch,
            "event_hashes": event_hashes,
            "height": self.height,
            "network_id": self.network_id,
            "post_state_root": self.post_state_root,
            "pre_state_root": self.pre_state_root,
            "program_id": self.program_id,
            "proposal_id": self.proposal_id,
            "proposer_validator_id": self.proposer_validator_id,
            "round": self.round,
            "timestamp_ms": self.timestamp_ms,
            "tx_id": self.tx_id,
        });
        canonical_json_bytes(&obj)
    }

    pub fn verify_proposer_signature(&self, validator: &ConsensusValidator) -> VResult<()> {
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
    pub network_id: String,
    pub height: u64,
    pub round: u64,
    pub epoch: u64,
    pub validator_id: String,
    pub validator_pubkey_hex: String,
    pub approve: bool,
    pub post_state_root: String,
    pub timestamp_ms: u64,
    pub signature: String,
}

impl ConsensusVote {
    pub fn canonical_signing_bytes(&self) -> VResult<Vec<u8>> {
        let obj = serde_json::json!({
            "approve": self.approve,
            "epoch": self.epoch,
            "height": self.height,
            "network_id": self.network_id,
            "post_state_root": self.post_state_root,
            "proposal_id": self.proposal_id,
            "round": self.round,
            "timestamp_ms": self.timestamp_ms,
            "validator_id": self.validator_id,
            "validator_pubkey_hex": self.validator_pubkey_hex,
        });
        canonical_json_bytes(&obj)
    }

    pub fn verify(&self, validator: &ConsensusValidator) -> VResult<()> {
        if !validator.active || validator.validator_id != self.validator_id {
            return Err(crate::error::VNetworkError::Consensus(
                "validator inactive or mismatched".to_string(),
            ));
        }
        if validator.validator_pubkey_hex != self.validator_pubkey_hex {
            return Err(crate::error::VNetworkError::Signature(
                "validator pubkey mismatch".to_string(),
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
    pub network_id: String,
    pub height: u64,
    pub round: u64,
    pub epoch: u64,
    pub post_state_root: String,
    pub event_hashes: Vec<String>,
    pub total_weight: u64,
    pub approving_weight: u64,
    pub quorum_threshold_bps: u16,
    pub votes: Vec<ConsensusVote>,
    pub finalized_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    pub validator_id: String,
    pub height: u64,
    pub round: u64,
    pub vote_a: ConsensusVote,
    pub vote_b: ConsensusVote,
    pub detected_at_ms: u64,
}
