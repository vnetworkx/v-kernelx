use crate::error::KernelXError;
use crate::record::VectorRecordV1;
use crate::state::now_ms;
use crate::wallet::verify_signature;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DEFAULT_QUORUM_BPS: u16 = 6667; // >= 2/3 supermajority

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusPolicy {
    pub min_auth_ratio: u16,
    pub require_certified: bool,
}

impl Default for ConsensusPolicy {
    fn default() -> Self {
        Self {
            min_auth_ratio: 700,
            require_certified: true,
        }
    }
}

/// Local admissibility filter preserved for compatibility with v0.1.4 engine callers.
pub fn accept_record(record: &VectorRecordV1, policy: &ConsensusPolicy) -> bool {
    if policy.require_certified && !record.certification.certified {
        return false;
    }
    record.certification.auth_ratio >= policy.min_auth_ratio
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorNode {
    pub node_id: String,
    pub public_key_hex: String,
    pub weight: u64,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventAttestation {
    pub event_hash: String,
    pub validator_id: String,
    pub validator_pubkey: String,
    pub vote_accept: bool,
    pub state_root_hash: String,
    pub signature: String,
    pub timestamp_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusRound {
    pub event_hash: String,
    pub total_weight: u64,
    pub approving_weight: u64,
    pub quorum_threshold_bps: u16,
    pub finalized: bool,
    pub attestations: Vec<EventAttestation>,
}

pub fn canonical_attestation_bytes(
    event_hash: &str,
    validator_id: &str,
    validator_pubkey: &str,
    vote_accept: bool,
    state_root_hash: &str,
    timestamp_ms: u64,
) -> Vec<u8> {
    let payload = serde_json::json!({
        "event_hash": event_hash,
        "state_root_hash": state_root_hash,
        "timestamp_ms": timestamp_ms,
        "validator_id": validator_id,
        "validator_pubkey": validator_pubkey,
        "vote_accept": vote_accept,
    });
    serde_json::to_vec(&payload).unwrap_or_default()
}

pub fn verify_attestation(
    attestation: &EventAttestation,
    validator: &ValidatorNode,
) -> Result<(), KernelXError> {
    if !validator.active {
        return Err(KernelXError::Rejected("validator is inactive".to_string()));
    }
    if attestation.validator_id != validator.node_id
        || attestation.validator_pubkey != validator.public_key_hex
    {
        return Err(KernelXError::Signature);
    }
    let bytes = canonical_attestation_bytes(
        &attestation.event_hash,
        &attestation.validator_id,
        &attestation.validator_pubkey,
        attestation.vote_accept,
        &attestation.state_root_hash,
        attestation.timestamp_ms,
    );
    verify_signature(&attestation.validator_pubkey, &bytes, &attestation.signature)
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct QuorumConsensusState {
    pub validators: BTreeMap<String, ValidatorNode>,
    pub attestations: BTreeMap<String, Vec<EventAttestation>>,
    pub quorum_threshold_bps: u16,
}

impl QuorumConsensusState {
    pub fn new(quorum_threshold_bps: u16) -> Self {
        Self {
            validators: BTreeMap::new(),
            attestations: BTreeMap::new(),
            quorum_threshold_bps: quorum_threshold_bps.clamp(5001, 10_000),
        }
    }

    pub fn register_validator(&mut self, validator: ValidatorNode) -> Result<(), KernelXError> {
        if validator.node_id.trim().is_empty() || validator.public_key_hex.trim().is_empty() {
            return Err(KernelXError::InvalidState(
                "validator node_id and public_key_hex are required".to_string(),
            ));
        }
        if validator.weight == 0 {
            return Err(KernelXError::InvalidState(
                "validator weight must be > 0".to_string(),
            ));
        }
        self.validators.insert(validator.node_id.clone(), validator);
        Ok(())
    }

    pub fn record_attestation(
        &mut self,
        attestation: EventAttestation,
    ) -> Result<ConsensusRound, KernelXError> {
        let validator = self
            .validators
            .get(&attestation.validator_id)
            .ok_or(KernelXError::WalletNotFound)?
            .clone();
        verify_attestation(&attestation, &validator)?;

        let list = self
            .attestations
            .entry(attestation.event_hash.clone())
            .or_default();
        if let Some(existing) = list
            .iter_mut()
            .find(|a| a.validator_id == attestation.validator_id)
        {
            *existing = attestation.clone();
        } else {
            list.push(attestation.clone());
        }

        Ok(self.evaluate_round(&attestation.event_hash))
    }

    pub fn evaluate_round(&self, event_hash: &str) -> ConsensusRound {
        let total_weight: u64 = self
            .validators
            .values()
            .filter(|v| v.active)
            .map(|v| v.weight)
            .sum();
        let attestations = self
            .attestations
            .get(event_hash)
            .cloned()
            .unwrap_or_default();
        let approving_weight: u64 = attestations
            .iter()
            .filter(|a| a.vote_accept)
            .filter_map(|a| self.validators.get(&a.validator_id))
            .filter(|v| v.active)
            .map(|v| v.weight)
            .sum();
        let threshold_bps = if self.quorum_threshold_bps == 0 {
            DEFAULT_QUORUM_BPS
        } else {
            self.quorum_threshold_bps
        };
        let finalized = total_weight > 0
            && (approving_weight as u128).saturating_mul(10_000)
                >= (total_weight as u128).saturating_mul(threshold_bps as u128);

        ConsensusRound {
            event_hash: event_hash.to_string(),
            total_weight,
            approving_weight,
            quorum_threshold_bps: threshold_bps,
            finalized,
            attestations,
        }
    }

    pub fn build_local_attestation(
        validator_id: impl Into<String>,
        validator_pubkey: impl Into<String>,
        event_hash: impl Into<String>,
        state_root_hash: impl Into<String>,
        vote_accept: bool,
        signature: impl Into<String>,
    ) -> EventAttestation {
        EventAttestation {
            event_hash: event_hash.into(),
            validator_id: validator_id.into(),
            validator_pubkey: validator_pubkey.into(),
            vote_accept,
            state_root_hash: state_root_hash.into(),
            signature: signature.into(),
            timestamp_ms: now_ms(),
        }
    }
}
