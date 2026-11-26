use crate::consensus_gate::{verify_membership_chain_from_genesis, verify_quorum_certificate_strict};
use crate::events::verify_event_chain;
use crate::state::{GenesisConfig, NetworkLedgerState, StateSnapshot, ValidatorEpochTransition};
use crate::supply::verify_token_supply_conservation;
use serde::{Deserialize, Serialize};
use vnetwork_types::*;

pub fn create_snapshot(state: &mut NetworkLedgerState, timestamp_ms: u64) -> VResult<StateSnapshot> {
    let state_root = state.compute_state_root()?;
    let replay_hash = state.compute_replay_hash();
    let seed = format!(
        "{}:{}:{}:{}",
        state.network_id, state.height, state.logical_clock, state_root
    );
    let snapshot_id = format!("snap_{}", &blake3_hex(seed.as_bytes())[..20]);
    let snap = StateSnapshot {
        snapshot_id,
        height: state.height,
        logical_clock: state.logical_clock,
        state_root,
        replay_hash,
        event_count: state.events.len(),
        created_at_ms: timestamp_ms,
    };
    state.snapshots.push(snap.clone());
    Ok(snap)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertifiedCheckpoint {
    pub checkpoint_version: u16,
    pub checkpoint_id: String,
    pub network_id: String,
    pub genesis_commitment: String,
    pub protocol_version: String,
    pub height: u64,
    pub proposal_digest: String,
    pub parent_commitment: String,
    pub state_root: String,
    pub event_history_root: String,
    pub validator_set_epoch: u64,
    pub validator_set_hash: String,
    pub quorum_certificate: QuorumCertificate,
    #[serde(default)]
    pub validator_epoch_chain: Vec<ValidatorEpochTransition>,
    pub state: NetworkLedgerState,
    pub created_at_ms: u64,
}

impl CertifiedCheckpoint {
    pub fn build(
        state: &NetworkLedgerState,
        latest_qc: &QuorumCertificate,
        proposal_digest: &str,
        parent_commitment: &str,
        timestamp_ms: u64,
    ) -> VResult<Self> {
        if state.height == 0 {
            return Err(VNetworkError::Consensus(
                "cannot create certified checkpoint at genesis height 0 without finalized QC"
                    .to_string(),
            ));
        }
        let state_root = state.compute_state_root()?;
        let event_history_root = state.compute_event_history_root();
        let validator_set_hash = validate_validator_set(&state.validators)?;
        let checkpoint_seed = serde_json::json!({
            "checkpoint_version": CHECKPOINT_VERSION,
            "domain": DOM_CHECKPOINT_V1,
            "event_history_root": event_history_root,
            "genesis_commitment": state.genesis_commitment,
            "height": state.height,
            "network_id": state.network_id,
            "parent_commitment": parent_commitment,
            "proposal_digest": proposal_digest,
            "protocol_version": state.protocol_version,
            "qc_id": latest_qc.certificate_id,
            "state_root": state_root,
            "validator_set_epoch": state.validator_epoch,
            "validator_set_hash": validator_set_hash,
        });
        let digest = blake3_hex(&canonical_json_bytes(&checkpoint_seed)?);
        let checkpoint_id = format!("ckpt_{}_{}", state.height, digest);
        Ok(Self {
            checkpoint_version: CHECKPOINT_VERSION,
            checkpoint_id,
            network_id: state.network_id.clone(),
            genesis_commitment: state.genesis_commitment.clone(),
            protocol_version: state.protocol_version.clone(),
            height: state.height,
            proposal_digest: proposal_digest.to_string(),
            parent_commitment: parent_commitment.to_string(),
            state_root,
            event_history_root,
            validator_set_epoch: state.validator_epoch,
            validator_set_hash,
            quorum_certificate: latest_qc.clone(),
            validator_epoch_chain: state.validator_membership_history.clone(),
            state: state.clone(),
            created_at_ms: timestamp_ms,
        })
    }

    pub fn verify(&self, genesis: &GenesisConfig) -> VResult<()> {
        if self.checkpoint_version != CHECKPOINT_VERSION {
            return Err(VNetworkError::Storage(format!(
                "unsupported checkpoint_version {}; expected {CHECKPOINT_VERSION}",
                self.checkpoint_version
            )));
        }
        genesis.validate()?;
        let expected_genesis_commitment = genesis.commitment_hash()?;
        if self.genesis_commitment != expected_genesis_commitment {
            return Err(VNetworkError::ProfileMismatch(format!(
                "checkpoint genesis_commitment `{}` != expected `{expected_genesis_commitment}`",
                self.genesis_commitment
            )));
        }
        if self.network_id != genesis.network_id || self.protocol_version != genesis.protocol_version {
            return Err(VNetworkError::ProfileMismatch(
                "checkpoint network_id or protocol_version does not match genesis".to_string(),
            ));
        }
        if self.state.network_id != genesis.network_id
            || self.state.profile != genesis.profile
            || self.state.protocol_version != genesis.protocol_version
            || self.state.genesis_commitment != expected_genesis_commitment
        {
            return Err(VNetworkError::ProfileMismatch(
                "checkpoint embedded ledger state metadata does not match genesis".to_string(),
            ));
        }
        if self.height == 0 || self.state.height != self.height {
            return Err(VNetworkError::Storage(format!(
                "checkpoint height mismatch: header {}, state {}",
                self.height, self.state.height
            )));
        }
        if self.proposal_digest.len() != 64 || self.parent_commitment.trim().is_empty() {
            return Err(VNetworkError::Storage(
                "checkpoint missing full proposal_digest or parent_commitment".to_string(),
            ));
        }

        // Verify genesis-rooted validator membership chain up to checkpoint epoch
        let proven_validators = verify_membership_chain_from_genesis(
            &genesis.initial_validators,
            &self.validator_epoch_chain,
            self.validator_set_epoch,
            &self.validator_set_hash,
            &self.state.validators,
        )?;

        // Verify QuorumCertificate against proven epoch validators and checkpoint commitments
        verify_quorum_certificate_strict(
            &self.quorum_certificate,
            &proven_validators,
            Some(&self.network_id),
            Some(&expected_genesis_commitment),
            Some(self.validator_set_epoch),
        )?;

        let qc = &self.quorum_certificate;
        if qc.height != self.height
            || qc.proposal_digest != self.proposal_digest
            || qc.parent_commitment != self.parent_commitment
            || qc.post_state_root != self.state_root
            || qc.validator_set_hash != self.validator_set_hash
            || qc.epoch != self.validator_set_epoch
        {
            return Err(VNetworkError::Consensus(
                "checkpoint quorum certificate does not match checkpoint commitments".to_string(),
            ));
        }

        // Verify deterministic state root, event history root, event hash chain, and supply invariants
        let computed_state_root = self.state.compute_state_root()?;
        if computed_state_root != self.state_root {
            return Err(VNetworkError::Storage(format!(
                "checkpoint state_root mismatch: expected {}, computed {computed_state_root}",
                self.state_root
            )));
        }
        let computed_event_root = self.state.compute_event_history_root();
        if computed_event_root != self.event_history_root {
            return Err(VNetworkError::Storage(format!(
                "checkpoint event_history_root mismatch: expected {}, computed {computed_event_root}",
                self.event_history_root
            )));
        }
        verify_event_chain(&self.state.events)?;
        for token_id in self.state.tokens.keys() {
            if !verify_token_supply_conservation(&self.state, token_id)? {
                return Err(VNetworkError::Storage(format!(
                    "checkpoint token `{token_id}` failed supply conservation check"
                )));
            }
        }
        Ok(())
    }
}
