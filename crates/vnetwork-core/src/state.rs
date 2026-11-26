use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use vnetwork_types::*;

fn default_validator_epoch() -> u64 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub network_id: String,
    pub network_name: String,
    pub profile: NetworkProfile,
    pub protocol_version: String,
    pub genesis_timestamp_ms: u64,
    pub initial_validators: Vec<ConsensusValidator>,
    pub allow_bootstrap_atlas: bool,
    #[serde(default)]
    pub drain_policy: DrainPolicy,
}

impl GenesisConfig {
    pub fn for_profile(
        profile: NetworkProfile,
        network_id: impl Into<String>,
        network_name: impl Into<String>,
        validators: Vec<ConsensusValidator>,
    ) -> Self {
        Self {
            network_id: network_id.into(),
            network_name: network_name.into(),
            profile,
            protocol_version: PROTOCOL_VERSION.to_string(),
            genesis_timestamp_ms: 1_764_150_000_000,
            initial_validators: validators,
            allow_bootstrap_atlas: profile.allows_dev_atlas_fixture(),
            drain_policy: DrainPolicy::unconfigured(),
        }
    }

    pub fn with_drain_policy(mut self, policy: DrainPolicy) -> Self {
        self.drain_policy = policy;
        self
    }

    pub fn validate(&self) -> VResult<()> {
        if self.network_id.trim().is_empty() {
            return Err(VNetworkError::Validation(
                "genesis network_id cannot be empty".to_string(),
            ));
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(VNetworkError::ProfileMismatch(format!(
                "genesis protocol_version `{}` != `{PROTOCOL_VERSION}`",
                self.protocol_version
            )));
        }
        self.drain_policy.validate()?;
        if !self.initial_validators.is_empty() {
            validate_validator_set(&self.initial_validators)?;
        }
        Ok(())
    }

    pub fn commitment_hash(&self) -> VResult<String> {
        let mut sorted_validators = self.initial_validators.clone();
        sorted_validators.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
        let obj = serde_json::json!({
            "allow_bootstrap_atlas": self.allow_bootstrap_atlas,
            "drain_policy": self.drain_policy,
            "genesis_timestamp_ms": self.genesis_timestamp_ms,
            "initial_validators": sorted_validators,
            "network_id": self.network_id,
            "network_name": self.network_name,
            "profile": self.profile,
            "protocol_version": self.protocol_version,
        });
        Ok(blake3_hex(&canonical_json_bytes(&obj)?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorEpochTransition {
    pub epoch: u64,
    pub height: u64,
    pub prev_validator_set_hash: String,
    pub new_validator_set_hash: String,
    pub new_validators: Vec<ConsensusValidator>,
    pub transition_certificate: QuorumCertificate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub snapshot_id: String,
    pub height: u64,
    pub logical_clock: u64,
    pub state_root: String,
    pub replay_hash: String,
    pub event_count: usize,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkLedgerState {
    pub network_id: String,
    pub profile: NetworkProfile,
    pub protocol_version: String,
    #[serde(default)]
    pub genesis_commitment: String,
    pub height: u64,
    pub logical_clock: u64,
    #[serde(default = "default_validator_epoch")]
    pub validator_epoch: u64,
    #[serde(default)]
    pub validators: Vec<ConsensusValidator>,
    #[serde(default)]
    pub validator_membership_history: Vec<ValidatorEpochTransition>,
    #[serde(default)]
    pub drain_policy: DrainPolicy,
    #[serde(default)]
    pub last_proposal_digest: String,
    #[serde(default)]
    pub event_history_root: String,
    pub spaces: BTreeMap<String, SpaceEntity>,
    pub regions: BTreeMap<String, RegionEntity>,
    pub wallets: BTreeMap<String, WalletEntity>,
    pub tokens: BTreeMap<String, TokenEntity>,
    /// Keyed by "{token_id}::{wallet_id}"
    pub balances: BTreeMap<String, TokenBalanceRecord>,
    pub contracts: BTreeMap<String, VContractEntity>,
    pub loans: BTreeMap<String, VLoanEntity>,
    pub participants: BTreeMap<String, ParticipantRecord>,
    pub nodes: BTreeMap<String, NodeRecord>,
    pub programs: BTreeMap<String, ProgramSubmission>,
    pub events: Vec<LedgerEvent>,
    pub certificates: BTreeMap<String, QuorumCertificate>,
    pub challenges: BTreeMap<String, ParticipantChallenge>,
    /// Keyed by actor_pubkey -> highest accepted nonce
    pub actor_nonces: BTreeMap<String, u64>,
    pub seen_request_ids: BTreeSet<String>,
    #[serde(default)]
    pub used_wallet_pop_nonces: BTreeSet<String>,
    /// Transactions / program_ids indexed by tx_id
    pub transactions: BTreeMap<String, TransactionReceipt>,
    pub snapshots: Vec<StateSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub tx_id: String,
    pub request_id: String,
    pub actor_pubkey: String,
    pub operation: String,
    pub status: ProgramLifecycleStatus,
    pub event_ids: Vec<String>,
    pub certificate_id: Option<String>,
    pub state_root: String,
    pub error: Option<String>,
    pub timestamp_ms: u64,
}

impl NetworkLedgerState {
    pub fn try_new(genesis: &GenesisConfig) -> VResult<Self> {
        genesis.validate()?;
        let genesis_commitment = genesis.commitment_hash()?;
        let initial_event_root = blake3_hex(DOM_EVENT_HISTORY_V1.as_bytes());
        Ok(Self {
            network_id: genesis.network_id.clone(),
            profile: genesis.profile,
            protocol_version: genesis.protocol_version.clone(),
            genesis_commitment: genesis_commitment.clone(),
            height: 0,
            logical_clock: 0,
            validator_epoch: 1,
            validators: genesis.initial_validators.clone(),
            validator_membership_history: Vec::new(),
            drain_policy: genesis.drain_policy.clone(),
            last_proposal_digest: genesis_commitment,
            event_history_root: initial_event_root,
            spaces: BTreeMap::new(),
            regions: BTreeMap::new(),
            wallets: BTreeMap::new(),
            tokens: BTreeMap::new(),
            balances: BTreeMap::new(),
            contracts: BTreeMap::new(),
            loans: BTreeMap::new(),
            participants: BTreeMap::new(),
            nodes: BTreeMap::new(),
            programs: BTreeMap::new(),
            events: Vec::new(),
            certificates: BTreeMap::new(),
            challenges: BTreeMap::new(),
            actor_nonces: BTreeMap::new(),
            seen_request_ids: BTreeSet::new(),
            used_wallet_pop_nonces: BTreeSet::new(),
            transactions: BTreeMap::new(),
            snapshots: Vec::new(),
        })
    }

    pub fn new(genesis: &GenesisConfig) -> Self {
        Self::try_new(genesis).expect("invalid GenesisConfig passed to NetworkLedgerState::new")
    }

    pub fn balance_key(token_id: &str, wallet_id: &str) -> String {
        format!("{token_id}::{wallet_id}")
    }

    pub fn get_balance(&self, token_id: &str, wallet_id: &str) -> Option<&TokenBalanceRecord> {
        self.balances.get(&Self::balance_key(token_id, wallet_id))
    }

    pub fn latest_event_hash(&self) -> Option<String> {
        self.events.last().map(|e| e.event_hash.clone())
    }

    pub fn expected_parent_commitment(&self) -> String {
        if self.height == 0 || self.last_proposal_digest.trim().is_empty() {
            self.genesis_commitment.clone()
        } else {
            self.last_proposal_digest.clone()
        }
    }

    pub fn compute_event_history_root(&self) -> String {
        let mut h = blake3::Hasher::new();
        h.update(DOM_EVENT_HISTORY_V1.as_bytes());
        h.update(b":");
        for ev in &self.events {
            h.update(ev.sequence.to_le_bytes().as_slice());
            h.update(b":");
            h.update(ev.event_id.as_bytes());
            h.update(b":");
            h.update(ev.event_hash.as_bytes());
            h.update(b"|");
        }
        h.finalize().to_hex().to_string()
    }

    pub fn compute_state_root(&self) -> VResult<String> {
        let mut sorted_validators = self.validators.clone();
        sorted_validators.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
        let root_obj = serde_json::json!({
            "actor_nonces": self.actor_nonces,
            "balances": self.balances,
            "contracts": self.contracts,
            "drain_policy": self.drain_policy,
            "genesis_commitment": self.genesis_commitment,
            "height": self.height,
            "loans": self.loans,
            "logical_clock": self.logical_clock,
            "network_id": self.network_id,
            "nodes": self.nodes,
            "participants": self.participants,
            "profile": self.profile,
            "protocol_version": self.protocol_version,
            "regions": self.regions,
            "seen_request_ids": self.seen_request_ids,
            "spaces": self.spaces,
            "tokens": self.tokens,
            "used_wallet_pop_nonces": self.used_wallet_pop_nonces,
            "validator_epoch": self.validator_epoch,
            "validator_membership_history": self.validator_membership_history,
            "validators": sorted_validators,
            "wallets": self.wallets,
        });
        let bytes = canonical_json_bytes(&root_obj)?;
        Ok(blake3_hex(&bytes))
    }

    pub fn compute_replay_hash(&self) -> String {
        let mut h = blake3::Hasher::new();
        h.update(b"vnetwork/replay-v1:");
        for ev in &self.events {
            h.update(ev.event_hash.as_bytes());
            h.update(b"|");
        }
        h.finalize().to_hex().to_string()
    }
}
