use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use vnetwork_types::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub network_id: String,
    pub network_name: String,
    pub profile: NetworkProfile,
    pub protocol_version: String,
    pub genesis_timestamp_ms: u64,
    pub initial_validators: Vec<ConsensusValidator>,
    pub allow_bootstrap_atlas: bool,
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
        }
    }
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
    pub height: u64,
    pub logical_clock: u64,
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
    pub fn new(genesis: &GenesisConfig) -> Self {
        Self {
            network_id: genesis.network_id.clone(),
            profile: genesis.profile,
            protocol_version: genesis.protocol_version.clone(),
            height: 0,
            logical_clock: 0,
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
            transactions: BTreeMap::new(),
            snapshots: Vec::new(),
        }
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

    pub fn compute_state_root(&self) -> VResult<String> {
        let root_obj = serde_json::json!({
            "balances": self.balances,
            "contracts": self.contracts,
            "height": self.height,
            "loans": self.loans,
            "logical_clock": self.logical_clock,
            "network_id": self.network_id,
            "participants": self.participants,
            "profile": self.profile,
            "regions": self.regions,
            "spaces": self.spaces,
            "tokens": self.tokens,
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
