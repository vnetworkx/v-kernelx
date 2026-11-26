use crate::ast::VectorType;
use crate::event::Event;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificationState {
    Certified,
    Uncertified,
    Suspended,
    Revoked,
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorState {
    pub name: String,
    pub vector_type: VectorType,
    pub components: Vec<u128>,
    pub owner: Option<String>,
    pub meta: BTreeMap<String, String>,
    pub certification: CertificationState,
    pub auth_ratio: String,
}

impl VectorState {
    pub fn magnitude(&self) -> u128 {
        self.components.iter().copied().sum()
    }

    pub fn is_zero(&self) -> bool {
        self.components.iter().all(|x| *x == 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletState {
    pub name: String,
    pub public_key: String,
    pub meta: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionState {
    pub projection_id: String,
    pub source: String,
    pub environment: String,
    pub locked: Vec<u128>,
    pub remainder: Vec<u128>,
    pub policy: Option<String>,
    pub consumed: bool,
    pub settlement_result: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractState {
    pub name: String,
    pub actions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct NetworkState {
    pub vectors: BTreeMap<String, VectorState>,
    pub wallets: BTreeMap<String, WalletState>,
    pub projections: BTreeMap<String, ProjectionState>,
    pub contracts: BTreeMap<String, ContractState>,
    pub events: Vec<Event>,
    pub logical_clock: u64,
    pub last_event_hash: Option<String>,
}

impl NetworkState {
    pub fn new() -> Self {
        Self {
            vectors: BTreeMap::new(),
            wallets: BTreeMap::new(),
            projections: BTreeMap::new(),
            contracts: BTreeMap::new(),
            events: Vec::new(),
            logical_clock: 0,
            last_event_hash: None,
        }
    }

    pub fn next_clock(&mut self) -> u64 {
        self.logical_clock = self.logical_clock.saturating_add(1);
        self.logical_clock
    }

    pub fn push_event(&mut self, event: Event) {
        self.last_event_hash = Some(event.event_hash.clone());
        self.events.push(event);
    }
}
