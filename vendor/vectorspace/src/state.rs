use crate::ast::VectorType;
use crate::error::{RuntimeError, RuntimeErrorKind};
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
    pub fn magnitude(&self) -> Result<u128, RuntimeError> {
        self.components.iter().try_fold(0u128, |sum, component| {
            sum.checked_add(*component).ok_or_else(|| {
                RuntimeError::new(RuntimeErrorKind::InvalidOperation(
                    "vector magnitude overflow".to_string(),
                ))
            })
        })
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

    pub fn next_clock(&mut self) -> Result<u64, RuntimeError> {
        let next = self.logical_clock.checked_add(1).ok_or_else(|| {
            RuntimeError::new(RuntimeErrorKind::InvalidOperation(
                "logical clock overflow".to_string(),
            ))
        })?;
        self.logical_clock = next;
        Ok(next)
    }

    pub fn push_event(&mut self, event: Event) {
        self.last_event_hash = Some(event.event_hash.clone());
        self.events.push(event);
    }
}


impl Default for NetworkState {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod checked_state_regressions {
    use super::{CertificationState, NetworkState, VectorState};
    use crate::ast::VectorType;

    #[test]
    fn vector_magnitude_rejects_overflow() {
        let vector = VectorState {
            name: "overflow".to_string(),
            vector_type: VectorType::Free,
            components: vec![u128::MAX, 1],
            owner: None,
            meta: Default::default(),
            certification: CertificationState::Pending,
            auth_ratio: "0.0000".to_string(),
        };
        assert!(vector.magnitude().is_err());
    }

    #[test]
    fn logical_clock_rejects_overflow_without_mutation() {
        let mut state = NetworkState::new();
        state.logical_clock = u64::MAX;
        assert!(state.next_clock().is_err());
        assert_eq!(state.logical_clock, u64::MAX);
    }
}
