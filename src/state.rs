use crate::error::KernelXError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const STATE_SCHEMA_V1: &str = "v.kernelx/VectorStateV1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum VectorType {
    Standard,
    Origin,
    Projected,
    Escrow,
    Settlement,
    Locked,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum VectorStatus {
    Active,
    Projected,
    Escrowed,
    Settled,
    Archived,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificationState {
    pub certified: bool,
    pub auth_ratio: u16,
    pub threshold: u16,
    pub last_checked_at_ms: u64,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectionState {
    pub escrow_id: String,
    pub projected_components: Vec<u128>,
    pub settled_components: Vec<u128>,
    pub started_at_ms: u64,
    pub settlement_at_ms: Option<u64>,
    pub outcome_tag: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OriginState {
    pub seed: String,
    pub nonce: u64,
    pub difficulty: u32,
    pub proof_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VectorStateV1 {
    pub schema: String,
    pub vector_id: String,
    pub owner_pubkey: String,
    pub space_id: String,
    pub vector_type: VectorType,
    pub status: VectorStatus,
    pub components: Vec<u128>,
    pub type_metadata: BTreeMap<String, String>,
    pub certification: CertificationState,
    pub projection: Option<ProjectionState>,
    pub origin: Option<OriginState>,
    pub version: u64,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectionShare {
    pub component_index: usize,
    pub numerator: u128,
    pub denominator: u128,
}

impl VectorStateV1 {
    pub fn new(
        vector_id: impl Into<String>,
        owner_pubkey: impl Into<String>,
        space_id: impl Into<String>,
        components: Vec<u128>,
        vector_type: VectorType,
        timestamp_ms: u64,
    ) -> Self {
        Self {
            schema: STATE_SCHEMA_V1.to_string(),
            vector_id: vector_id.into(),
            owner_pubkey: owner_pubkey.into(),
            space_id: space_id.into(),
            vector_type,
            status: VectorStatus::Active,
            components,
            type_metadata: BTreeMap::new(),
            certification: CertificationState {
                certified: false,
                auth_ratio: 0,
                threshold: 700,
                last_checked_at_ms: timestamp_ms,
                reason: Some("not yet certified".to_string()),
            },
            projection: None,
            origin: None,
            version: 1,
            created_at_ms: timestamp_ms,
            updated_at_ms: timestamp_ms,
        }
    }

    pub fn magnitude(&self) -> u128 {
        self.components.iter().copied().sum()
    }

    pub fn is_zero(&self) -> bool {
        self.components.iter().all(|v| *v == 0)
    }

    pub fn direction_shares(&self) -> Result<Vec<DirectionShare>, KernelXError> {
        let magnitude = self.magnitude();
        if magnitude == 0 {
            return Err(KernelXError::ZeroNormalization);
        }
        Ok(self
            .components
            .iter()
            .enumerate()
            .map(|(i, component)| DirectionShare {
                component_index: i,
                numerator: *component,
                denominator: magnitude,
            })
            .collect())
    }

    pub fn ensure_same_shape(&self, other: &Self) -> Result<(), KernelXError> {
        if self.components.len() != other.components.len() {
            return Err(KernelXError::DimensionMismatch);
        }
        Ok(())
    }

    pub fn with_components(mut self, components: Vec<u128>, timestamp_ms: u64) -> Self {
        self.components = components;
        self.updated_at_ms = timestamp_ms;
        self.version += 1;
        self
    }

    pub fn with_status(mut self, status: VectorStatus, timestamp_ms: u64) -> Self {
        self.status = status;
        self.updated_at_ms = timestamp_ms;
        self.version += 1;
        self
    }
}

pub fn validate_canonical_state(state: &VectorStateV1) -> Result<(), KernelXError> {
    if state.schema != STATE_SCHEMA_V1 {
        return Err(KernelXError::InvalidState("schema mismatch".to_string()));
    }
    if state.components.is_empty() {
        return Err(KernelXError::InvalidState(
            "a vector must contain at least one component".to_string(),
        ));
    }
    if state.owner_pubkey.is_empty() || state.vector_id.is_empty() || state.space_id.is_empty() {
        return Err(KernelXError::InvalidState(
            "vector_id, owner_pubkey, and space_id are required".to_string(),
        ));
    }
    Ok(())
}

pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
