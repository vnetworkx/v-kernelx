use crate::state::{now_ms, CertificationState, VectorStateV1};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum OperationKind {
    OriginCreate,
    Transfer,
    Drain,
    Project,
    Reconstruct,
    Certify,
    Query,
    Custom(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VectorRecordV1 {
    pub schema: String,
    pub record_id: String,
    pub vector_id: String,
    pub before: Option<VectorStateV1>,
    pub after: VectorStateV1,
    pub operation: OperationKind,
    pub parameters: Value,
    pub certification: CertificationState,
    pub timestamp_ms: u64,
    pub proof: String,
}

impl VectorRecordV1 {
    pub fn new(
        record_id: impl Into<String>,
        vector_id: impl Into<String>,
        before: Option<VectorStateV1>,
        after: VectorStateV1,
        operation: OperationKind,
        parameters: Value,
    ) -> Self {
        let certification = after.certification.clone();
        let timestamp_ms = now_ms();
        let mut record = Self {
            schema: "v.kernelx/VectorRecordV1".to_string(),
            record_id: record_id.into(),
            vector_id: vector_id.into(),
            before,
            after,
            operation,
            parameters,
            certification,
            timestamp_ms,
            proof: String::new(),
        };
        record.proof = record.hash();
        record
    }

    pub fn hash(&self) -> String {
        let bytes = serde_json::to_vec(&(
            &self.schema,
            &self.record_id,
            &self.vector_id,
            &self.before,
            &self.after,
            &self.operation,
            &self.parameters,
            &self.certification,
            &self.timestamp_ms,
        ))
        .unwrap_or_default();
        let digest = Sha256::digest(bytes);
        hex::encode(digest)
    }
}

pub fn make_record_id(prefix: &str, vector_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(vector_id.as_bytes());
    hasher.update(now_ms().to_le_bytes());
    hex::encode(hasher.finalize())
}
