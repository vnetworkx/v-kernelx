use crate::consensus::QuorumCertificate;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProgramLifecycleStatus {
    Received,
    Parsing,
    Compiled,
    Validating,
    AwaitingAuthorization,
    AwaitingConsensus,
    Committed,
    Rejected,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleCommitment {
    pub path: String,
    pub blake3_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramSubmission {
    pub program_id: String,
    pub file_name: String,
    pub file_kind: String,
    pub source_bytes: String,
    pub source_hash: String,
    pub language_version: String,
    pub compiler_version: String,
    pub imported_modules: Vec<ModuleCommitment>,
    pub resolved_module_sources: BTreeMap<String, String>,
    pub compiled_program_hash: String,
    pub protocol_version: String,
    pub network_id: String,
    pub submitter_participant_id: String,
    pub submitter_pubkey: String,
    pub request_id: String,
    pub nonce: u64,
    pub signature: String,
    pub execution_params: BTreeMap<String, serde_json::Value>,
    pub status: ProgramLifecycleStatus,
    pub failed_operation_index: Option<usize>,
    pub error_message: Option<String>,
    pub resulting_event_ids: Vec<String>,
    pub consensus_certificate: Option<QuorumCertificate>,
    pub final_state_root: Option<String>,
    pub created_entities: Vec<CreatedEntitySummary>,
    pub outputs: Vec<String>,
    pub submitted_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedEntitySummary {
    pub kind: String,
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramExecutionReport {
    pub program_id: String,
    pub status: ProgramLifecycleStatus,
    pub compiled_program_hash: String,
    pub source_hash: String,
    pub ops_executed: usize,
    pub failed_operation_index: Option<usize>,
    pub error_message: Option<String>,
    pub resulting_event_ids: Vec<String>,
    pub created_entities: Vec<CreatedEntitySummary>,
    pub outputs: Vec<String>,
    pub final_state_root: String,
    pub consensus_certificate: Option<QuorumCertificate>,
}
