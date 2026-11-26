use crate::authentication::SignedOperationHttpRequest;
use crate::errors::ApiError;
use crate::rate_limits::RateLimiter;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;
use vnetwork_core::identity::JoinNetworkRequest;
use vnetwork_core::language::SubmitProgramRequest;
use vnetwork_core::ledger::LedgerProofReport;
use vnetwork_core::reconstruction::ReconstructionReport;
use vnetwork_core::state::{NetworkLedgerState, TransactionReceipt};
use vnetwork_types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkWsEvent {
    pub event_type: String,
    pub network_id: String,
    pub height: u64,
    pub data: serde_json::Value,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConnectHttpRequest {
    pub multiaddr: String,
}

#[async_trait]
pub trait NetworkNodeBackend: Send + Sync {
    async fn health_report(&self) -> serde_json::Value;
    async fn ready_report(&self) -> (bool, serde_json::Value);
    async fn metrics_prometheus(&self) -> String;
    async fn network_info(&self) -> serde_json::Value;
    async fn network_status(&self) -> serde_json::Value;
    async fn state_snapshot(&self) -> NetworkLedgerState;
    async fn list_peers_and_nodes(&self) -> serde_json::Value;
    async fn get_node_details(&self, node_id: &str) -> Result<serde_json::Value, ApiError>;
    async fn connect_peer(&self, multiaddr: &str) -> Result<serde_json::Value, ApiError>;
    async fn issue_challenge(&self) -> Result<ParticipantChallenge, ApiError>;
    async fn join_participant(&self, req: JoinNetworkRequest) -> Result<serde_json::Value, ApiError>;
    async fn submit_program(&self, req: SubmitProgramRequest) -> Result<ProgramSubmission, ApiError>;
    async fn submit_signed_operation(
        &self,
        req: SignedOperationHttpRequest,
    ) -> Result<TransactionReceipt, ApiError>;
    async fn consensus_status(&self) -> serde_json::Value;
    async fn verify_ledger_proofs(&self) -> Result<LedgerProofReport, ApiError>;
    async fn verify_reconstruction(
        &self,
        entity_kind: &str,
        entity_id: &str,
    ) -> Result<ReconstructionReport, ApiError>;
    fn subscribe_ws(&self) -> broadcast::Receiver<NetworkWsEvent>;
}

#[derive(Clone)]
pub struct ApiAppState {
    pub backend: Arc<dyn NetworkNodeBackend>,
    pub rate_limiter: Arc<RateLimiter>,
}
