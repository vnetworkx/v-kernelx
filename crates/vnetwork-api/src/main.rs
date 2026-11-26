use async_trait::async_trait;
use axum::http::StatusCode;
use clap::Parser;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing_subscriber::EnvFilter;
use vnetwork_api::{
    serve_api, ApiError, ApiServerConfig, NetworkNodeBackend, NetworkWsEvent,
    SignedOperationHttpRequest,
};
use vnetwork_core::identity::JoinNetworkRequest;
use vnetwork_core::language::SubmitProgramRequest;
use vnetwork_core::ledger::LedgerProofReport;
use vnetwork_core::reconstruction::ReconstructionReport;
use vnetwork_core::replay::ReplayVerificationReport;
use vnetwork_core::state::{GenesisConfig, NetworkLedgerState, TransactionReceipt};
use vnetwork_core::supply::SupplyConservationBreakdown;
use vnetwork_types::*;

#[derive(Parser, Debug)]
#[command(
    name = "vnetwork-api",
    about = "Vector Network standalone Language & Health API service (attach vnetwork-node for full ledger consensus)"
)]
struct Args {
    #[arg(long, env = "NETWORK_API_LISTEN_ADDR", default_value = "0.0.0.0:8080")]
    bind: String,

    #[arg(long, env = "NETWORK_ID", default_value = "vector-devnet-1")]
    network_id: String,

    #[arg(long, env = "NETWORK_PROFILE", default_value = "DEVELOPMENT")]
    profile: String,
}

struct DetachedApiBackend {
    network_id: String,
    profile: NetworkProfile,
    genesis: GenesisConfig,
    ws_tx: broadcast::Sender<NetworkWsEvent>,
}

impl DetachedApiBackend {
    fn detached_err() -> ApiError {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "NODE_UNATTACHED",
            "vnetwork-api standalone binary has no attached consensus node; run vnetwork-node for full ledger execution",
        )
    }
}

#[async_trait]
impl NetworkNodeBackend for DetachedApiBackend {
    async fn health_report(&self) -> serde_json::Value {
        serde_json::json!({
            "healthy": false,
            "ready": false,
            "storage_ok": false,
            "wal_consistency_ok": false,
            "equivocation_store_ok": false,
            "verification_status": VerificationStatus::Unverified,
            "mode": "standalone-language-only",
            "network_id": self.network_id,
            "profile": self.profile,
            "protocol_version": PROTOCOL_VERSION,
            "kernel_version": format!("vnetwork-api/{}", env!("CARGO_PKG_VERSION")),
        })
    }

    async fn ready_report(&self) -> (bool, serde_json::Value) {
        (
            false,
            serde_json::json!({
                "ready": false,
                "mode": "standalone-language-only",
                "reason": "no attached consensus node",
            }),
        )
    }

    async fn metrics_prometheus(&self) -> String {
        format!(
            "# HELP vnetwork_api_standalone Standalone API mode (1 = no consensus node attached)\n\
             # TYPE vnetwork_api_standalone gauge\n\
             vnetwork_api_standalone{{network_id=\"{}\"}} 1\n",
            self.network_id
        )
    }

    async fn network_info(&self) -> serde_json::Value {
        serde_json::json!({
            "network_id": self.network_id,
            "profile": self.profile,
            "protocol_version": PROTOCOL_VERSION,
            "mode": "standalone-language-only",
        })
    }

    async fn network_status(&self) -> serde_json::Value {
        serde_json::json!({
            "network_id": self.network_id,
            "profile": self.profile,
            "protocol_version": PROTOCOL_VERSION,
            "mode": "standalone-language-only",
            "ready": false,
        })
    }

    async fn state_snapshot(&self) -> NetworkLedgerState {
        NetworkLedgerState::new(&self.genesis)
    }

    async fn list_peers_and_nodes(&self) -> serde_json::Value {
        serde_json::json!({ "connected_p2p_peers": [], "registered_nodes": [] })
    }

    async fn get_node_details(&self, _node_id: &str) -> Result<serde_json::Value, ApiError> {
        Err(Self::detached_err())
    }

    async fn connect_peer(&self, _multiaddr: &str) -> Result<serde_json::Value, ApiError> {
        Err(Self::detached_err())
    }

    async fn issue_challenge(&self) -> Result<ParticipantChallenge, ApiError> {
        Err(Self::detached_err())
    }

    async fn join_participant(&self, _req: JoinNetworkRequest) -> Result<serde_json::Value, ApiError> {
        Err(Self::detached_err())
    }

    async fn submit_program(&self, _req: SubmitProgramRequest) -> Result<ProgramSubmission, ApiError> {
        Err(Self::detached_err())
    }

    async fn submit_signed_operation(
        &self,
        _req: SignedOperationHttpRequest,
    ) -> Result<TransactionReceipt, ApiError> {
        Err(Self::detached_err())
    }

    async fn consensus_status(&self) -> serde_json::Value {
        serde_json::json!({
            "network_id": self.network_id,
            "mode": "standalone-language-only",
            "ready": false,
        })
    }

    async fn verify_ledger_proofs(&self) -> Result<LedgerProofReport, ApiError> {
        Err(Self::detached_err())
    }

    async fn verify_replay(&self) -> Result<ReplayVerificationReport, ApiError> {
        Err(Self::detached_err())
    }

    async fn verify_token_supply(
        &self,
        _token_id: &str,
    ) -> Result<SupplyConservationBreakdown, ApiError> {
        Err(Self::detached_err())
    }

    async fn list_equivocations(&self) -> Vec<EquivocationEvidence> {
        Vec::new()
    }

    async fn verify_reconstruction(
        &self,
        _entity_kind: &str,
        _entity_id: &str,
    ) -> Result<ReconstructionReport, ApiError> {
        Err(Self::detached_err())
    }

    fn subscribe_ws(&self) -> broadcast::Receiver<NetworkWsEvent> {
        self.ws_tx.subscribe()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let profile = NetworkProfile::parse(&args.profile).ok_or_else(|| {
        VNetworkError::Validation(format!(
            "invalid NETWORK_PROFILE `{}`; expected DEVELOPMENT, TESTNET, or PRODUCTION",
            args.profile
        ))
    })?;
    if profile == NetworkProfile::Production && args.network_id.to_ascii_lowercase().contains("devnet") {
        return Err(Box::new(VNetworkError::ProfileMismatch(
            "PRODUCTION profile cannot use a devnet network_id".to_string(),
        )));
    }
    let genesis = GenesisConfig::for_profile(profile, &args.network_id, "Vector Network", Vec::new());
    let (ws_tx, _) = broadcast::channel(64);
    let backend: Arc<dyn NetworkNodeBackend> = Arc::new(DetachedApiBackend {
        network_id: args.network_id,
        profile,
        genesis,
        ws_tx,
    });

    tracing::warn!(
        bind = %args.bind,
        "starting vnetwork-api in standalone language/health mode; run vnetwork-node for full P2P and consensus endpoints"
    );

    serve_api(
        backend,
        ApiServerConfig {
            bind_addr: args.bind,
            ..ApiServerConfig::default()
        },
    )
    .await
}
