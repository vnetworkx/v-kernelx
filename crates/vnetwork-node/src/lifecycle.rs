use crate::bootstrap::parse_bootstrap_multiaddrs;
use crate::config::NodeConfig;
use crate::discovery::parse_listen_multiaddrs;
use crate::health::NodeHealthReport;
use crate::identity::NodeIdentity;
use crate::metrics::NodeMetrics;
use crate::networking::{build_behaviour, VNetworkBehaviour, VNetworkBehaviourEvent};
use crate::peer::PeerRegistry;
use crate::shutdown::ShutdownSignal;
use crate::synchronization::reconcile_sync_commits;
use crate::transport::{P2pGossipMessage, P2pSyncRequest, P2pSyncResponse};
use crate::validator::evaluate_and_sign_proposal;
use async_trait::async_trait;
use futures::StreamExt;
use libp2p::{gossipsub, identify, multiaddr::Protocol, request_response, swarm::SwarmEvent, Multiaddr, PeerId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use vnetwork_api::{
    ApiError, NetworkNodeBackend, NetworkWsEvent, SignedOperationHttpRequest, StatusCode,
};
use vnetwork_consensus::{
    finalize_and_commit, EquivocationStore, QuorumTracker, ValidatorMembership,
};
use vnetwork_core::engine::ProtocolEngine;
use vnetwork_core::identity::JoinNetworkRequest;
use vnetwork_core::language::SubmitProgramRequest;
use vnetwork_core::ledger::LedgerProofReport;
use vnetwork_core::reconstruction::ReconstructionReport;
use vnetwork_core::replay::ReplayVerificationReport;
use vnetwork_core::state::{GenesisConfig, NetworkLedgerState, TransactionReceipt};
use vnetwork_core::supply::SupplyConservationBreakdown;
use vnetwork_storage::{CommittedProposalRecord, StorageDatabase};
use vnetwork_types::*;

fn consensus_timeout_ms() -> u64 {
    std::env::var("NETWORK_CONSENSUS_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&ms| ms >= 500)
        .unwrap_or(8_000)
}

pub enum NodeCommand {
    IssueChallenge {
        reply: oneshot::Sender<Result<ParticipantChallenge, ApiError>>,
    },
    JoinParticipant {
        req: JoinNetworkRequest,
        reply: oneshot::Sender<Result<serde_json::Value, ApiError>>,
    },
    SubmitProgram {
        req: SubmitProgramRequest,
        reply: oneshot::Sender<Result<ProgramSubmission, ApiError>>,
    },
    SubmitSignedOp {
        req: SignedOperationHttpRequest,
        reply: oneshot::Sender<Result<TransactionReceipt, ApiError>>,
    },
    ConnectPeer {
        multiaddr: String,
        reply: oneshot::Sender<Result<serde_json::Value, ApiError>>,
    },
}

struct PendingWaiter {
    _proposal_id: String,
    kind: PendingKind,
    deadline_ms: u64,
}

enum PendingKind {
    Join {
        participant: ParticipantRecord,
        node: NodeRecord,
        receipt: TransactionReceipt,
        reply: oneshot::Sender<Result<serde_json::Value, ApiError>>,
    },
    Program {
        program_id: String,
        reply: oneshot::Sender<Result<ProgramSubmission, ApiError>>,
    },
    Transaction {
        tx_id: String,
        reply: oneshot::Sender<Result<TransactionReceipt, ApiError>>,
    },
}

#[derive(Clone)]
pub struct NodeHandle {
    pub config: NodeConfig,
    pub identity: NodeIdentity,
    pub cmd_tx: mpsc::Sender<NodeCommand>,
    pub shared_state: Arc<RwLock<NetworkLedgerState>>,
    pub shared_peers: Arc<RwLock<PeerRegistry>>,
    pub shared_membership: Arc<RwLock<ValidatorMembership>>,
    pub shared_equivocations: Arc<RwLock<Vec<EquivocationEvidence>>>,
    pub storage: StorageDatabase,
    pub storage_healthy: Arc<AtomicBool>,
    pub equivocation_store_healthy: Arc<AtomicBool>,
    pub metrics: Arc<NodeMetrics>,
    pub ws_tx: broadcast::Sender<NetworkWsEvent>,
    pub genesis: GenesisConfig,
    pub listen_addrs: Arc<RwLock<Vec<String>>>,
}

#[async_trait]
impl NetworkNodeBackend for NodeHandle {
    async fn health_report(&self) -> serde_json::Value {
        let state = self.shared_state.read().await;
        let peers = self.shared_peers.read().await;
        let equivocations = self.shared_equivocations.read().await;
        let wal_ok = self.storage.check_health().is_ok();
        let storage_ok = self.storage_healthy.load(Ordering::Relaxed) && wal_ok;
        let eq_ok = self.equivocation_store_healthy.load(Ordering::Relaxed);
        let state_root_res = state.compute_state_root();
        let healthy = storage_ok && eq_ok && state_root_res.is_ok();
        let state_root = match state_root_res {
            Ok(root) => root,
            Err(e) => {
                tracing::error!(error = %e, "compute_state_root failed in health_report");
                String::new()
            }
        };
        let ready = healthy
            && (state.height > 0
                || peers.connected_count() > 0
                || !self.config.enable_p2p
                || self.config.bootstrap_peers.is_empty());
        let report = NodeHealthReport {
            healthy,
            ready,
            node_id: self.identity.node_id.clone(),
            peer_id: self.identity.libp2p_peer_id.to_string(),
            network_id: self.config.network_id.clone(),
            profile: self.config.profile,
            node_kind: self.config.node_kind,
            height: state.height,
            state_root,
            connected_peers: peers.connected_count(),
            validator_active: self.config.enable_validator,
            storage_ok,
            wal_consistency_ok: wal_ok,
            equivocation_store_ok: eq_ok,
            equivocation_count: equivocations.len(),
            key_storage_mode: self.identity.storage_security_mode.clone(),
            verification_status: if healthy {
                VerificationStatus::Verified
            } else {
                VerificationStatus::Invalid
            },
            api_enabled: self.config.enable_public_api,
            p2p_enabled: self.config.enable_p2p,
            protocol_version: self.config.protocol_version.clone(),
            kernel_version: format!("vnetwork-node/{}", env!("CARGO_PKG_VERSION")),
        };
        serde_json::to_value(report).unwrap_or_else(|e| {
            serde_json::json!({
                "healthy": false,
                "ready": false,
                "verification_status": "INVALID",
                "error": format!("serialize health report failed: {e}")
            })
        })
    }

    async fn ready_report(&self) -> (bool, serde_json::Value) {
        let state = self.shared_state.read().await;
        let peers = self.shared_peers.read().await;
        let wal_ok = self.storage.check_health().is_ok();
        let storage_ok = self.storage_healthy.load(Ordering::Relaxed) && wal_ok;
        let eq_ok = self.equivocation_store_healthy.load(Ordering::Relaxed);
        let ready = storage_ok
            && eq_ok
            && (!self.config.enable_p2p
                || self.config.bootstrap_peers.is_empty()
                || peers.connected_count() > 0
                || state.height > 0);
        (
            ready,
            serde_json::json!({
                "ready": ready,
                "storage_ok": storage_ok,
                "wal_consistency_ok": wal_ok,
                "equivocation_store_ok": eq_ok,
                "node_id": self.identity.node_id,
                "network_id": self.config.network_id,
                "height": state.height,
                "connected_peers": peers.connected_count(),
            }),
        )
    }

    async fn metrics_prometheus(&self) -> String {
        let state = self.shared_state.read().await;
        let peers = self.shared_peers.read().await;
        let membership = self.shared_membership.read().await;
        self.metrics.render_prometheus(
            &self.config.network_id,
            &self.identity.node_id,
            state.height,
            state.events.len(),
            peers.connected_count(),
            membership.active_validators().len(),
        )
    }

    async fn network_info(&self) -> serde_json::Value {
        let state = self.shared_state.read().await;
        let addrs = self.listen_addrs.read().await;
        let membership = self.shared_membership.read().await;
        let state_root = state.compute_state_root().ok();
        serde_json::json!({
            "network_id": self.config.network_id,
            "network_name": self.config.network_name,
            "profile": self.config.profile,
            "protocol_version": self.config.protocol_version,
            "kernel_version": format!("vnetwork-node/{}", env!("CARGO_PKG_VERSION")),
            "genesis_commitment": state.genesis_commitment,
            "node_id": self.identity.node_id,
            "peer_id": self.identity.libp2p_peer_id.to_string(),
            "node_metadata": self.identity.node_metadata,
            "validator_metadata": self.identity.validator_metadata,
            "key_storage_mode": self.identity.storage_security_mode,
            "listen_addresses": *addrs,
            "advertised_addresses": self.config.advertised_addresses,
            "bootstrap_peers": self.config.bootstrap_peers,
            "height": state.height,
            "epoch": state.validator_epoch,
            "state_root": state_root,
            "event_history_root": state.event_history_root,
            "drain_policy": state.drain_policy,
            "quorum_threshold_bps": membership.quorum_threshold_bps(),
            "validator_count": membership.active_validators().len(),
            "allow_bootstrap_atlas": self.genesis.allow_bootstrap_atlas,
        })
    }

    async fn network_status(&self) -> serde_json::Value {
        let state = self.shared_state.read().await;
        let peers = self.shared_peers.read().await;
        let membership = self.shared_membership.read().await;
        let wal_ok = self.storage.check_health().is_ok();
        let storage_ok = self.storage_healthy.load(Ordering::Relaxed) && wal_ok;
        let eq_ok = self.equivocation_store_healthy.load(Ordering::Relaxed);
        serde_json::json!({
            "network_id": self.config.network_id,
            "profile": self.config.profile,
            "protocol_version": self.config.protocol_version,
            "kernel_version": format!("vnetwork-node/{}", env!("CARGO_PKG_VERSION")),
            "node_id": self.identity.node_id,
            "peer_id": self.identity.libp2p_peer_id.to_string(),
            "genesis_commitment": state.genesis_commitment,
            "height": state.height,
            "epoch": state.validator_epoch,
            "logical_clock": state.logical_clock,
            "committed_events": state.events.len(),
            "certificates": state.certificates.len(),
            "connected_peers": peers.connected_count(),
            "participants": state.participants.len(),
            "spaces": state.spaces.len(),
            "regions": state.regions.len(),
            "wallets": state.wallets.len(),
            "tokens": state.tokens.len(),
            "contracts": state.contracts.len(),
            "loans": state.loans.len(),
            "programs": state.programs.len(),
            "active_validators": membership.active_validators().len(),
            "required_quorum_weight": membership.required_weight().unwrap_or(0),
            "total_validator_weight": membership.total_active_weight().unwrap_or(0),
            "state_root": state.compute_state_root().ok(),
            "event_history_root": state.event_history_root,
            "replay_hash": state.compute_replay_hash(),
            "storage_engine": "vnetwork-wal-json",
            "storage_ok": storage_ok,
            "wal_consistency_ok": wal_ok,
            "equivocation_store_ok": eq_ok,
        })
    }

    async fn state_snapshot(&self) -> NetworkLedgerState {
        self.shared_state.read().await.clone()
    }

    async fn list_peers_and_nodes(&self) -> serde_json::Value {
        let state = self.shared_state.read().await;
        let peers = self.shared_peers.read().await;
        let addrs = self.listen_addrs.read().await;
        let p2p_peers: Vec<_> = peers.peers.values().cloned().collect();
        let reg_nodes: Vec<_> = state.nodes.values().cloned().collect();
        serde_json::json!({
            "local_node": {
                "node_id": self.identity.node_id,
                "peer_id": self.identity.libp2p_peer_id.to_string(),
                "node_kind": self.config.node_kind,
                "listen_addresses": *addrs,
                "height": state.height,
            },
            "connected_p2p_peers": p2p_peers,
            "registered_nodes": reg_nodes,
        })
    }

    async fn get_node_details(&self, node_id: &str) -> Result<serde_json::Value, ApiError> {
        if node_id == self.identity.node_id {
            return Ok(self.health_report().await);
        }
        let state = self.shared_state.read().await;
        if let Some(n) = state.nodes.get(node_id) {
            return serde_json::to_value(n).map_err(|e| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "SERIALIZATION_ERROR",
                    format!("failed to serialize node record: {e}"),
                )
            });
        }
        let peers = self.shared_peers.read().await;
        if let Some(p) = peers
            .peers
            .values()
            .find(|p| p.node_id.as_deref() == Some(node_id) || p.peer_id == node_id)
        {
            return serde_json::to_value(p).map_err(|e| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "SERIALIZATION_ERROR",
                    format!("failed to serialize peer record: {e}"),
                )
            });
        }
        Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "NODE_NOT_FOUND",
            format!("node `{node_id}` not found"),
        ))
    }

    async fn connect_peer(&self, multiaddr: &str) -> Result<serde_json::Value, ApiError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(NodeCommand::ConnectPeer {
                multiaddr: multiaddr.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "NODE_STOPPED", "node runtime stopped"))?;
        rx.await
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "CHANNEL_CLOSED", "command dropped"))?
    }

    async fn issue_challenge(&self) -> Result<ParticipantChallenge, ApiError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(NodeCommand::IssueChallenge { reply: tx })
            .await
            .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "NODE_STOPPED", "node runtime stopped"))?;
        rx.await
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "CHANNEL_CLOSED", "command dropped"))?
    }

    async fn join_participant(&self, req: JoinNetworkRequest) -> Result<serde_json::Value, ApiError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(NodeCommand::JoinParticipant { req, reply: tx })
            .await
            .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "NODE_STOPPED", "node runtime stopped"))?;
        rx.await
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "CHANNEL_CLOSED", "command dropped"))?
    }

    async fn submit_program(&self, req: SubmitProgramRequest) -> Result<ProgramSubmission, ApiError> {
        self.metrics.programs_submitted.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(NodeCommand::SubmitProgram { req, reply: tx })
            .await
            .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "NODE_STOPPED", "node runtime stopped"))?;
        let res = rx
            .await
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "CHANNEL_CLOSED", "command dropped"))?;
        if res.is_err() {
            self.metrics.programs_failed.fetch_add(1, Ordering::Relaxed);
        }
        res
    }

    async fn submit_signed_operation(
        &self,
        req: SignedOperationHttpRequest,
    ) -> Result<TransactionReceipt, ApiError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(NodeCommand::SubmitSignedOp { req, reply: tx })
            .await
            .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "NODE_STOPPED", "node runtime stopped"))?;
        rx.await
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "CHANNEL_CLOSED", "command dropped"))?
    }

    async fn consensus_status(&self) -> serde_json::Value {
        let state = self.shared_state.read().await;
        let membership = self.shared_membership.read().await;
        let equivocations = self.shared_equivocations.read().await;
        serde_json::json!({
            "network_id": self.config.network_id,
            "genesis_commitment": state.genesis_commitment,
            "height": state.height,
            "epoch": state.validator_epoch,
            "validator_set_hash": compute_validator_set_hash(&state.validators).ok(),
            "quorum_threshold_bps": membership.quorum_threshold_bps(),
            "required_weight": membership.required_weight().unwrap_or(0),
            "total_active_weight": membership.total_active_weight().unwrap_or(0),
            "validators": membership.all_validators(),
            "certificate_count": state.certificates.len(),
            "equivocation_count": equivocations.len(),
            "equivocations": *equivocations,
            "equivocation_store_ok": self.equivocation_store_healthy.load(Ordering::Relaxed),
            "proposals_committed": self.metrics.proposals_committed.load(Ordering::Relaxed),
            "proposals_rejected": self.metrics.proposals_rejected.load(Ordering::Relaxed),
            "votes_cast": self.metrics.votes_cast.load(Ordering::Relaxed),
        })
    }

    async fn verify_ledger_proofs(&self) -> Result<LedgerProofReport, ApiError> {
        let state = self.shared_state.read().await;
        vnetwork_core::ledger::build_verified_ledger_proof_report(&state, Some(&self.genesis))
            .map_err(ApiError::from)
    }

    async fn verify_replay(&self) -> Result<ReplayVerificationReport, ApiError> {
        let state = self.shared_state.read().await;
        vnetwork_core::replay::verify_replay_equivalence(&state, &self.genesis).map_err(ApiError::from)
    }

    async fn verify_token_supply(
        &self,
        token_id: &str,
    ) -> Result<SupplyConservationBreakdown, ApiError> {
        let state = self.shared_state.read().await;
        vnetwork_core::supply::compute_token_supply_breakdown(&state, token_id).map_err(ApiError::from)
    }

    async fn list_equivocations(&self) -> Vec<EquivocationEvidence> {
        self.shared_equivocations.read().await.clone()
    }

    async fn verify_reconstruction(
        &self,
        entity_kind: &str,
        entity_id: &str,
    ) -> Result<ReconstructionReport, ApiError> {
        let state = self.shared_state.read().await;
        vnetwork_core::reconstruction::reconstruct_entity(
            &state,
            &self.genesis,
            entity_kind,
            entity_id,
        )
        .map_err(ApiError::from)
    }

    fn subscribe_ws(&self) -> broadcast::Receiver<NetworkWsEvent> {
        self.ws_tx.subscribe()
    }
}

pub fn build_genesis_from_config(cfg: &NodeConfig, identity: &NodeIdentity) -> VResult<GenesisConfig> {
    let mut validators = cfg.genesis_validators.clone();
    if validators.is_empty() && cfg.enable_validator {
        if let (Some(vid), Some(vmeta)) = (&identity.validator_id, &identity.validator_metadata) {
            validators.push(ConsensusValidator {
                validator_id: vid.clone(),
                node_id: identity.node_id.clone(),
                validator_pubkey_hex: vmeta.public_key_hex.clone(),
                weight: 100,
                active: true,
                joined_epoch: 1,
            });
        }
    }
    let params = NetworkConsensusParameters::with_quorum_threshold_bps(cfg.quorum_threshold_bps)?;
    let mut g = GenesisConfig::for_profile(
        cfg.profile,
        &cfg.network_id,
        &cfg.network_name,
        validators,
    )
    .with_drain_policy(cfg.drain_policy.clone())
    .with_consensus_parameters(params)?;
    if let Some(allow) = cfg.allow_bootstrap_atlas {
        if cfg.profile == NetworkProfile::Production && allow {
            return Err(VNetworkError::Authorization(
                "allow_bootstrap_atlas cannot be enabled in PRODUCTION".to_string(),
            ));
        }
        g.allow_bootstrap_atlas = allow;
    }
    g.validate()?;
    Ok(g)
}

fn requires_shared_genesis(profile: NetworkProfile) -> bool {
    matches!(profile, NetworkProfile::Testnet | NetworkProfile::Production)
}

pub async fn start_node_runtime(
    cfg: NodeConfig,
    explicit_genesis: Option<GenesisConfig>,
    shutdown: ShutdownSignal,
) -> Result<(NodeHandle, tokio::task::JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
    cfg.validate()?;
    if requires_shared_genesis(cfg.profile)
        && explicit_genesis.is_none()
        && cfg.genesis_validators.is_empty()
    {
        return Err(Box::new(VNetworkError::Validation(format!(
            "{} profile requires a shared genesis_file or a configured genesis_validators set; per-node key-derived genesis is development-only",
            cfg.profile.as_str()
        ))));
    }
    let passphrase = cfg.resolve_key_passphrase()?;
    let id_opts = crate::identity::NodeIdentityLoadOptions {
        profile: cfg.profile,
        passphrase,
        kdf_params: None,
        allow_plaintext_key_fallback: false,
        external_node_signer: None,
        external_validator_signer: None,
        transport_key_path: None,
    };
    let identity = NodeIdentity::load_or_create_secure(
        &cfg.node_identity_path,
        cfg.validator_key_path.as_deref(),
        cfg.validator_id.as_deref(),
        cfg.enable_validator,
        &id_opts,
    )?;

    let genesis = match explicit_genesis {
        Some(g) => g,
        None => build_genesis_from_config(&cfg, &identity)?,
    };
    cfg.validate_against_genesis(&genesis)?;
    let (storage, recovered_state, recovery_report) =
        StorageDatabase::open_and_recover(&cfg.storage_path, &genesis)?;
    let equivocation_store = EquivocationStore::open(&cfg.storage_path)?;

    tracing::info!(
        node_id = %identity.node_id,
        peer_id = %identity.libp2p_peer_id,
        network_id = %cfg.network_id,
        height = recovery_report.final_height,
        events = recovery_report.wal_events_verified,
        key_mode = %identity.storage_security_mode,
        "recovered durable node state"
    );

    let active_validators = if recovered_state.validators.is_empty() {
        genesis.initial_validators.clone()
    } else {
        recovered_state.validators.clone()
    };
    let membership = ValidatorMembership::try_new(
        active_validators,
        genesis.consensus_parameters.quorum_threshold_bps,
    )?;
    let engine = ProtocolEngine::from_restored(genesis.clone(), recovered_state.clone());

    let shared_state = Arc::new(RwLock::new(recovered_state));
    let shared_peers = Arc::new(RwLock::new(PeerRegistry::default()));
    let shared_membership = Arc::new(RwLock::new(membership));
    let shared_equivocations = Arc::new(RwLock::new(equivocation_store.evidence().to_vec()));
    let storage_healthy = Arc::new(AtomicBool::new(storage.check_health().is_ok()));
    let equivocation_store_healthy = Arc::new(AtomicBool::new(equivocation_store.check_health().is_ok()));
    let metrics = Arc::new(NodeMetrics::default());
    let (ws_tx, _) = broadcast::channel(512);
    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    let listen_addrs = Arc::new(RwLock::new(cfg.p2p_listen_addresses.clone()));

    let handle = NodeHandle {
        config: cfg.clone(),
        identity: identity.clone(),
        cmd_tx,
        shared_state: shared_state.clone(),
        shared_peers: shared_peers.clone(),
        shared_membership: shared_membership.clone(),
        shared_equivocations: shared_equivocations.clone(),
        storage: storage.clone(),
        storage_healthy: storage_healthy.clone(),
        equivocation_store_healthy: equivocation_store_healthy.clone(),
        metrics: metrics.clone(),
        ws_tx: ws_tx.clone(),
        genesis: genesis.clone(),
        listen_addrs: listen_addrs.clone(),
    };

    let task = tokio::spawn(run_node_loop(
        cfg,
        identity,
        genesis,
        engine,
        storage,
        equivocation_store,
        storage_healthy,
        equivocation_store_healthy,
        shared_state,
        shared_peers,
        shared_membership,
        shared_equivocations,
        metrics,
        ws_tx,
        listen_addrs,
        cmd_rx,
        shutdown,
    ));

    Ok((handle, task))
}

#[allow(clippy::too_many_arguments)]
async fn run_node_loop(
    cfg: NodeConfig,
    identity: NodeIdentity,
    genesis: GenesisConfig,
    mut engine: ProtocolEngine,
    storage: StorageDatabase,
    mut equivocation_store: EquivocationStore,
    storage_healthy: Arc<AtomicBool>,
    equivocation_store_healthy: Arc<AtomicBool>,
    shared_state: Arc<RwLock<NetworkLedgerState>>,
    shared_peers: Arc<RwLock<PeerRegistry>>,
    shared_membership: Arc<RwLock<ValidatorMembership>>,
    shared_equivocations: Arc<RwLock<Vec<EquivocationEvidence>>>,
    metrics: Arc<NodeMetrics>,
    ws_tx: broadcast::Sender<NetworkWsEvent>,
    listen_addrs: Arc<RwLock<Vec<String>>>,
    mut cmd_rx: mpsc::Receiver<NodeCommand>,
    shutdown: ShutdownSignal,
) {
    let agent = PeerRegistry::parse_agent_header(
        &cfg.network_id,
        &identity.node_id,
        engine.state.height,
    );
    let consensus_topic = gossipsub::IdentTopic::new(format!("vnetwork/{}/consensus", cfg.network_id));
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity.libp2p_keypair.clone())
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .expect("tcp/noise/yamux init")
        .with_dns()
        .expect("dns init")
        .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)
        .expect("relay client")
        .with_behaviour(|key, relay_client| {
            build_behaviour(key, relay_client, agent.clone()).expect("behaviour init")
        })
        .expect("swarm build")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    if cfg.enable_p2p {
        let _ = swarm.behaviour_mut().gossipsub.subscribe(&consensus_topic);
        if let Ok(addrs) = parse_listen_multiaddrs(&cfg.p2p_listen_addresses) {
            for addr in addrs {
                if let Err(e) = swarm.listen_on(addr.clone()) {
                    tracing::warn!(%addr, error = %e, "failed to listen on multiaddr");
                }
            }
        }
        if let Ok(boot_addrs) = parse_bootstrap_multiaddrs(&cfg.bootstrap_peers) {
            for ma in boot_addrs {
                if let Some(peer_id) = extract_peer_id(&ma) {
                    if peer_id != identity.libp2p_peer_id {
                        swarm.behaviour_mut().kademlia.add_address(&peer_id, ma.clone());
                        let _ = swarm.dial(ma);
                    }
                } else {
                    let _ = swarm.dial(ma);
                }
            }
        }
        let _ = swarm.behaviour_mut().kademlia.bootstrap();
    }

    let mut quorum_tracker = QuorumTracker::new();
    let mut pending_proposals: BTreeMap<String, ConsensusProposal> = BTreeMap::new();
    let mut pending_waiters: BTreeMap<String, PendingWaiter> = BTreeMap::new();
    let mut connected_peer_ids: BTreeSet<PeerId> = BTreeSet::new();
    let mut buffered_commits: BTreeMap<u64, CommittedProposalRecord> = BTreeMap::new();
    let mut shutdown_rx = shutdown.subscribe();
    let mut tick = tokio::time::interval(Duration::from_millis(200));

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    tracing::info!(node_id = %identity.node_id, "shutting down node loop");
                    break;
                }
            }
            _ = tick.tick() => {
                let now = now_ms();
                // Timeout any pending consensus rounds that failed to reach quorum
                let expired_ids: Vec<String> = pending_waiters
                    .iter()
                    .filter(|(_, w)| now >= w.deadline_ms)
                    .map(|(k, _)| k.clone())
                    .collect();
                for pid in expired_ids {
                    if let Some(w) = pending_waiters.remove(&pid) {
                        metrics.proposals_rejected.fetch_add(1, Ordering::Relaxed);
                        let err_msg = format!(
                            "consensus quorum not reached for proposal {} (votes={}/{})",
                            pid,
                            quorum_tracker.vote_count(&pid),
                            shared_membership.read().await.active_validators().len()
                        );
                        match &w.kind {
                            PendingKind::Program { program_id, .. } => {
                                if let Some(sub) = engine.state.programs.get_mut(program_id) {
                                    sub.status = ProgramLifecycleStatus::Rejected;
                                    sub.error_message = Some(err_msg.clone());
                                    sub.updated_at_ms = now;
                                }
                                if let Some(tx) = engine.state.transactions.get_mut(program_id) {
                                    tx.status = ProgramLifecycleStatus::Rejected;
                                    tx.error = Some(err_msg.clone());
                                }
                                if let Err(e) = storage.persist_metadata_only(&engine.state) {
                                    storage_healthy.store(false, Ordering::Relaxed);
                                    tracing::error!(proposal_id = %pid, error = %e, "failed to persist rejected program metadata");
                                } else {
                                    *shared_state.write().await = engine.state.clone();
                                }
                            }
                            PendingKind::Join { receipt, .. } => {
                                if let Some(tx) = engine.state.transactions.get_mut(&receipt.tx_id) {
                                    tx.status = ProgramLifecycleStatus::Rejected;
                                    tx.error = Some(err_msg.clone());
                                }
                                if let Err(e) = storage.persist_metadata_only(&engine.state) {
                                    storage_healthy.store(false, Ordering::Relaxed);
                                    tracing::error!(proposal_id = %pid, error = %e, "failed to persist rejected join metadata");
                                } else {
                                    *shared_state.write().await = engine.state.clone();
                                }
                            }
                            PendingKind::Transaction { tx_id, .. } => {
                                if let Some(tx) = engine.state.transactions.get_mut(tx_id) {
                                    tx.status = ProgramLifecycleStatus::Rejected;
                                    tx.error = Some(err_msg.clone());
                                }
                                if let Err(e) = storage.persist_metadata_only(&engine.state) {
                                    storage_healthy.store(false, Ordering::Relaxed);
                                    tracing::error!(proposal_id = %pid, error = %e, "failed to persist rejected transaction metadata");
                                } else {
                                    *shared_state.write().await = engine.state.clone();
                                }
                            }
                        }
                        let api_err = ApiError::new(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "INSUFFICIENT_QUORUM",
                            err_msg,
                        );
                        match w.kind {
                            PendingKind::Join { reply, .. } => { let _ = reply.send(Err(api_err)); }
                            PendingKind::Program { reply, .. } => { let _ = reply.send(Err(api_err)); }
                            PendingKind::Transaction { reply, .. } => { let _ = reply.send(Err(api_err)); }
                        }
                    }
                    pending_proposals.remove(&pid);
                }

                // Request sync from connected peers periodically if behind or on tick
                if cfg.enable_p2p && !connected_peer_ids.is_empty() {
                    match engine.state.compute_state_root() {
                        Ok(root) => {
                            let msg = P2pGossipMessage::Heartbeat {
                                node_id: identity.node_id.clone(),
                                height: engine.state.height,
                                state_root: root,
                                timestamp_ms: now,
                            };
                            if let Ok(bytes) = serde_json::to_vec(&msg) {
                                let _ = swarm.behaviour_mut().gossipsub.publish(consensus_topic.clone(), bytes);
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "failed to compute state root for P2P heartbeat");
                        }
                    }
                }
            }
            Some(cmd) = cmd_rx.recv() => {
                let now = now_ms();
                match cmd {
                    NodeCommand::ConnectPeer { multiaddr, reply } => {
                        match multiaddr.parse::<Multiaddr>() {
                            Ok(ma) => {
                                if let Err(err) = crate::config::validate_peer_dial_multiaddr(
                                    &ma,
                                    cfg.profile,
                                    cfg.allow_local_p2p,
                                ) {
                                    let _ = reply.send(Err(ApiError::new(
                                        StatusCode::FORBIDDEN,
                                        "PEER_ADDR_FORBIDDEN",
                                        err.to_string(),
                                    )));
                                    continue;
                                }
                                if let Some(pid) = extract_peer_id(&ma) {
                                    swarm.behaviour_mut().kademlia.add_address(&pid, ma.clone());
                                }
                                match swarm.dial(ma.clone()) {
                                    Ok(_) => {
                                        let _ = reply.send(Ok(serde_json::json!({
                                            "dialing": multiaddr,
                                            "local_peer_id": identity.libp2p_peer_id.to_string(),
                                        })));
                                    }
                                    Err(e) => {
                                        let _ = reply.send(Err(ApiError::new(
                                            StatusCode::BAD_REQUEST,
                                            "DIAL_ERROR",
                                            format!("failed to dial {multiaddr}: {e}"),
                                        )));
                                    }
                                }
                            }
                            Err(e) => {
                                let _ = reply.send(Err(ApiError::new(
                                    StatusCode::BAD_REQUEST,
                                    "INVALID_MULTIADDR",
                                    format!("invalid multiaddr: {e}"),
                                )));
                            }
                        }
                    }
                    NodeCommand::IssueChallenge { reply } => {
                        let ch = engine.issue_challenge(now);
                        *shared_state.write().await = engine.state.clone();
                        let _ = reply.send(Ok(ch));
                    }
                    NodeCommand::JoinParticipant { req, reply } => {
                        let Some((val_id, val_signer)) = (&identity.validator_id, &identity.validator_signer)
                            .into_opt_pair()
                        else {
                            let _ = reply.send(Err(ApiError::new(
                                StatusCode::BAD_REQUEST,
                                "NOT_VALIDATOR",
                                "join must be submitted to an active validator endpoint",
                            )));
                            continue;
                        };
                        match engine.stage_participant_join(&req, val_id, |b| val_signer.sign(b), now) {
                            Ok((participant, node, proposal, receipt)) => {
                                if let Err(e) = quorum_tracker.register_proposal(proposal.clone()) {
                                    let _ = reply.send(Err(ApiError::from(e)));
                                    continue;
                                }
                                let pid = proposal.proposal_id.clone();
                                pending_proposals.insert(pid.clone(), proposal.clone());
                                pending_waiters.insert(
                                    pid.clone(),
                                    PendingWaiter {
                                        _proposal_id: pid.clone(),
                                        kind: PendingKind::Join {
                                            participant,
                                            node,
                                            receipt,
                                            reply,
                                        },
                                        deadline_ms: now + consensus_timeout_ms(),
                                    },
                                );
                                process_new_proposal(
                                    &cfg,
                                    &identity,
                                    &genesis,
                                    &mut engine,
                                    &storage,
                                    &mut equivocation_store,
                                    &storage_healthy,
                                    &equivocation_store_healthy,
                                    &shared_state,
                                    &shared_membership,
                                    &shared_equivocations,
                                    &metrics,
                                    &ws_tx,
                                    &mut swarm,
                                    &consensus_topic,
                                    &connected_peer_ids,
                                    &mut quorum_tracker,
                                    &mut pending_proposals,
                                    &mut pending_waiters,
                                    proposal,
                                    now,
                                )
                                .await;
                            }
                            Err(e) => {
                                let _ = reply.send(Err(ApiError::from(e)));
                            }
                        }
                    }
                    NodeCommand::SubmitProgram { req, reply } => {
                        let Some((val_id, val_signer)) = (&identity.validator_id, &identity.validator_signer)
                            .into_opt_pair()
                        else {
                            let _ = reply.send(Err(ApiError::new(
                                StatusCode::BAD_REQUEST,
                                "NOT_VALIDATOR",
                                "program submission requires an active validator proposer endpoint",
                            )));
                            continue;
                        };
                        match engine.stage_program_submission(&req, None, val_id, |b| val_signer.sign(b), now) {
                            Ok(Ok(staged)) => {
                                if let Err(e) = quorum_tracker.register_proposal(staged.proposal.clone()) {
                                    let _ = reply.send(Err(ApiError::from(e)));
                                    continue;
                                }
                                let pid = staged.proposal.proposal_id.clone();
                                let prog_id = staged
                                    .program_submission
                                    .as_ref()
                                    .map(|p| p.program_id.clone())
                                    .unwrap_or_default();
                                *shared_state.write().await = engine.state.clone();
                                pending_proposals.insert(pid.clone(), staged.proposal.clone());
                                pending_waiters.insert(
                                    pid.clone(),
                                    PendingWaiter {
                                        _proposal_id: pid,
                                        kind: PendingKind::Program {
                                            program_id: prog_id,
                                            reply,
                                        },
                                        deadline_ms: now + consensus_timeout_ms(),
                                    },
                                );
                                process_new_proposal(
                                    &cfg,
                                    &identity,
                                    &genesis,
                                    &mut engine,
                                    &storage,
                                    &mut equivocation_store,
                                    &storage_healthy,
                                    &equivocation_store_healthy,
                                    &shared_state,
                                    &shared_membership,
                                    &shared_equivocations,
                                    &metrics,
                                    &ws_tx,
                                    &mut swarm,
                                    &consensus_topic,
                                    &connected_peer_ids,
                                    &mut quorum_tracker,
                                    &mut pending_proposals,
                                    &mut pending_waiters,
                                    staged.proposal,
                                    now,
                                )
                                .await;
                            }
                            Ok(Err(failed_sub)) => {
                                if let Err(e) = storage.persist_metadata_only(&engine.state) {
                                    storage_healthy.store(false, Ordering::Relaxed);
                                    tracing::error!(error = %e, "failed to persist failed program submission metadata");
                                    let _ = reply.send(Err(ApiError::from(e)));
                                } else {
                                    storage_healthy.store(true, Ordering::Relaxed);
                                    *shared_state.write().await = engine.state.clone();
                                    let _ = reply.send(Ok(failed_sub));
                                }
                            }
                            Err(e) => {
                                let _ = reply.send(Err(ApiError::from(e)));
                            }
                        }
                    }
                    NodeCommand::SubmitSignedOp { req, reply } => {
                        let env = match req.verify_and_extract_envelope() {
                            Ok(e) => e,
                            Err(err) => {
                                let _ = reply.send(Err(err));
                                continue;
                            }
                        };
                        let Some((val_id, val_signer)) = (&identity.validator_id, &identity.validator_signer)
                            .into_opt_pair()
                        else {
                            let _ = reply.send(Err(ApiError::new(
                                StatusCode::BAD_REQUEST,
                                "NOT_VALIDATOR",
                                "transaction requires an active validator proposer endpoint",
                            )));
                            continue;
                        };
                        match engine.stage_signed_operation(&env, &req.operation, val_id, |b| val_signer.sign(b), now) {
                            Ok(staged) => {
                                if let Err(e) = quorum_tracker.register_proposal(staged.proposal.clone()) {
                                    let _ = reply.send(Err(ApiError::from(e)));
                                    continue;
                                }
                                let pid = staged.proposal.proposal_id.clone();
                                let tx_id = staged.tx_receipt.tx_id.clone();
                                *shared_state.write().await = engine.state.clone();
                                pending_proposals.insert(pid.clone(), staged.proposal.clone());
                                pending_waiters.insert(
                                    pid.clone(),
                                    PendingWaiter {
                                        _proposal_id: pid,
                                        kind: PendingKind::Transaction { tx_id, reply },
                                        deadline_ms: now + consensus_timeout_ms(),
                                    },
                                );
                                process_new_proposal(
                                    &cfg,
                                    &identity,
                                    &genesis,
                                    &mut engine,
                                    &storage,
                                    &mut equivocation_store,
                                    &storage_healthy,
                                    &equivocation_store_healthy,
                                    &shared_state,
                                    &shared_membership,
                                    &shared_equivocations,
                                    &metrics,
                                    &ws_tx,
                                    &mut swarm,
                                    &consensus_topic,
                                    &connected_peer_ids,
                                    &mut quorum_tracker,
                                    &mut pending_proposals,
                                    &mut pending_waiters,
                                    staged.proposal,
                                    now,
                                )
                                .await;
                            }
                            Err(e) => {
                                let _ = reply.send(Err(ApiError::from(e)));
                            }
                        }
                    }
                }
            }
            event = swarm.select_next_some() => {
                let now = now_ms();
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        let full = format!("{}/p2p/{}", address, identity.libp2p_peer_id);
                        tracing::info!(addr = %full, "libp2p listening");
                        let mut addrs = listen_addrs.write().await;
                        if !addrs.contains(&full) {
                            addrs.push(full);
                        }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        connected_peer_ids.insert(peer_id);
                        let addr_str = endpoint.get_remote_address().to_string();
                        shared_peers.write().await.upsert_connected(
                            peer_id.to_string(),
                            Some(addr_str),
                            now,
                        );
                        swarm.behaviour_mut().sync.send_request(
                            &peer_id,
                            P2pSyncRequest::GetMissingCommits {
                                network_id: cfg.network_id.clone(),
                                from_height: engine.state.height + 1,
                            },
                        );
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        connected_peer_ids.remove(&peer_id);
                        shared_peers.write().await.mark_disconnected(&peer_id.to_string(), now);
                    }
                    SwarmEvent::Behaviour(VNetworkBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                        match PeerRegistry::check_agent_compatible(&cfg.network_id, &info.agent_version) {
                            Ok((peer_node_id, peer_height)) => {
                                let addrs: Vec<String> = info.listen_addrs.iter().map(|a| a.to_string()).collect();
                                for a in &info.listen_addrs {
                                    swarm.behaviour_mut().kademlia.add_address(&peer_id, a.clone());
                                }
                                shared_peers.write().await.update_identify(
                                    &peer_id.to_string(),
                                    Some(peer_node_id),
                                    info.agent_version,
                                    addrs,
                                    now,
                                );
                                if peer_height > engine.state.height {
                                    swarm.behaviour_mut().sync.send_request(
                                        &peer_id,
                                        P2pSyncRequest::GetMissingCommits {
                                            network_id: cfg.network_id.clone(),
                                            from_height: engine.state.height + 1,
                                        },
                                    );
                                }
                            }
                            Err(reason) => {
                                tracing::warn!(%peer_id, %reason, "incompatible peer identified");
                                let _ = swarm.disconnect_peer_id(peer_id);
                            }
                        }
                    }
                    SwarmEvent::Behaviour(VNetworkBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                        if let Ok(msg) = serde_json::from_slice::<P2pGossipMessage>(&message.data) {
                            handle_gossip_or_relay_message(
                                msg,
                                &cfg,
                                &identity,
                                &genesis,
                                &mut engine,
                                &storage,
                                &mut equivocation_store,
                                &storage_healthy,
                                &equivocation_store_healthy,
                                &shared_state,
                                &shared_membership,
                                &shared_equivocations,
                                &metrics,
                                &ws_tx,
                                &mut swarm,
                                &consensus_topic,
                                &connected_peer_ids,
                                &mut quorum_tracker,
                                &mut pending_proposals,
                                &mut pending_waiters,
                                &mut buffered_commits,
                                now,
                            ).await;
                        }
                    }
                    SwarmEvent::Behaviour(VNetworkBehaviourEvent::Sync(request_response::Event::Message { peer, message })) => {
                        match message {
                            request_response::Message::Request { request, channel, .. } => {
                                match request {
                                    P2pSyncRequest::GetMissingCommits { network_id, from_height } => {
                                        let commits = if network_id == cfg.network_id {
                                            match storage.load_committed_proposals() {
                                                Ok(all) => all
                                                    .into_iter()
                                                    .filter(|c| c.proposal.height >= from_height)
                                                    .collect(),
                                                Err(e) => {
                                                    storage_healthy.store(false, Ordering::Relaxed);
                                                    tracing::error!(error = %e, "failed to load committed proposals for sync response");
                                                    Vec::new()
                                                }
                                            }
                                        } else {
                                            Vec::new()
                                        };
                                        let _ = swarm.behaviour_mut().sync.send_response(
                                            channel,
                                            P2pSyncResponse::Commits {
                                                network_id: cfg.network_id.clone(),
                                                head_height: engine.state.height,
                                                commits,
                                            },
                                        );
                                    }
                                    P2pSyncRequest::RelayProposal(proposal) => {
                                        let _ = swarm.behaviour_mut().sync.send_response(
                                            channel,
                                            P2pSyncResponse::Ack { accepted: true, message: "ok".to_string() },
                                        );
                                        handle_gossip_or_relay_message(
                                            P2pGossipMessage::Proposal(proposal),
                                            &cfg,
                                            &identity,
                                            &genesis,
                                            &mut engine,
                                            &storage,
                                            &mut equivocation_store,
                                            &storage_healthy,
                                            &equivocation_store_healthy,
                                            &shared_state,
                                            &shared_membership,
                                            &shared_equivocations,
                                            &metrics,
                                            &ws_tx,
                                            &mut swarm,
                                            &consensus_topic,
                                            &connected_peer_ids,
                                            &mut quorum_tracker,
                                            &mut pending_proposals,
                                            &mut pending_waiters,
                                            &mut buffered_commits,
                                            now,
                                        ).await;
                                    }
                                    P2pSyncRequest::RelayVote(vote) => {
                                        let _ = swarm.behaviour_mut().sync.send_response(
                                            channel,
                                            P2pSyncResponse::Ack { accepted: true, message: "ok".to_string() },
                                        );
                                        handle_gossip_or_relay_message(
                                            P2pGossipMessage::Vote(vote),
                                            &cfg,
                                            &identity,
                                            &genesis,
                                            &mut engine,
                                            &storage,
                                            &mut equivocation_store,
                                            &storage_healthy,
                                            &equivocation_store_healthy,
                                            &shared_state,
                                            &shared_membership,
                                            &shared_equivocations,
                                            &metrics,
                                            &ws_tx,
                                            &mut swarm,
                                            &consensus_topic,
                                            &connected_peer_ids,
                                            &mut quorum_tracker,
                                            &mut pending_proposals,
                                            &mut pending_waiters,
                                            &mut buffered_commits,
                                            now,
                                        ).await;
                                    }
                                    P2pSyncRequest::RelayCertificate { proposal_id, certificate } => {
                                        let _ = swarm.behaviour_mut().sync.send_response(
                                            channel,
                                            P2pSyncResponse::Ack { accepted: true, message: "ok".to_string() },
                                        );
                                        handle_gossip_or_relay_message(
                                            P2pGossipMessage::Certificate { proposal_id, certificate },
                                            &cfg,
                                            &identity,
                                            &genesis,
                                            &mut engine,
                                            &storage,
                                            &mut equivocation_store,
                                            &storage_healthy,
                                            &equivocation_store_healthy,
                                            &shared_state,
                                            &shared_membership,
                                            &shared_equivocations,
                                            &metrics,
                                            &ws_tx,
                                            &mut swarm,
                                            &consensus_topic,
                                            &connected_peer_ids,
                                            &mut quorum_tracker,
                                            &mut pending_proposals,
                                            &mut pending_waiters,
                                            &mut buffered_commits,
                                            now,
                                        ).await;
                                    }
                                    P2pSyncRequest::RelayProgramSubmission { .. } => {
                                        let _ = swarm.behaviour_mut().sync.send_response(
                                            channel,
                                            P2pSyncResponse::Ack { accepted: false, message: "submit directly to validator API".to_string() },
                                        );
                                    }
                                }
                            }
                            request_response::Message::Response { response, .. } => {
                                if let P2pSyncResponse::Commits { network_id, head_height, commits } = response {
                                    if network_id == cfg.network_id {
                                        shared_peers.write().await.peers.entry(peer.to_string()).and_modify(|p| p.sync_height = head_height);
                                        if !commits.is_empty() {
                                            let membership_guard = shared_membership.read().await;
                                            match reconcile_sync_commits(&mut engine, &storage, &membership_guard, &commits, now) {
                                                Ok(applied) if applied > 0 => {
                                                    storage_healthy.store(true, Ordering::Relaxed);
                                                    metrics.sync_batches_applied.fetch_add(1, Ordering::Relaxed);
                                                    *shared_state.write().await = engine.state.clone();
                                                    tracing::info!(node_id = %identity.node_id, applied, height = engine.state.height, "synchronized verified commits from peer");
                                                }
                                                Ok(_) => {}
                                                Err(e) => {
                                                    if matches!(e, VNetworkError::Storage(_)) {
                                                        storage_healthy.store(false, Ordering::Relaxed);
                                                    }
                                                    tracing::warn!(node_id = %identity.node_id, error = %e, "sync verification or persistence failed");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_new_proposal(
    cfg: &NodeConfig,
    identity: &NodeIdentity,
    genesis: &GenesisConfig,
    engine: &mut ProtocolEngine,
    storage: &StorageDatabase,
    equivocation_store: &mut EquivocationStore,
    storage_healthy: &Arc<AtomicBool>,
    equivocation_store_healthy: &Arc<AtomicBool>,
    shared_state: &Arc<RwLock<NetworkLedgerState>>,
    shared_membership: &Arc<RwLock<ValidatorMembership>>,
    shared_equivocations: &Arc<RwLock<Vec<EquivocationEvidence>>>,
    metrics: &Arc<NodeMetrics>,
    ws_tx: &broadcast::Sender<NetworkWsEvent>,
    swarm: &mut libp2p::Swarm<VNetworkBehaviour>,
    topic: &gossipsub::IdentTopic,
    connected_peers: &BTreeSet<PeerId>,
    quorum_tracker: &mut QuorumTracker,
    pending_proposals: &mut BTreeMap<String, ConsensusProposal>,
    pending_waiters: &mut BTreeMap<String, PendingWaiter>,
    proposal: ConsensusProposal,
    now: u64,
) {
    metrics.proposals_proposed.fetch_add(1, Ordering::Relaxed);
    broadcast_gossip_and_direct(
        cfg,
        swarm,
        topic,
        connected_peers,
        P2pGossipMessage::Proposal(proposal.clone()),
        P2pSyncRequest::RelayProposal(proposal.clone()),
    );

    // Self-vote if local node is an active validator, ALWAYS through durable EquivocationStore
    if let (Some(val_id), Some(val_signer)) = (&identity.validator_id, &identity.validator_signer) {
        let membership = shared_membership.read().await.clone();
        match evaluate_and_sign_proposal(
            &engine.state,
            genesis,
            &membership,
            &proposal,
            val_id,
            val_signer.as_ref(),
            equivocation_store,
            now,
        ) {
            Ok(vote) => {
                equivocation_store_healthy.store(true, Ordering::Relaxed);
                metrics.votes_cast.fetch_add(1, Ordering::Relaxed);
                broadcast_gossip_and_direct(
                    cfg,
                    swarm,
                    topic,
                    connected_peers,
                    P2pGossipMessage::Vote(vote.clone()),
                    P2pSyncRequest::RelayVote(vote.clone()),
                );
                match quorum_tracker.record_vote_with_store(
                    &membership,
                    vote,
                    Some(equivocation_store),
                    now,
                ) {
                    Ok(Some(qc)) => {
                        finalize_proposal_everywhere(
                            cfg,
                            engine,
                            storage,
                            storage_healthy,
                            shared_state,
                            &membership,
                            metrics,
                            ws_tx,
                            swarm,
                            topic,
                            connected_peers,
                            pending_proposals,
                            pending_waiters,
                            &proposal.proposal_id,
                            qc,
                            now,
                        )
                        .await;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        *shared_equivocations.write().await = equivocation_store.evidence().to_vec();
                        tracing::warn!(proposal_id = %proposal.proposal_id, error = %e, "rejected self-vote in quorum tracker");
                    }
                }
            }
            Err(e) => {
                if matches!(e, VNetworkError::Storage(_)) {
                    equivocation_store_healthy.store(false, Ordering::Relaxed);
                }
                tracing::warn!(proposal_id = %proposal.proposal_id, error = %e, "failed or refused self-vote in equivocation store");
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_gossip_or_relay_message(
    msg: P2pGossipMessage,
    cfg: &NodeConfig,
    identity: &NodeIdentity,
    genesis: &GenesisConfig,
    engine: &mut ProtocolEngine,
    storage: &StorageDatabase,
    equivocation_store: &mut EquivocationStore,
    storage_healthy: &Arc<AtomicBool>,
    equivocation_store_healthy: &Arc<AtomicBool>,
    shared_state: &Arc<RwLock<NetworkLedgerState>>,
    shared_membership: &Arc<RwLock<ValidatorMembership>>,
    shared_equivocations: &Arc<RwLock<Vec<EquivocationEvidence>>>,
    metrics: &Arc<NodeMetrics>,
    ws_tx: &broadcast::Sender<NetworkWsEvent>,
    swarm: &mut libp2p::Swarm<VNetworkBehaviour>,
    topic: &gossipsub::IdentTopic,
    connected_peers: &BTreeSet<PeerId>,
    quorum_tracker: &mut QuorumTracker,
    pending_proposals: &mut BTreeMap<String, ConsensusProposal>,
    pending_waiters: &mut BTreeMap<String, PendingWaiter>,
    buffered_commits: &mut BTreeMap<u64, CommittedProposalRecord>,
    now: u64,
) {
    match msg {
        P2pGossipMessage::Proposal(proposal) => {
            if proposal.network_id != cfg.network_id || proposal.height <= engine.state.height {
                return;
            }
            if pending_proposals.contains_key(&proposal.proposal_id) {
                return;
            }
            let membership = shared_membership.read().await.clone();
            if let Err(e) =
                vnetwork_consensus::validate_proposal_against_state(&engine.state, genesis, &membership, &proposal)
            {
                tracing::warn!(proposal_id = %proposal.proposal_id, error = %e, "rejected invalid proposal");
                return;
            }
            if let Err(e) = quorum_tracker.register_proposal(proposal.clone()) {
                tracing::warn!(proposal_id = %proposal.proposal_id, error = %e, "rejected proposal registration");
                return;
            }
            pending_proposals.insert(proposal.proposal_id.clone(), proposal.clone());

            if let (Some(val_id), Some(val_signer)) = (&identity.validator_id, &identity.validator_signer) {
                match evaluate_and_sign_proposal(
                    &engine.state,
                    genesis,
                    &membership,
                    &proposal,
                    val_id,
                    val_signer.as_ref(),
                    equivocation_store,
                    now,
                ) {
                    Ok(vote) => {
                        equivocation_store_healthy.store(true, Ordering::Relaxed);
                        metrics.votes_cast.fetch_add(1, Ordering::Relaxed);
                        broadcast_gossip_and_direct(
                            cfg,
                            swarm,
                            topic,
                            connected_peers,
                            P2pGossipMessage::Vote(vote.clone()),
                            P2pSyncRequest::RelayVote(vote.clone()),
                        );
                        match quorum_tracker.record_vote_with_store(
                            &membership,
                            vote,
                            Some(equivocation_store),
                            now,
                        ) {
                            Ok(Some(qc)) => {
                                finalize_proposal_everywhere(
                                    cfg,
                                    engine,
                                    storage,
                                    storage_healthy,
                                    shared_state,
                                    &membership,
                                    metrics,
                                    ws_tx,
                                    swarm,
                                    topic,
                                    connected_peers,
                                    pending_proposals,
                                    pending_waiters,
                                    &proposal.proposal_id,
                                    qc,
                                    now,
                                )
                                .await;
                            }
                            Ok(None) => {}
                            Err(e) => {
                                *shared_equivocations.write().await = equivocation_store.evidence().to_vec();
                                tracing::warn!(proposal_id = %proposal.proposal_id, error = %e, "rejected peer proposal vote");
                            }
                        }
                    }
                    Err(e) => {
                        if matches!(e, VNetworkError::Storage(_)) {
                            equivocation_store_healthy.store(false, Ordering::Relaxed);
                        }
                        tracing::warn!(proposal_id = %proposal.proposal_id, error = %e, "refused vote signing via durable equivocation store");
                    }
                }
            }
        }
        P2pGossipMessage::Vote(vote) => {
            if vote.network_id != cfg.network_id || vote.height <= engine.state.height {
                return;
            }
            let membership = shared_membership.read().await.clone();
            match quorum_tracker.record_vote_with_store(
                &membership,
                vote.clone(),
                Some(equivocation_store),
                now,
            ) {
                Ok(Some(qc)) => {
                    finalize_proposal_everywhere(
                        cfg,
                        engine,
                        storage,
                        storage_healthy,
                        shared_state,
                        &membership,
                        metrics,
                        ws_tx,
                        swarm,
                        topic,
                        connected_peers,
                        pending_proposals,
                        pending_waiters,
                        &vote.proposal_id,
                        qc,
                        now,
                    )
                    .await;
                }
                Ok(None) => {}
                Err(e) => {
                    if matches!(e, VNetworkError::Storage(_)) {
                        equivocation_store_healthy.store(false, Ordering::Relaxed);
                    }
                    *shared_equivocations.write().await = equivocation_store.evidence().to_vec();
                    tracing::warn!(proposal_id = %vote.proposal_id, validator_id = %vote.validator_id, error = %e, "rejected incoming vote");
                }
            }
        }
        P2pGossipMessage::Certificate { proposal_id, certificate } => {
            if certificate.network_id != cfg.network_id || certificate.height <= engine.state.height {
                return;
            }
            let membership = shared_membership.read().await.clone();
            if pending_proposals.contains_key(&proposal_id) {
                finalize_proposal_everywhere(
                    cfg,
                    engine,
                    storage,
                    storage_healthy,
                    shared_state,
                    &membership,
                    metrics,
                    ws_tx,
                    swarm,
                    topic,
                    connected_peers,
                    pending_proposals,
                    pending_waiters,
                    &proposal_id,
                    certificate,
                    now,
                )
                .await;
            } else if certificate.height > engine.state.height {
                // Request missing commits from peers
                for p in connected_peers {
                    swarm.behaviour_mut().sync.send_request(
                        p,
                        P2pSyncRequest::GetMissingCommits {
                            network_id: cfg.network_id.clone(),
                            from_height: engine.state.height + 1,
                        },
                    );
                }
                let _ = buffered_commits;
            }
        }
        P2pGossipMessage::Heartbeat { height, .. } => {
            if height > engine.state.height && cfg.enable_p2p {
                for p in connected_peers {
                    swarm.behaviour_mut().sync.send_request(
                        p,
                        P2pSyncRequest::GetMissingCommits {
                            network_id: cfg.network_id.clone(),
                            from_height: engine.state.height + 1,
                        },
                    );
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn finalize_proposal_everywhere(
    cfg: &NodeConfig,
    engine: &mut ProtocolEngine,
    storage: &StorageDatabase,
    storage_healthy: &Arc<AtomicBool>,
    shared_state: &Arc<RwLock<NetworkLedgerState>>,
    membership: &ValidatorMembership,
    metrics: &Arc<NodeMetrics>,
    ws_tx: &broadcast::Sender<NetworkWsEvent>,
    swarm: &mut libp2p::Swarm<VNetworkBehaviour>,
    topic: &gossipsub::IdentTopic,
    connected_peers: &BTreeSet<PeerId>,
    pending_proposals: &mut BTreeMap<String, ConsensusProposal>,
    pending_waiters: &mut BTreeMap<String, PendingWaiter>,
    proposal_id: &str,
    qc: QuorumCertificate,
    now: u64,
) {
    let Some(proposal) = pending_proposals.remove(proposal_id) else {
        return;
    };
    if proposal.height <= engine.state.height {
        return;
    }

    let mut staged_engine = engine.clone();
    match finalize_and_commit(&mut staged_engine, membership, &proposal, &qc, now) {
        Ok(post_root) => {
            if let Err(e) = storage.persist_commit(&staged_engine.state, &proposal, &qc) {
                storage_healthy.store(false, Ordering::Relaxed);
                metrics.proposals_rejected.fetch_add(1, Ordering::Relaxed);
                tracing::error!(proposal_id = %proposal_id, error = %e, "storage persist_commit failed; aborting commit finality");
                if let Some(waiter) = pending_waiters.remove(proposal_id) {
                    let err = ApiError::from(e);
                    match waiter.kind {
                        PendingKind::Join { reply, .. } => { let _ = reply.send(Err(err)); }
                        PendingKind::Program { reply, .. } => { let _ = reply.send(Err(err)); }
                        PendingKind::Transaction { reply, .. } => { let _ = reply.send(Err(err)); }
                    }
                }
                return;
            }
            storage_healthy.store(true, Ordering::Relaxed);
            *engine = staged_engine;
            *shared_state.write().await = engine.state.clone();
            metrics.proposals_committed.fetch_add(1, Ordering::Relaxed);

            broadcast_gossip_and_direct(
                cfg,
                swarm,
                topic,
                connected_peers,
                P2pGossipMessage::Certificate {
                    proposal_id: proposal_id.to_string(),
                    certificate: qc.clone(),
                },
                P2pSyncRequest::RelayCertificate {
                    proposal_id: proposal_id.to_string(),
                    certificate: qc.clone(),
                },
            );

            let _ = ws_tx.send(NetworkWsEvent {
                event_type: "CONSENSUS_FINALITY".to_string(),
                network_id: cfg.network_id.clone(),
                height: engine.state.height,
                data: serde_json::json!({
                    "proposal_id": proposal_id,
                    "certificate_id": qc.certificate_id,
                    "state_root": post_root,
                    "events": proposal.events.len(),
                }),
                timestamp_ms: now,
            });

            if let Some(waiter) = pending_waiters.remove(proposal_id) {
                match waiter.kind {
                    PendingKind::Join { participant, node, mut receipt, reply } => {
                        receipt.status = ProgramLifecycleStatus::Committed;
                        receipt.certificate_id = Some(qc.certificate_id.clone());
                        receipt.state_root = post_root.clone();
                        let _ = reply.send(Ok(serde_json::json!({
                            "participant": participant,
                            "node": node,
                            "receipt": receipt,
                            "consensus_certificate": qc,
                            "state_root": post_root,
                        })));
                    }
                    PendingKind::Program { program_id, reply } => {
                        if let Some(sub) = engine.state.programs.get(&program_id).cloned() {
                            let _ = reply.send(Ok(sub));
                        } else {
                            let _ = reply.send(Err(ApiError::new(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "PROGRAM_MISSING",
                                "committed program missing from state",
                            )));
                        }
                    }
                    PendingKind::Transaction { tx_id, reply } => {
                        if let Some(tx) = engine.state.transactions.get(&tx_id).cloned() {
                            let _ = reply.send(Ok(tx));
                        } else {
                            let _ = reply.send(Err(ApiError::new(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "TX_MISSING",
                                "committed transaction missing",
                            )));
                        }
                    }
                }
            }
        }
        Err(e) => {
            metrics.proposals_rejected.fetch_add(1, Ordering::Relaxed);
            if let Some(waiter) = pending_waiters.remove(proposal_id) {
                let err = ApiError::from(e);
                match waiter.kind {
                    PendingKind::Join { reply, .. } => { let _ = reply.send(Err(err)); }
                    PendingKind::Program { reply, .. } => { let _ = reply.send(Err(err)); }
                    PendingKind::Transaction { reply, .. } => { let _ = reply.send(Err(err)); }
                }
            }
        }
    }
}

fn broadcast_gossip_and_direct(
    cfg: &NodeConfig,
    swarm: &mut libp2p::Swarm<VNetworkBehaviour>,
    topic: &gossipsub::IdentTopic,
    connected_peers: &BTreeSet<PeerId>,
    gossip_msg: P2pGossipMessage,
    direct_req: P2pSyncRequest,
) {
    if !cfg.enable_p2p {
        return;
    }
    if let Ok(bytes) = serde_json::to_vec(&gossip_msg) {
        let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes);
    }
    for peer in connected_peers {
        swarm.behaviour_mut().sync.send_request(peer, direct_req.clone());
    }
}

fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        Protocol::P2p(pid) => Some(pid),
        _ => None,
    })
}

trait OptPair<A, B> {
    fn into_opt_pair(self) -> Option<(A, B)>;
}

impl<'a, A, B> OptPair<&'a A, &'a B> for (&'a Option<A>, &'a Option<B>) {
    fn into_opt_pair(self) -> Option<(&'a A, &'a B)> {
        match (self.0, self.1) {
            (Some(a), Some(b)) => Some((a, b)),
            _ => None,
        }
    }
}


#[cfg(test)]
mod shared_genesis_policy_tests {
    use super::requires_shared_genesis;
    use vnetwork_types::NetworkProfile;

    #[test]
    fn testnet_and_production_require_shared_genesis() {
        assert!(requires_shared_genesis(NetworkProfile::Testnet));
        assert!(requires_shared_genesis(NetworkProfile::Production));
        assert!(!requires_shared_genesis(NetworkProfile::Development));
    }
}
