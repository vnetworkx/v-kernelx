use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;
use vnetwork_api::{serve_api, ApiServerConfig};
use vnetwork_core::state::GenesisConfig;
use vnetwork_node::{start_node_runtime, NodeConfig, NodeIdentity, ShutdownSignal};

#[derive(Parser, Debug)]
#[command(name = "vnetwork-node", about = "Vector Network P2P + Consensus Node")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(long, env = "NETWORK_CONFIG_FILE")]
    config: Option<PathBuf>,

    #[arg(long, env = "NETWORK_GENESIS_FILE")]
    genesis_file: Option<PathBuf>,

    #[arg(long, env = "NETWORK_ID")]
    network_id: Option<String>,

    #[arg(long, env = "NETWORK_STORAGE_PATH")]
    storage_path: Option<PathBuf>,

    #[arg(long, env = "NETWORK_PUBLIC_API_BIND")]
    api_bind: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize node and optional validator keys and output public identity JSON
    InitKey {
        #[arg(long)]
        node_key: PathBuf,
        #[arg(long)]
        validator_key: Option<PathBuf>,
        #[arg(long)]
        validator_id: Option<String>,
        #[arg(long, default_value_t = false)]
        validator: bool,
    },
    /// Run the node runtime and optional public HTTP/WebSocket API
    Run,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();

    let cli = Cli::parse();

    if let Some(Commands::InitKey {
        node_key,
        validator_key,
        validator_id,
        validator,
    }) = cli.command
    {
        let id = NodeIdentity::load_or_create(
            &node_key,
            validator_key.as_deref(),
            validator_id.as_deref(),
            validator,
        )?;
        let out = serde_json::json!({
            "node_id": id.node_id,
            "node_pubkey_hex": id.node_keypair.public_key_hex,
            "peer_id": id.libp2p_peer_id.to_string(),
            "validator_id": id.validator_id,
            "validator_pubkey_hex": id.validator_keypair.as_ref().map(|k| k.public_key_hex.clone()),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    let mut cfg = if let Some(path) = &cli.config {
        NodeConfig::from_toml_file(path)?
    } else {
        let mut c = NodeConfig::default();
        c.apply_env_overrides();
        c
    };

    if let Some(nid) = cli.network_id {
        cfg.network_id = nid;
    }
    if let Some(sp) = cli.storage_path {
        cfg.storage_path = sp;
    }
    if let Some(bind) = cli.api_bind {
        cfg.public_api_bind = bind;
    }

    let explicit_genesis: Option<GenesisConfig> = if let Some(gpath) = &cli.genesis_file {
        let raw = std::fs::read_to_string(gpath)?;
        Some(serde_json::from_str(&raw)?)
    } else {
        None
    };

    let shutdown = ShutdownSignal::new();
    let shutdown_clone = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        shutdown_clone.trigger();
    });

    let (handle, node_task) = start_node_runtime(cfg.clone(), explicit_genesis, shutdown.clone()).await?;

    let api_task = if cfg.enable_public_api {
        let api_cfg = ApiServerConfig {
            bind_addr: cfg.public_api_bind.clone(),
            max_body_bytes: 2 * 1024 * 1024,
            rate_limit_per_min: 3000,
            tls_enabled: cfg.tls.enabled,
            tls_cert_path: (!cfg.tls.cert_path.is_empty()).then(|| PathBuf::from(&cfg.tls.cert_path)),
            tls_key_path: (!cfg.tls.key_path.is_empty()).then(|| PathBuf::from(&cfg.tls.key_path)),
        };
        let backend: Arc<dyn vnetwork_api::NetworkNodeBackend> = Arc::new(handle);
        Some(tokio::spawn(async move {
            if let Err(e) = serve_api(backend, api_cfg).await {
                tracing::error!(error = %e, "API server exited with error");
            }
        }))
    } else {
        None
    };

    let _ = node_task.await;
    if let Some(t) = api_task {
        t.abort();
    }
    Ok(())
}
