use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;
use vnetwork_api::{serve_api, ApiServerConfig};
use vnetwork_core::state::GenesisConfig;
use vnetwork_node::{
    enforce_strict_key_file_permissions, migrate_plaintext_key_to_encrypted, rotate_encrypted_key,
    start_node_runtime, NodeConfig, NodeIdentity, NodeIdentityLoadOptions, ShutdownSignal,
};
use vnetwork_types::{NetworkProfile, VNetworkError};
use zeroize::Zeroizing;

#[derive(Parser)]
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

    #[arg(long, env = "NETWORK_KEY_PASSPHRASE")]
    key_passphrase: Option<String>,

    #[arg(long, env = "NETWORK_KEY_PASSPHRASE_FILE")]
    key_passphrase_file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize encrypted node and optional validator keys and output redacted public metadata JSON
    InitKey {
        #[arg(long)]
        node_key: PathBuf,
        #[arg(long)]
        validator_key: Option<PathBuf>,
        #[arg(long)]
        validator_id: Option<String>,
        #[arg(long, default_value_t = false)]
        validator: bool,
        #[arg(long, default_value = "development")]
        profile: String,
    },
    /// Offline migration converting a legacy plaintext key file into an encrypted envelope
    MigrateKey {
        #[arg(long)]
        legacy_key: PathBuf,
        #[arg(long)]
        dest_key: PathBuf,
        #[arg(long)]
        role: Option<String>,
        #[arg(long)]
        backup_path: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        remove_legacy_source: bool,
    },
    /// Rotate an encrypted key envelope and record versioned rotation history
    RotateKey {
        #[arg(long)]
        key_path: PathBuf,
        #[arg(long, env = "NETWORK_KEY_PASSPHRASE")]
        current_passphrase: String,
        #[arg(long, env = "NETWORK_NEW_KEY_PASSPHRASE")]
        new_passphrase: String,
        #[arg(long, default_value = "scheduled_rotation")]
        reason: String,
    },
    /// Run the node runtime and optional public HTTP/WebSocket API
    Run,
}

fn read_passphrase(
    inline: Option<String>,
    file: Option<PathBuf>,
) -> Result<Option<Zeroizing<String>>, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(p) = inline {
        if !p.is_empty() {
            return Ok(Some(Zeroizing::new(p)));
        }
    }
    if let Some(path) = file {
        enforce_strict_key_file_permissions(&path)?;
        let raw = Zeroizing::new(std::fs::read_to_string(&path)?);
        let trimmed = raw.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(Some(Zeroizing::new(trimmed)));
        }
    }
    Ok(None)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let mut cli = Cli::parse();
    let passphrase = read_passphrase(cli.key_passphrase.take(), cli.key_passphrase_file.clone())?;

    if let Some(Commands::InitKey {
        node_key,
        validator_key,
        validator_id,
        validator,
        profile,
    }) = cli.command
    {
        let parsed_profile = NetworkProfile::parse(&profile).ok_or_else(|| {
            VNetworkError::Validation(format!("invalid network profile `{profile}`"))
        })?;
        let opts = NodeIdentityLoadOptions {
            profile: parsed_profile,
            passphrase,
            kdf_params: None,
            allow_plaintext_key_fallback: false,
            external_node_signer: None,
            external_validator_signer: None,
            transport_key_path: None,
        };
        let id = NodeIdentity::load_or_create_secure(
            &node_key,
            validator_key.as_deref(),
            validator_id.as_deref(),
            validator,
            &opts,
        )?;
        let out = serde_json::json!({
            "node_id": id.node_id,
            "node_metadata": id.node_metadata,
            "peer_id": id.libp2p_peer_id.to_string(),
            "validator_id": id.validator_id,
            "validator_metadata": id.validator_metadata,
            "storage_security_mode": id.storage_security_mode,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    if let Some(Commands::MigrateKey {
        legacy_key,
        dest_key,
        role,
        backup_path,
        remove_legacy_source,
    }) = cli.command
    {
        let pass = passphrase.ok_or_else(|| {
            VNetworkError::Authorization(
                "offline key migration requires --key-passphrase-file or passphrase env"
                    .to_string(),
            )
        })?;
        let meta = migrate_plaintext_key_to_encrypted(
            &legacy_key,
            &dest_key,
            role.as_deref(),
            &pass,
            None,
            backup_path.as_deref(),
            remove_legacy_source,
            vnetwork_types::now_ms(),
        )?;
        println!("{}", serde_json::to_string_pretty(&meta)?);
        return Ok(());
    }

    if let Some(Commands::RotateKey {
        key_path,
        current_passphrase,
        new_passphrase,
        reason,
    }) = cli.command
    {
        let current_z = Zeroizing::new(current_passphrase);
        let new_z = Zeroizing::new(new_passphrase);
        let (_, meta) = rotate_encrypted_key(
            &key_path,
            current_z.as_str(),
            new_z.as_str(),
            None,
            &reason,
            vnetwork_types::now_ms(),
        )?;
        println!("{}", serde_json::to_string_pretty(&meta)?);
        return Ok(());
    }

    let mut cfg = if let Some(path) = &cli.config {
        NodeConfig::from_toml_file(path)?
    } else {
        let mut c = NodeConfig::default();
        c.apply_env_overrides()?;
        c
    };

    if let Some(nid) = cli.network_id {
        if nid.trim().is_empty() {
            return Err(Box::new(VNetworkError::Validation(
                "--network-id cannot be empty".to_string(),
            )) as Box<dyn std::error::Error + Send + Sync>);
        }
        cfg.network_id = nid;
    }
    if let Some(sp) = cli.storage_path {
        cfg.storage_path = sp;
    }
    if let Some(bind) = cli.api_bind {
        cfg.public_api_bind = bind;
    }
    if cli.key_passphrase_file.is_some() {
        cfg.key_passphrase_file = cli.key_passphrase_file;
    }

    let explicit_genesis: Option<GenesisConfig> =
        if let Some(gpath) = cli.genesis_file.as_ref().or(cfg.genesis_file.as_ref()) {
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

    let (handle, node_task) =
        start_node_runtime(cfg.clone(), explicit_genesis, shutdown.clone()).await?;

    let api_task = if cfg.enable_public_api {
        let api_cfg = ApiServerConfig {
            bind_addr: cfg.public_api_bind.clone(),
            max_body_bytes: 2 * 1024 * 1024,
            rate_limit_per_min: 3000,
            tls_enabled: cfg.tls.enabled,
            tls_cert_path: (!cfg.tls.cert_path.is_empty())
                .then(|| PathBuf::from(&cfg.tls.cert_path)),
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
