use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use vnetwork_types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cert_path: String,
    #[serde(default)]
    pub key_path: String,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: String::new(),
            key_path: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub network_id: String,
    pub network_name: String,
    pub profile: NetworkProfile,
    pub protocol_version: String,
    pub node_name: String,
    pub node_kind: NodeKind,
    pub enable_p2p: bool,
    pub enable_public_api: bool,
    pub enable_validator: bool,
    #[serde(default)]
    pub enable_relay_server: bool,
    pub p2p_listen_addresses: Vec<String>,
    pub advertised_addresses: Vec<String>,
    pub bootstrap_peers: Vec<String>,
    pub discovery_mode: String,
    pub public_api_bind: String,
    pub public_api_url: String,
    pub storage_path: PathBuf,
    pub node_identity_path: PathBuf,
    pub validator_key_path: Option<PathBuf>,
    pub validator_id: Option<String>,
    #[serde(default)]
    pub genesis_validators: Vec<ConsensusValidator>,
    #[serde(default = "default_quorum_bps")]
    pub quorum_threshold_bps: u16,
    #[serde(default)]
    pub allow_bootstrap_atlas: Option<bool>,
    #[serde(default)]
    pub tls: TlsConfig,
}

fn default_quorum_bps() -> u16 {
    DEFAULT_BFT_QUORUM_BPS
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            network_id: "vector-devnet-1".to_string(),
            network_name: "Vector Development Network".to_string(),
            profile: NetworkProfile::Development,
            protocol_version: PROTOCOL_VERSION.to_string(),
            node_name: "vn-node-1".to_string(),
            node_kind: NodeKind::FullNode,
            enable_p2p: true,
            enable_public_api: true,
            enable_validator: false,
            enable_relay_server: false,
            p2p_listen_addresses: vec!["/ip4/127.0.0.1/tcp/7001".to_string()],
            advertised_addresses: Vec::new(),
            bootstrap_peers: Vec::new(),
            discovery_mode: "hybrid".to_string(),
            public_api_bind: "127.0.0.1:8080".to_string(),
            public_api_url: "http://127.0.0.1:8080".to_string(),
            storage_path: PathBuf::from("./data/node1"),
            node_identity_path: PathBuf::from("./data/node1/node.key.json"),
            validator_key_path: None,
            validator_id: None,
            genesis_validators: Vec::new(),
            quorum_threshold_bps: DEFAULT_BFT_QUORUM_BPS,
            allow_bootstrap_atlas: None,
            tls: TlsConfig::default(),
        }
    }
}

impl NodeConfig {
    pub fn from_toml_file(path: &Path) -> VResult<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| VNetworkError::Storage(format!("read config {:?} failed: {e}", path)))?;
        let mut cfg: Self = toml::from_str(&raw)
            .map_err(|e| VNetworkError::Validation(format!("parse config {:?} failed: {e}", path)))?;
        cfg.apply_env_overrides();
        Ok(cfg)
    }

    pub fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("NETWORK_ID") {
            if !v.trim().is_empty() {
                self.network_id = v.trim().to_string();
            }
        }
        if let Ok(v) = std::env::var("NETWORK_NAME") {
            if !v.trim().is_empty() {
                self.network_name = v.trim().to_string();
            }
        }
        if let Ok(v) = std::env::var("NETWORK_PROFILE") {
            if let Some(p) = NetworkProfile::parse(&v) {
                self.profile = p;
            }
        }
        if let Ok(v) = std::env::var("NETWORK_PROTOCOL_VERSION") {
            if !v.trim().is_empty() {
                self.protocol_version = v.trim().to_string();
            }
        }
        if let Ok(v) = std::env::var("NETWORK_BOOTSTRAP_PEERS") {
            self.bootstrap_peers = split_csv(&v);
        }
        if let Ok(v) = std::env::var("NETWORK_LISTEN_ADDRESSES").or_else(|_| std::env::var("NETWORK_P2P_LISTEN_ADDRS")) {
            let list = split_csv(&v);
            if !list.is_empty() {
                self.p2p_listen_addresses = list;
            }
        }
        if let Ok(v) = std::env::var("NETWORK_ADVERTISED_ADDRESSES") {
            self.advertised_addresses = split_csv(&v);
        }
        if let Ok(v) = std::env::var("NETWORK_PUBLIC_API") {
            if !v.trim().is_empty() {
                self.public_api_url = v.trim().to_string();
            }
        }
        if let Ok(v) = std::env::var("NETWORK_PUBLIC_API_BIND").or_else(|_| std::env::var("NETWORK_API_LISTEN_ADDR")) {
            if !v.trim().is_empty() {
                self.public_api_bind = v.trim().to_string();
            }
        }
        if let Ok(v) = std::env::var("NETWORK_NODE_IDENTITY").or_else(|_| std::env::var("NETWORK_IDENTITY_PATH")) {
            if !v.trim().is_empty() {
                self.node_identity_path = PathBuf::from(v.trim());
            }
        }
        if let Ok(v) = std::env::var("NETWORK_VALIDATOR_KEY_PATH") {
            if !v.trim().is_empty() {
                self.validator_key_path = Some(PathBuf::from(v.trim()));
            }
        }
        if let Ok(v) = std::env::var("NETWORK_VALIDATOR_ID") {
            if !v.trim().is_empty() {
                self.validator_id = Some(v.trim().to_string());
            }
        }
        if let Ok(v) = std::env::var("NETWORK_STORAGE_PATH") {
            if !v.trim().is_empty() {
                self.storage_path = PathBuf::from(v.trim());
            }
        }
        if let Ok(v) = std::env::var("NETWORK_DISCOVERY_MODE") {
            if !v.trim().is_empty() {
                self.discovery_mode = v.trim().to_string();
            }
        }
        if let Ok(v) = std::env::var("NETWORK_ENABLE_PUBLIC_API") {
            self.enable_public_api = parse_bool(&v);
        }
        if let Ok(v) = std::env::var("NETWORK_ENABLE_P2P") {
            self.enable_p2p = parse_bool(&v);
        }
        if let Ok(v) = std::env::var("NETWORK_NODE_KIND") {
            match v.trim().to_ascii_uppercase().as_str() {
                "VALIDATOR" | "VALIDATOR_NODE" | "VALIDATORNODE" => {
                    self.node_kind = NodeKind::ValidatorNode;
                    self.enable_validator = true;
                }
                "BOOTSTRAP" | "BOOTSTRAP_SEED" | "BOOTSTRAPSEED" | "BOOTSTRAP_NODE" => {
                    self.node_kind = NodeKind::BootstrapSeed;
                }
                "FULL" | "FULL_NODE" | "FULLNODE" | "GATEWAY" | "GATEWAY_NODE" => {
                    self.node_kind = NodeKind::FullNode;
                }
                "LIGHT" | "LIGHT_PARTICIPANT" | "LIGHTPARTICIPANT" | "OBSERVER" | "OBSERVER_NODE" => {
                    self.node_kind = NodeKind::LightParticipant;
                }
                _ => {}
            }
        }
        if let Ok(v) = std::env::var("NETWORK_ENABLE_VALIDATOR") {
            self.enable_validator = parse_bool(&v);
            if self.enable_validator {
                self.node_kind = NodeKind::ValidatorNode;
            }
        }
        if let Ok(v) = std::env::var("NETWORK_ALLOW_BOOTSTRAP_ATLAS") {
            self.allow_bootstrap_atlas = Some(parse_bool(&v));
        }
        if let Ok(v) = std::env::var("NETWORK_TLS_CONFIGURATION") {
            if let Ok(tls) = serde_json::from_str::<TlsConfig>(&v) {
                self.tls = tls;
            }
        }
    }

    pub fn validate(&self) -> VResult<()> {
        if self.network_id.trim().is_empty() {
            return Err(VNetworkError::Validation("NETWORK_ID cannot be empty".to_string()));
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(VNetworkError::ProfileMismatch(format!(
                "unsupported protocol version `{}`; expected `{PROTOCOL_VERSION}`",
                self.protocol_version
            )));
        }
        if self.profile == NetworkProfile::Production
            && self.network_id.to_ascii_lowercase().contains("devnet")
        {
            return Err(VNetworkError::ProfileMismatch(
                "PRODUCTION profile cannot use a devnet network_id".to_string(),
            ));
        }
        Ok(())
    }
}

fn split_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_bool(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}
