use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use vnetwork_core::state::GenesisConfig;
use vnetwork_types::*;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
    /// Explicit declaration that plaintext loopback/bridge traffic terminates behind
    /// an audited TLS-terminating reverse proxy (e.g., Caddy, Nginx, Ingress).
    pub terminated_by_reverse_proxy: bool,
}

impl TlsConfig {
    pub fn validate(&self) -> VResult<()> {
        if self.enabled {
            let cert = self.cert_path.trim();
            let key = self.key_path.trim();
            if cert.is_empty() || key.is_empty() {
                return Err(VNetworkError::Validation(
                    "tls.enabled=true requires non-empty tls.cert_path and tls.key_path"
                        .to_string(),
                ));
            }
            let cert_p = Path::new(cert);
            let key_p = Path::new(key);
            let cert_raw = std::fs::read_to_string(cert_p).map_err(|e| {
                VNetworkError::Storage(format!(
                    "read tls.cert_path `{}` failed: {e}",
                    cert_p.display()
                ))
            })?;
            if !cert_raw.contains("-----BEGIN CERTIFICATE-----") {
                return Err(VNetworkError::Validation(format!(
                    "tls.cert_path `{}` does not contain a PEM certificate",
                    cert_p.display()
                )));
            }
            crate::identity::enforce_strict_key_file_permissions(key_p)?;
            let key_raw = std::fs::read_to_string(key_p).map_err(|e| {
                VNetworkError::Storage(format!(
                    "read tls.key_path `{}` failed: {e}",
                    key_p.display()
                ))
            })?;
            if !key_raw.contains("-----BEGIN ") || !key_raw.contains("PRIVATE KEY-----") {
                return Err(VNetworkError::Validation(format!(
                    "tls.key_path `{}` does not contain a PEM private key",
                    key_p.display()
                )));
            }
        } else if !self.cert_path.trim().is_empty() || !self.key_path.trim().is_empty() {
            return Err(VNetworkError::Validation(
                "tls.cert_path / tls.key_path are set while tls.enabled=false".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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
    pub genesis_validators: Vec<ConsensusValidator>,
    pub quorum_threshold_bps: u16,
    pub allow_bootstrap_atlas: Option<bool>,
    pub genesis_file: Option<PathBuf>,
    pub key_passphrase_env: String,
    pub key_passphrase_file: Option<PathBuf>,
    pub allow_plaintext_key_fallback: bool,
    pub drain_policy: DrainPolicy,
    pub tls: TlsConfig,
}

fn default_passphrase_env() -> String {
    "NETWORK_KEY_PASSPHRASE".to_string()
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
            genesis_file: None,
            key_passphrase_env: default_passphrase_env(),
            key_passphrase_file: None,
            allow_plaintext_key_fallback: false,
            drain_policy: DrainPolicy::unconfigured(),
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
        cfg.apply_env_overrides()?;
        Ok(cfg)
    }

    pub fn apply_env_overrides(&mut self) -> VResult<()> {
        if let Ok(v) = std::env::var("NETWORK_ID") {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                return Err(VNetworkError::Validation(
                    "NETWORK_ID env override cannot be empty".to_string(),
                ));
            }
            self.network_id = trimmed.to_string();
        }
        if let Ok(v) = std::env::var("NETWORK_NAME") {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                return Err(VNetworkError::Validation(
                    "NETWORK_NAME env override cannot be empty".to_string(),
                ));
            }
            self.network_name = trimmed.to_string();
        }
        if let Ok(v) = std::env::var("NETWORK_PROFILE") {
            let p = NetworkProfile::parse(&v).ok_or_else(|| {
                VNetworkError::Validation(format!(
                    "invalid NETWORK_PROFILE `{}`; expected DEVELOPMENT, TESTNET, or PRODUCTION",
                    v.trim()
                ))
            })?;
            self.profile = p;
        }
        if let Ok(v) = std::env::var("NETWORK_PROTOCOL_VERSION") {
            let trimmed = v.trim();
            if trimmed != PROTOCOL_VERSION {
                return Err(VNetworkError::ProfileMismatch(format!(
                    "unsupported NETWORK_PROTOCOL_VERSION `{trimmed}`; expected `{PROTOCOL_VERSION}`"
                )));
            }
            self.protocol_version = trimmed.to_string();
        }
        if let Ok(v) = std::env::var("NETWORK_BOOTSTRAP_PEERS") {
            self.bootstrap_peers = split_csv(&v);
        }
        if let Ok(v) = std::env::var("NETWORK_LISTEN_ADDRESSES")
            .or_else(|_| std::env::var("NETWORK_P2P_LISTEN_ADDRS"))
        {
            let list = split_csv(&v);
            if list.is_empty() {
                return Err(VNetworkError::Validation(
                    "NETWORK_P2P_LISTEN_ADDRS / NETWORK_LISTEN_ADDRESSES cannot be empty when set"
                        .to_string(),
                ));
            }
            self.p2p_listen_addresses = list;
        }
        if let Ok(v) = std::env::var("NETWORK_ADVERTISED_ADDRESSES")
            .or_else(|_| std::env::var("NETWORK_ADVERTISED_ADDRS"))
        {
            self.advertised_addresses = split_csv(&v);
        }
        if let Ok(v) = std::env::var("NETWORK_PUBLIC_API")
            .or_else(|_| std::env::var("NETWORK_PUBLIC_API_URL"))
        {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                return Err(VNetworkError::Validation(
                    "NETWORK_PUBLIC_API_URL cannot be empty when set".to_string(),
                ));
            }
            self.public_api_url = trimmed.to_string();
        }
        if let Ok(v) = std::env::var("NETWORK_PUBLIC_API_BIND")
            .or_else(|_| std::env::var("NETWORK_API_LISTEN_ADDR"))
        {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                return Err(VNetworkError::Validation(
                    "NETWORK_PUBLIC_API_BIND / NETWORK_API_LISTEN_ADDR cannot be empty when set"
                        .to_string(),
                ));
            }
            self.public_api_bind = trimmed.to_string();
        }
        if let Ok(v) = std::env::var("NETWORK_NODE_IDENTITY")
            .or_else(|_| std::env::var("NETWORK_IDENTITY_PATH"))
        {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                return Err(VNetworkError::Validation(
                    "NETWORK_IDENTITY_PATH cannot be empty when set".to_string(),
                ));
            }
            self.node_identity_path = PathBuf::from(trimmed);
        }
        if let Ok(v) = std::env::var("NETWORK_VALIDATOR_KEY_PATH") {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                return Err(VNetworkError::Validation(
                    "NETWORK_VALIDATOR_KEY_PATH cannot be empty when set".to_string(),
                ));
            }
            self.validator_key_path = Some(PathBuf::from(trimmed));
        }
        if let Ok(v) = std::env::var("NETWORK_VALIDATOR_ID") {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                return Err(VNetworkError::Validation(
                    "NETWORK_VALIDATOR_ID cannot be empty when set".to_string(),
                ));
            }
            self.validator_id = Some(trimmed.to_string());
        }
        if let Ok(v) = std::env::var("NETWORK_STORAGE_PATH") {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                return Err(VNetworkError::Validation(
                    "NETWORK_STORAGE_PATH cannot be empty when set".to_string(),
                ));
            }
            self.storage_path = PathBuf::from(trimmed);
        }
        if let Ok(v) = std::env::var("NETWORK_DISCOVERY_MODE") {
            let trimmed = v.trim();
            validate_discovery_mode(trimmed)?;
            self.discovery_mode = trimmed.to_string();
        }
        if let Ok(v) = std::env::var("NETWORK_GENESIS_FILE")
            .or_else(|_| std::env::var("NETWORK_GENESIS_PATH"))
        {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                return Err(VNetworkError::Validation(
                    "NETWORK_GENESIS_FILE cannot be empty when set".to_string(),
                ));
            }
            self.genesis_file = Some(PathBuf::from(trimmed));
        }
        if let Ok(v) = std::env::var("NETWORK_QUORUM_THRESHOLD_BPS") {
            let bps = v.trim().parse::<u16>().map_err(|_| {
                VNetworkError::Validation(format!(
                    "invalid NETWORK_QUORUM_THRESHOLD_BPS `{}`: expected integer between {DEFAULT_BFT_QUORUM_BPS} and 10000",
                    v.trim()
                ))
            })?;
            if !(DEFAULT_BFT_QUORUM_BPS..=10_000).contains(&bps) {
                return Err(VNetworkError::Validation(format!(
                    "NETWORK_QUORUM_THRESHOLD_BPS `{bps}` must be between {DEFAULT_BFT_QUORUM_BPS} and 10000"
                )));
            }
            self.quorum_threshold_bps = bps;
        }
        if let Ok(v) = std::env::var("NETWORK_ENABLE_PUBLIC_API") {
            self.enable_public_api = parse_strict_bool(&v, "NETWORK_ENABLE_PUBLIC_API")?;
        }
        if let Ok(v) = std::env::var("NETWORK_ENABLE_P2P") {
            self.enable_p2p = parse_strict_bool(&v, "NETWORK_ENABLE_P2P")?;
        }

        let mut explicit_node_kind: Option<NodeKind> = None;
        if let Ok(v) = std::env::var("NETWORK_NODE_KIND") {
            let kind = match v.trim().to_ascii_uppercase().as_str() {
                "VALIDATOR" | "VALIDATOR_NODE" | "VALIDATORNODE" => NodeKind::ValidatorNode,
                "BOOTSTRAP" | "BOOTSTRAP_SEED" | "BOOTSTRAPSEED" | "BOOTSTRAP_NODE" => {
                    NodeKind::BootstrapSeed
                }
                "FULL" | "FULL_NODE" | "FULLNODE" | "GATEWAY" | "GATEWAY_NODE" => {
                    NodeKind::FullNode
                }
                "LIGHT" | "LIGHT_PARTICIPANT" | "LIGHTPARTICIPANT" | "OBSERVER"
                | "OBSERVER_NODE" => NodeKind::LightParticipant,
                other => {
                    return Err(VNetworkError::Validation(format!(
                        "invalid NETWORK_NODE_KIND `{other}`"
                    )));
                }
            };
            self.node_kind = kind;
            if kind == NodeKind::ValidatorNode {
                self.enable_validator = true;
            }
            explicit_node_kind = Some(kind);
        }
        if let Ok(v) = std::env::var("NETWORK_ENABLE_VALIDATOR") {
            let enabled = parse_strict_bool(&v, "NETWORK_ENABLE_VALIDATOR")?;
            if let Some(kind) = explicit_node_kind {
                if enabled && kind != NodeKind::ValidatorNode {
                    return Err(VNetworkError::Validation(format!(
                        "conflicting env configuration: NETWORK_ENABLE_VALIDATOR=true conflicts with NETWORK_NODE_KIND={:?}",
                        kind
                    )));
                }
                if !enabled && kind == NodeKind::ValidatorNode {
                    return Err(VNetworkError::Validation(
                        "conflicting env configuration: NETWORK_ENABLE_VALIDATOR=false conflicts with NETWORK_NODE_KIND=VALIDATOR_NODE".to_string(),
                    ));
                }
            } else if enabled {
                self.node_kind = NodeKind::ValidatorNode;
            } else if self.node_kind == NodeKind::ValidatorNode {
                self.node_kind = NodeKind::FullNode;
            }
            self.enable_validator = enabled;
        }
        if let Ok(v) = std::env::var("NETWORK_ALLOW_BOOTSTRAP_ATLAS") {
            self.allow_bootstrap_atlas =
                Some(parse_strict_bool(&v, "NETWORK_ALLOW_BOOTSTRAP_ATLAS")?);
        }
        if let Ok(v) = std::env::var("NETWORK_KEY_PASSPHRASE_FILE") {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                return Err(VNetworkError::Validation(
                    "NETWORK_KEY_PASSPHRASE_FILE cannot be empty when set".to_string(),
                ));
            }
            self.key_passphrase_file = Some(PathBuf::from(trimmed));
        }
        if let Ok(v) = std::env::var("NETWORK_DRAIN_POLICY") {
            let dp = serde_json::from_str::<DrainPolicy>(&v).map_err(|e| {
                VNetworkError::Validation(format!("invalid NETWORK_DRAIN_POLICY JSON: {e}"))
            })?;
            dp.validate()?;
            self.drain_policy = dp;
        }
        if let Ok(v) = std::env::var("NETWORK_TLS_CONFIGURATION") {
            let tls = serde_json::from_str::<TlsConfig>(&v).map_err(|e| {
                VNetworkError::Validation(format!(
                    "invalid NETWORK_TLS_CONFIGURATION JSON: {e}"
                ))
            })?;
            self.tls = tls;
        }
        Ok(())
    }

    pub fn resolve_key_passphrase(&self) -> VResult<Option<zeroize::Zeroizing<String>>> {
        if let Some(path) = &self.key_passphrase_file {
            crate::identity::enforce_strict_key_file_permissions(path)?;
            let raw = zeroize::Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
                VNetworkError::Storage(format!("read key passphrase file {:?} failed: {e}", path))
            })?);
            let trimmed = raw.trim().to_string();
            if !trimmed.is_empty() {
                return Ok(Some(zeroize::Zeroizing::new(trimmed)));
            }
        }
        if !self.key_passphrase_env.trim().is_empty() {
            if let Ok(val) = std::env::var(self.key_passphrase_env.trim()) {
                if !val.is_empty() {
                    return Ok(Some(zeroize::Zeroizing::new(val)));
                }
            }
        }
        if let Ok(val) = std::env::var("NETWORK_KEY_PASSPHRASE") {
            if !val.is_empty() {
                return Ok(Some(zeroize::Zeroizing::new(val)));
            }
        }
        Ok(None)
    }

    pub fn validate(&self) -> VResult<()> {
        if self.network_id.trim().is_empty() {
            return Err(VNetworkError::Validation("NETWORK_ID cannot be empty".to_string()));
        }
        if self.network_name.trim().is_empty() {
            return Err(VNetworkError::Validation("network_name cannot be empty".to_string()));
        }
        if self.node_name.trim().is_empty() {
            return Err(VNetworkError::Validation("node_name cannot be empty".to_string()));
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(VNetworkError::ProfileMismatch(format!(
                "unsupported protocol version `{}`; expected `{PROTOCOL_VERSION}`",
                self.protocol_version
            )));
        }
        if self.quorum_threshold_bps < DEFAULT_BFT_QUORUM_BPS || self.quorum_threshold_bps > 10_000 {
            return Err(VNetworkError::Validation(format!(
                "quorum_threshold_bps `{}` must be between {DEFAULT_BFT_QUORUM_BPS} and 10000",
                self.quorum_threshold_bps
            )));
        }
        validate_discovery_mode(&self.discovery_mode)?;

        if self.enable_validator && self.node_kind != NodeKind::ValidatorNode {
            return Err(VNetworkError::Validation(format!(
                "enable_validator=true conflicts with node_kind `{:?}`",
                self.node_kind
            )));
        }
        if !self.enable_validator && self.node_kind == NodeKind::ValidatorNode {
            return Err(VNetworkError::Validation(
                "node_kind=VALIDATOR_NODE requires enable_validator=true".to_string(),
            ));
        }

        if self.enable_p2p {
            if self.p2p_listen_addresses.is_empty() {
                return Err(VNetworkError::Validation(
                    "enable_p2p=true requires at least one p2p_listen_addresses entry".to_string(),
                ));
            }
            for addr in &self.p2p_listen_addresses {
                validate_multiaddr(addr, "p2p_listen_addresses")?;
            }
            for addr in &self.advertised_addresses {
                validate_multiaddr(addr, "advertised_addresses")?;
            }
            for addr in &self.bootstrap_peers {
                validate_multiaddr(addr, "bootstrap_peers")?;
            }
        }

        let parsed_api_bind = if self.enable_public_api {
            let sock = self.public_api_bind.parse::<SocketAddr>().map_err(|e| {
                VNetworkError::Validation(format!(
                    "invalid public_api_bind `{}`: {e}",
                    self.public_api_bind
                ))
            })?;
            let api_url = self.public_api_url.trim();
            if !api_url.starts_with("http://") && !api_url.starts_with("https://") {
                return Err(VNetworkError::Validation(format!(
                    "invalid public_api_url `{api_url}`: must begin with http:// or https://"
                )));
            }
            Some(sock)
        } else {
            None
        };

        self.tls.validate()?;
        self.drain_policy.validate()?;

        if !self.genesis_validators.is_empty() {
            validate_validator_set(&self.genesis_validators)?;
        }

        if self.profile == NetworkProfile::Production {
            if self.allow_plaintext_key_fallback {
                return Err(VNetworkError::Authorization(
                    "allow_plaintext_key_fallback is forbidden in PRODUCTION profile".to_string(),
                ));
            }
            if self.allow_bootstrap_atlas == Some(true) {
                return Err(VNetworkError::Authorization(
                    "allow_bootstrap_atlas=true is forbidden in PRODUCTION profile".to_string(),
                ));
            }
            if self.network_id.to_ascii_lowercase().contains("devnet") {
                return Err(VNetworkError::ProfileMismatch(
                    "PRODUCTION profile cannot use a devnet network_id".to_string(),
                ));
            }
            if let Some(sock) = parsed_api_bind {
                if !sock.ip().is_loopback()
                    && !self.tls.enabled
                    && !self.tls.terminated_by_reverse_proxy
                {
                    return Err(VNetworkError::Authorization(format!(
                        "PRODUCTION public_api_bind `{}` exposes plaintext HTTP/WS on non-loopback interface without tls.enabled=true or tls.terminated_by_reverse_proxy=true",
                        self.public_api_bind
                    )));
                }
                let url_lower = self.public_api_url.trim().to_ascii_lowercase();
                if url_lower.starts_with("http://")
                    && !url_lower.starts_with("http://127.0.0.1")
                    && !url_lower.starts_with("http://localhost")
                    && !url_lower.starts_with("http://[::1]")
                {
                    return Err(VNetworkError::Authorization(format!(
                        "PRODUCTION public_api_url `{}` must use https:// for non-loopback endpoints",
                        self.public_api_url
                    )));
                }
            }
        }
        Ok(())
    }

    /// Ensures the local node configuration does not contradict the authoritative GenesisConfig.
    pub fn validate_against_genesis(&self, genesis: &GenesisConfig) -> VResult<()> {
        self.validate()?;
        genesis.validate()?;

        if self.network_id != genesis.network_id {
            return Err(VNetworkError::ProfileMismatch(format!(
                "config network_id `{}` conflicts with genesis network_id `{}`",
                self.network_id, genesis.network_id
            )));
        }
        if self.network_name != genesis.network_name {
            return Err(VNetworkError::ProfileMismatch(format!(
                "config network_name `{}` conflicts with genesis network_name `{}`",
                self.network_name, genesis.network_name
            )));
        }
        if self.profile != genesis.profile {
            return Err(VNetworkError::ProfileMismatch(format!(
                "config profile `{:?}` conflicts with genesis profile `{:?}`",
                self.profile, genesis.profile
            )));
        }
        if self.protocol_version != genesis.protocol_version {
            return Err(VNetworkError::ProfileMismatch(format!(
                "config protocol_version `{}` conflicts with genesis protocol_version `{}`",
                self.protocol_version, genesis.protocol_version
            )));
        }
        if self.quorum_threshold_bps != genesis.consensus_parameters.quorum_threshold_bps {
            return Err(VNetworkError::ProfileMismatch(format!(
                "config quorum_threshold_bps `{}` conflicts with genesis consensus_parameters.quorum_threshold_bps `{}`",
                self.quorum_threshold_bps, genesis.consensus_parameters.quorum_threshold_bps
            )));
        }
        if !self.genesis_validators.is_empty()
            && self.genesis_validators != genesis.initial_validators
        {
            return Err(VNetworkError::ProfileMismatch(
                "config genesis_validators list conflicts with genesis initial_validators"
                    .to_string(),
            ));
        }
        if self.drain_policy != DrainPolicy::unconfigured()
            && self.drain_policy != genesis.drain_policy
        {
            return Err(VNetworkError::ProfileMismatch(
                "config drain_policy conflicts with genesis drain_policy".to_string(),
            ));
        }
        if self.profile == NetworkProfile::Production && genesis.allow_bootstrap_atlas {
            return Err(VNetworkError::Authorization(
                "genesis.allow_bootstrap_atlas is forbidden in PRODUCTION profile".to_string(),
            ));
        }
        if let Some(local_allow) = self.allow_bootstrap_atlas {
            if local_allow != genesis.allow_bootstrap_atlas {
                return Err(VNetworkError::ProfileMismatch(format!(
                    "config allow_bootstrap_atlas `{local_allow}` conflicts with genesis allow_bootstrap_atlas `{}`",
                    genesis.allow_bootstrap_atlas
                )));
            }
        }
        Ok(())
    }
}

fn validate_discovery_mode(mode: &str) -> VResult<()> {
    match mode {
        "hybrid" | "kademlia" | "bootstrap" | "mdns" | "none" => Ok(()),
        other => Err(VNetworkError::Validation(format!(
            "invalid discovery_mode `{other}`; expected hybrid, kademlia, bootstrap, mdns, or none"
        ))),
    }
}

fn validate_multiaddr(raw: &str, field: &str) -> VResult<()> {
    raw.trim().parse::<Multiaddr>().map(|_| ()).map_err(|e| {
        VNetworkError::Validation(format!("invalid multiaddr `{raw}` in {field}: {e}"))
    })
}

fn split_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_strict_bool(raw: &str, var_name: &str) -> VResult<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(VNetworkError::Validation(format!(
            "invalid boolean `{other}` for {var_name}; expected true/false/1/0/yes/no/on/off"
        ))),
    }
}
