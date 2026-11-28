use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use vnetwork_core::state::GenesisConfig;
use vnetwork_node::NodeConfig;
use vnetwork_types::*;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn temp_test_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "vnetwork_cfg_{}_{}_{}",
        label,
        std::process::id(),
        now_ms()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn with_env_vars(pairs: &[(&str, &str)], f: impl FnOnce()) {
    let _guard = ENV_LOCK.lock().unwrap();
    let prev: Vec<(&str, Option<String>)> = pairs
        .iter()
        .map(|(k, _)| (*k, std::env::var(k).ok()))
        .collect();
    for (k, v) in pairs {
        std::env::set_var(k, v);
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    for (k, old) in prev {
        match old {
            Some(val) => std::env::set_var(k, val),
            None => std::env::remove_var(k),
        }
    }
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

#[test]
fn test_apply_env_overrides_rejects_malformed_or_conflicting_values() {
    with_env_vars(&[("NETWORK_ENABLE_P2P", "maybe")], || {
        let mut cfg = NodeConfig::default();
        assert!(cfg.apply_env_overrides().is_err());
    });

    with_env_vars(&[("NETWORK_PROFILE", "STAGING")], || {
        let mut cfg = NodeConfig::default();
        assert!(cfg.apply_env_overrides().is_err());
    });

    with_env_vars(&[("NETWORK_NODE_KIND", "ARBITRARY_ROLE")], || {
        let mut cfg = NodeConfig::default();
        assert!(cfg.apply_env_overrides().is_err());
    });

    with_env_vars(&[("NETWORK_QUORUM_THRESHOLD_BPS", "5000")], || {
        let mut cfg = NodeConfig::default();
        assert!(cfg.apply_env_overrides().is_err());
    });

    with_env_vars(&[("NETWORK_QUORUM_THRESHOLD_BPS", "not_a_number")], || {
        let mut cfg = NodeConfig::default();
        assert!(cfg.apply_env_overrides().is_err());
    });

    with_env_vars(&[("NETWORK_DISCOVERY_MODE", "magic_flood")], || {
        let mut cfg = NodeConfig::default();
        assert!(cfg.apply_env_overrides().is_err());
    });

    with_env_vars(&[("NETWORK_DRAIN_POLICY", "{bad-json")], || {
        let mut cfg = NodeConfig::default();
        assert!(cfg.apply_env_overrides().is_err());
    });

    with_env_vars(&[("NETWORK_TLS_CONFIGURATION", "{bad-json")], || {
        let mut cfg = NodeConfig::default();
        assert!(cfg.apply_env_overrides().is_err());
    });

    with_env_vars(
        &[
            ("NETWORK_NODE_KIND", "BOOTSTRAP_SEED"),
            ("NETWORK_ENABLE_VALIDATOR", "true"),
        ],
        || {
            let mut cfg = NodeConfig::default();
            assert!(cfg.apply_env_overrides().is_err());
        },
    );
}

#[test]
fn test_toml_rejects_unknown_fields_and_loads_examples() {
    let dir = temp_test_dir("toml");
    let bad_toml = dir.join("bad.toml");
    fs::write(
        &bad_toml,
        "network_id = \"vector-devnet-1\"\ntypo_field = true\n",
    )
    .unwrap();
    assert!(NodeConfig::from_toml_file(&bad_toml).is_err());

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root_dir = manifest_dir.parent().unwrap().parent().unwrap();
    let _guard = ENV_LOCK.lock().unwrap();
    let bootstrap_cfg =
        NodeConfig::from_toml_file(&root_dir.join("config/bootstrap.example.toml")).unwrap();
    bootstrap_cfg.validate().unwrap();
    let node_cfg = NodeConfig::from_toml_file(&root_dir.join("config/node.example.toml")).unwrap();
    node_cfg.validate().unwrap();

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_production_tls_and_address_validation() {
    let dir = temp_test_dir("prod_tls");
    let cert_path = dir.join("server.crt");
    let key_path = dir.join("server.key");
    fs::write(
        &cert_path,
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    fs::write(
        &key_path,
        "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    // Non-loopback bind without TLS or reverse proxy declaration must fail in PRODUCTION
    let mut cfg = NodeConfig {
        profile: NetworkProfile::Production,
        network_id: "vector-main".to_string(),
        network_name: "Vector Main".to_string(),
        public_api_bind: "0.0.0.0:8080".to_string(),
        public_api_url: "https://rpc.vectornetwork.example".to_string(),
        ..Default::default()
    };
    assert!(cfg.validate().is_err());

    // http:// public URL in PRODUCTION fails
    cfg.tls.terminated_by_reverse_proxy = true;
    cfg.public_api_url = "http://rpc.vectornetwork.example".to_string();
    assert!(cfg.validate().is_err());

    // Valid PEM TLS succeeds
    cfg.public_api_url = "https://rpc.vectornetwork.example".to_string();
    cfg.tls.terminated_by_reverse_proxy = false;
    cfg.tls.enabled = true;
    cfg.tls.cert_path = cert_path.to_string_lossy().to_string();
    cfg.tls.key_path = key_path.to_string_lossy().to_string();
    cfg.validate().unwrap();

    // Enabling allow_bootstrap_atlas in PRODUCTION fails
    cfg.allow_bootstrap_atlas = Some(true);
    assert!(cfg.validate().is_err());
    cfg.allow_bootstrap_atlas = Some(false);

    // Invalid multiaddr fails
    cfg.bootstrap_peers = vec!["not-a-multiaddr".to_string()];
    assert!(cfg.validate().is_err());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_validate_against_genesis_detects_conflicts() {
    let validator = KeypairMaterial::generate("validator");
    let val = ConsensusValidator {
        validator_id: "val_1".to_string(),
        node_id: "nod_1".to_string(),
        validator_pubkey_hex: validator.public_key_hex.clone(),
        weight: 100,
        active: true,
        joined_epoch: 1,
    };
    let genesis = GenesisConfig::for_profile(
        NetworkProfile::Production,
        "vector-main",
        "Vector Main",
        vec![val],
    );
    let mut cfg = NodeConfig {
        profile: NetworkProfile::Production,
        network_id: "vector-main".to_string(),
        network_name: "Vector Main".to_string(),
        ..Default::default()
    };
    cfg.validate_against_genesis(&genesis).unwrap();

    // Conflicting quorum_threshold_bps fails
    cfg.quorum_threshold_bps = 7500;
    assert!(cfg.validate_against_genesis(&genesis).is_err());
    cfg.quorum_threshold_bps = DEFAULT_BFT_QUORUM_BPS;

    // Conflicting network_id fails
    cfg.network_id = "vector-other".to_string();
    assert!(cfg.validate_against_genesis(&genesis).is_err());
}

#[test]
fn test_peer_dial_multiaddr_ssrf_guard() {
    use libp2p::Multiaddr;
    use vnetwork_node::config::validate_peer_dial_multiaddr;

    with_env_vars(&[("NETWORK_ALLOW_LOCAL_P2P", "invalid-bool")], || {
        let mut cfg = NodeConfig::default();
        assert!(cfg.apply_env_overrides().is_err());
    });
    with_env_vars(&[("NETWORK_ALLOW_LOCAL_P2P", "true")], || {
        let mut cfg = NodeConfig::default();
        cfg.apply_env_overrides().unwrap();
        assert!(cfg.allow_local_p2p);
    });

    for blocked in [
        "/ip4/127.0.0.1/tcp/7001",
        "/ip4/10.0.0.12/tcp/7001",
        "/ip4/172.16.4.5/tcp/7001",
        "/ip4/192.168.1.50/tcp/7001",
        "/ip4/169.254.169.254/tcp/80",
        "/ip4/100.64.1.2/tcp/7001",
        "/ip6/::1/tcp/7001",
        "/ip6/fe80::1/tcp/7001",
        "/ip6/fc00::1/tcp/7001",
        "/ip6/::ffff:127.0.0.1/tcp/7001",
        "/dns4/localhost/tcp/7001",
        "/dns/metadata.google.internal/tcp/80",
        "/tcp/7001",
    ] {
        let ma: Multiaddr = blocked.parse().unwrap();
        assert!(
            validate_peer_dial_multiaddr(&ma, NetworkProfile::Production, false).is_err(),
            "expected Production to block {blocked}"
        );
        assert!(
            validate_peer_dial_multiaddr(&ma, NetworkProfile::Testnet, false).is_err(),
            "expected Testnet to block {blocked}"
        );
    }

    let pub_ip: Multiaddr = "/ip4/8.8.8.8/tcp/7001".parse().unwrap();
    validate_peer_dial_multiaddr(&pub_ip, NetworkProfile::Production, false).unwrap();

    let pub_dns: Multiaddr = "/dns4/bootnode1.vectornetwork.example/tcp/7001"
        .parse()
        .unwrap();
    validate_peer_dial_multiaddr(&pub_dns, NetworkProfile::Production, false).unwrap();

    let loopback: Multiaddr = "/ip4/127.0.0.1/tcp/7001".parse().unwrap();
    validate_peer_dial_multiaddr(&loopback, NetworkProfile::Development, false).unwrap();
    validate_peer_dial_multiaddr(&loopback, NetworkProfile::Testnet, true).unwrap();
}
