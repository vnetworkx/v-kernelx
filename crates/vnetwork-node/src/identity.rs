use libp2p::identity as p2p_id;
use serde::Deserialize;
use std::fmt;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use vnetwork_types::*;
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct NodeIdentityLoadOptions {
    pub profile: NetworkProfile,
    pub passphrase: Option<String>,
    pub kdf_params: Option<KeyKdfParams>,
    pub allow_plaintext_key_fallback: bool,
    pub external_node_signer: Option<ExternalSignerProvider>,
    pub external_validator_signer: Option<ExternalSignerProvider>,
}

impl Default for NodeIdentityLoadOptions {
    fn default() -> Self {
        Self {
            profile: NetworkProfile::Development,
            passphrase: None,
            kdf_params: None,
            allow_plaintext_key_fallback: false,
            external_node_signer: None,
            external_validator_signer: None,
        }
    }
}

#[derive(Clone)]
pub struct NodeIdentity {
    pub node_signer: Arc<dyn SigningProvider>,
    pub node_metadata: NodeIdentityMetadata,
    pub node_id: String,
    pub libp2p_keypair: p2p_id::Keypair,
    pub libp2p_peer_id: libp2p::PeerId,
    pub validator_signer: Option<Arc<dyn SigningProvider>>,
    pub validator_metadata: Option<NodeIdentityMetadata>,
    pub validator_id: Option<String>,
    pub storage_security_mode: String,
}

impl fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("node_id", &self.node_id)
            .field("node_metadata", &self.node_metadata)
            .field("libp2p_peer_id", &self.libp2p_peer_id.to_string())
            .field("validator_id", &self.validator_id)
            .field("validator_metadata", &self.validator_metadata)
            .field("storage_security_mode", &self.storage_security_mode)
            .finish()
    }
}

#[derive(Deserialize)]
struct LegacyPlaintextKeyFile {
    key_role: Option<String>,
    public_key_hex: Option<String>,
    private_key_hex: String,
}

impl NodeIdentity {
    pub fn load_or_create_secure(
        node_key_path: &Path,
        validator_key_path: Option<&Path>,
        explicit_validator_id: Option<&str>,
        enable_validator: bool,
        options: &NodeIdentityLoadOptions,
    ) -> VResult<Self> {
        let (node_signer, node_metadata, node_protected) = if let Some(ext) = &options.external_node_signer {
            let meta = ext.metadata.clone();
            let err_msg = "external_node_signer cannot construct libp2p ed25519 transport without protected seed; provide protected or pass seed";
            let _ = err_msg;
            // For libp2p Swarm transport, external node signers still keep local encrypted libp2p transport OR fail cleanly
            return Err(VNetworkError::Authorization(
                "external_node_signer requires load_or_create_with_libp2p_keypair; use external_validator_signer for consensus HSM signing".to_string(),
            ));
        } else {
            let (sk, meta) = load_or_generate_encrypted_key(node_key_path, "node", options)?;
            let provider: Arc<dyn SigningProvider> =
                Arc::new(LocalEncryptedSigningProvider::new(sk.clone(), &meta.storage_mode));
            (provider, meta, sk)
        };

        let node_id = derive_node_id(&node_metadata.public_key_hex);
        let libp2p_keypair = to_libp2p_ed25519(&node_protected)?;
        let libp2p_peer_id = libp2p::PeerId::from(libp2p_keypair.public());

        let (validator_signer, validator_metadata, validator_id, storage_security_mode) =
            if enable_validator {
                let (v_signer, v_meta) = if let Some(ext_val) = &options.external_validator_signer {
                    let meta = ext_val.metadata.clone();
                    let provider: Arc<dyn SigningProvider> = Arc::new(ext_val.clone());
                    (provider, meta)
                } else {
                    let vpath = validator_key_path.map(|p| p.to_path_buf()).unwrap_or_else(|| {
                        node_key_path
                            .parent()
                            .unwrap_or_else(|| Path::new("."))
                            .join("validator.key.json")
                    });
                    let (vsk, vmeta) = load_or_generate_encrypted_key(&vpath, "validator", options)?;
                    let provider: Arc<dyn SigningProvider> =
                        Arc::new(LocalEncryptedSigningProvider::new(vsk, &vmeta.storage_mode));
                    (provider, vmeta)
                };

                let node_pk = canonical_ed25519_pubkey_bytes(&node_metadata.public_key_hex)?;
                let val_pk = canonical_ed25519_pubkey_bytes(&v_meta.public_key_hex)?;
                if node_pk == val_pk {
                    return Err(VNetworkError::Authorization(
                        "validator key must remain distinct from node identity key".to_string(),
                    ));
                }
                let vid = explicit_validator_id
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("val_{}", &v_meta.public_key_hex[..16]));
                let mode = format!("node:{};validator:{}", node_metadata.storage_mode, v_meta.storage_mode);
                (Some(v_signer), Some(v_meta), Some(vid), mode)
            } else {
                (None, None, None, node_metadata.storage_mode.clone())
            };

        Ok(Self {
            node_signer,
            node_metadata,
            node_id,
            libp2p_keypair,
            libp2p_peer_id,
            validator_signer,
            validator_metadata,
            validator_id,
            storage_security_mode,
        })
    }

    pub fn load_or_create(
        node_key_path: &Path,
        validator_key_path: Option<&Path>,
        explicit_validator_id: Option<&str>,
        enable_validator: bool,
    ) -> VResult<Self> {
        let passphrase = std::env::var("NETWORK_KEY_PASSPHRASE")
            .ok()
            .filter(|s| !s.is_empty());
        let allow_plaintext_key_fallback = std::env::var("NETWORK_ALLOW_PLAINTEXT_KEY_FALLBACK")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        let opts = NodeIdentityLoadOptions {
            profile: NetworkProfile::Production,
            passphrase,
            kdf_params: None,
            allow_plaintext_key_fallback,
            external_node_signer: None,
            external_validator_signer: None,
        };
        Self::load_or_create_secure(
            node_key_path,
            validator_key_path,
            explicit_validator_id,
            enable_validator,
            &opts,
        )
    }
}

pub fn load_or_generate_encrypted_key(
    path: &Path,
    role: &str,
    options: &NodeIdentityLoadOptions,
) -> VResult<(ProtectedSigningKey, NodeIdentityMetadata)> {
    if path.exists() {
        enforce_strict_key_file_permissions(path)?;
        let raw = fs::read_to_string(path)
            .map_err(|e| VNetworkError::Storage(format!("read key {:?} failed: {e}", path)))?;
        let val: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|e| VNetworkError::Serialization(format!("parse key {:?} failed: {e}", path)))?;

        if val.get("ciphertext_hex").is_some() {
            let env: EncryptedKeyEnvelope = serde_json::from_value(val).map_err(|e| {
                VNetworkError::Serialization(format!("parse encrypted key envelope {:?} failed: {e}", path))
            })?;
            let passphrase = options.passphrase.as_deref().ok_or_else(|| {
                VNetworkError::Authorization(format!(
                    "passphrase required to unlock encrypted key `{:?}`",
                    path
                ))
            })?;
            let sk = ProtectedSigningKey::from_envelope(&env, passphrase)?;
            let meta = env.metadata("encrypted-envelope-v1");
            return Ok((sk, meta));
        }

        if val.get("private_key_hex").is_some() {
            if !options.allow_plaintext_key_fallback {
                return Err(VNetworkError::Authorization(format!(
                    "plaintext private key file `{:?}` refused (profile={}): migrate to encrypted envelope or pass explicit allow_plaintext_key_fallback override",
                    path,
                    options.profile.as_str()
                )));
            }
            let legacy: LegacyPlaintextKeyFile = serde_json::from_value(val).map_err(|e| {
                VNetworkError::Serialization(format!("parse legacy key {:?} failed: {e}", path))
            })?;
            let actual_role = legacy.key_role.as_deref().unwrap_or(role);
            let sk = ProtectedSigningKey::from_private_hex(actual_role, &legacy.private_key_hex)?;
            if let Some(expected_pk) = &legacy.public_key_hex {
                if expected_pk != &sk.public_key_hex {
                    return Err(VNetworkError::Signature(
                        "legacy plaintext key public_key_hex does not match private seed".to_string(),
                    ));
                }
            }
            let meta = sk.metadata("legacy-plaintext-override", 1, now_ms(), None, Vec::new());
            return Ok((sk, meta));
        }

        return Err(VNetworkError::Storage(format!(
            "unrecognized key file format at `{:?}`",
            path
        )));
    }

    let passphrase = options.passphrase.as_deref().ok_or_else(|| {
        VNetworkError::Authorization(format!(
            "cannot generate encrypted key `{:?}` without keystore passphrase",
            path
        ))
    })?;

    let sk = ProtectedSigningKey::generate(role);
    let now = now_ms();
    let history = vec![KeyRotationRecord {
        version: 1,
        previous_public_key_hex: None,
        new_public_key_hex: sk.public_key_hex.clone(),
        previous_derived_id: None,
        new_derived_id: sk.derived_id.clone(),
        rotated_at_ms: now,
        reason: "initial_generation".to_string(),
    }];
    let env = sk.encrypt_to_envelope(
        passphrase,
        options.kdf_params.clone(),
        1,
        now,
        None,
        history,
    )?;
    write_encrypted_envelope_atomic(path, &env)?;
    let meta = env.metadata("encrypted-envelope-v1");
    Ok((sk, meta))
}

pub fn rotate_encrypted_key(
    path: &Path,
    current_passphrase: &str,
    new_passphrase: &str,
    kdf_params: Option<KeyKdfParams>,
    reason: &str,
    timestamp_ms: u64,
) -> VResult<(ProtectedSigningKey, NodeIdentityMetadata)> {
    let raw = fs::read_to_string(path)
        .map_err(|e| VNetworkError::Storage(format!("read key {:?} failed: {e}", path)))?;
    let prev_env: EncryptedKeyEnvelope = serde_json::from_str(&raw).map_err(|e| {
        VNetworkError::Serialization(format!("parse encrypted key envelope {:?} failed: {e}", path))
    })?;
    let old_sk = ProtectedSigningKey::from_envelope(&prev_env, current_passphrase)?;

    let new_sk = ProtectedSigningKey::generate(&prev_env.key_role);
    let next_version = prev_env.key_version.saturating_add(1);
    let mut history = prev_env.rotation_history.clone();
    history.push(KeyRotationRecord {
        version: next_version,
        previous_public_key_hex: Some(old_sk.public_key_hex.clone()),
        new_public_key_hex: new_sk.public_key_hex.clone(),
        previous_derived_id: Some(old_sk.derived_id.clone()),
        new_derived_id: new_sk.derived_id.clone(),
        rotated_at_ms: timestamp_ms,
        reason: reason.to_string(),
    });
    let next_env = new_sk.encrypt_to_envelope(
        new_passphrase,
        kdf_params.or_else(|| Some(prev_env.kdf_params.clone())),
        next_version,
        prev_env.created_at_ms,
        Some(timestamp_ms),
        history,
    )?;
    write_encrypted_envelope_atomic(path, &next_env)?;
    let meta = next_env.metadata("encrypted-envelope-v1");
    Ok((new_sk, meta))
}

pub fn write_encrypted_envelope_atomic(path: &Path, envelope: &EncryptedKeyEnvelope) -> VResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| VNetworkError::Storage(format!("create key dir failed: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    let json = Zeroizing::new(
        serde_json::to_vec_pretty(envelope)
            .map_err(|e| VNetworkError::Serialization(e.to_string()))?,
    );
    let tmp = path.with_extension("json.enc.tmp");
    {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| VNetworkError::Storage(format!("create encrypted tmp key {:?} failed: {e}", tmp)))?
        };
        #[cfg(not(unix))]
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)
            .map_err(|e| VNetworkError::Storage(format!("create encrypted tmp key {:?} failed: {e}", tmp)))?;

        f.write_all(&json)
            .map_err(|e| VNetworkError::Storage(format!("write encrypted tmp key failed: {e}")))?;
        f.sync_all()
            .map_err(|e| VNetworkError::Storage(format!("fsync encrypted tmp key failed: {e}")))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
            .map_err(|e| VNetworkError::Storage(format!("chmod 0600 {:?} failed: {e}", tmp)))?;
    }
    fs::rename(&tmp, path)
        .map_err(|e| VNetworkError::Storage(format!("atomic rename {:?} failed: {e}", path)))?;
    if let Some(parent) = path.parent() {
        if let Ok(d) = File::open(parent) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

pub fn enforce_strict_key_file_permissions(path: &Path) -> VResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(path)
            .map_err(|e| VNetworkError::Storage(format!("stat key {:?} failed: {e}", path)))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(VNetworkError::Authorization(format!(
                "insecure permissions {mode:04o} on key file `{:?}`; expected 0600",
                path
            )));
        }
    }
    Ok(())
}

pub fn export_redacted_metadata_json(path: &Path, metadata: &NodeIdentityMetadata) -> VResult<()> {
    let bytes = serde_json::to_vec_pretty(metadata)
        .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
    fs::write(path, bytes)
        .map_err(|e| VNetworkError::Storage(format!("write metadata {:?} failed: {e}", path)))?;
    Ok(())
}

pub fn to_libp2p_ed25519(sk: &ProtectedSigningKey) -> VResult<p2p_id::Keypair> {
    let mut seed_copy = Zeroizing::new(*sk.signing_key_bytes());
    p2p_id::Keypair::ed25519_from_bytes(seed_copy.as_mut())
        .map_err(|e| VNetworkError::Signature(format!("libp2p ed25519 key error: {e}")))
}
