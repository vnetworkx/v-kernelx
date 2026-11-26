use libp2p::identity as p2p_id;
use serde::Deserialize;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use vnetwork_types::*;
use zeroize::Zeroizing;

static TMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Options controlling identity key loading.
/// Does NOT derive `Debug` or `Clone` so secret passphrases are never accidentally printed or duplicated.
pub struct NodeIdentityLoadOptions {
    pub profile: NetworkProfile,
    pub passphrase: Option<Zeroizing<String>>,
    pub kdf_params: Option<KeyKdfParams>,
    pub allow_plaintext_key_fallback: bool,
    pub external_node_signer: Option<ExternalSignerProvider>,
    pub external_validator_signer: Option<ExternalSignerProvider>,
    pub transport_key_path: Option<PathBuf>,
}

impl fmt::Debug for NodeIdentityLoadOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeIdentityLoadOptions")
            .field("profile", &self.profile)
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "[REDACTED]"),
            )
            .field("kdf_params", &self.kdf_params)
            .field(
                "allow_plaintext_key_fallback",
                &self.allow_plaintext_key_fallback,
            )
            .field(
                "external_node_signer",
                &self.external_node_signer.as_ref().map(|s| &s.backend_name),
            )
            .field(
                "external_validator_signer",
                &self
                    .external_validator_signer
                    .as_ref()
                    .map(|s| &s.backend_name),
            )
            .field("transport_key_path", &self.transport_key_path)
            .finish()
    }
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
            transport_key_path: None,
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
    /// Loads or creates encrypted node/validator identities.
    /// Supported signing providers:
    /// - Local Argon2id + AES-256-GCM encrypted key envelopes (default for both node and validator)
    /// - `external_validator_signer`: HSM/remote consensus validator signer
    /// - `external_node_signer`: requires an explicit `transport_key_path` for the local libp2p Noise transport keypair
    pub fn load_or_create_secure(
        node_key_path: &Path,
        validator_key_path: Option<&Path>,
        explicit_validator_id: Option<&str>,
        enable_validator: bool,
        options: &NodeIdentityLoadOptions,
    ) -> VResult<Self> {
        let (node_signer, node_metadata, transport_protected) =
            if let Some(ext) = &options.external_node_signer {
                let transport_path = options.transport_key_path.as_deref().ok_or_else(|| {
                    VNetworkError::Authorization(
                        "external_node_signer requires `transport_key_path` for libp2p Noise session transport authentication"
                            .to_string(),
                    )
                })?;
                let (transport_sk, _transport_meta) =
                    load_or_generate_encrypted_key(transport_path, "node-transport", options)?;
                let mut meta = ext.metadata.clone();
                meta.storage_mode = format!("external:{}+encrypted-transport", ext.backend_name);
                let provider: Arc<dyn SigningProvider> = Arc::new(ext.clone());
                (provider, meta, transport_sk)
            } else {
                let (sk, meta) = load_or_generate_encrypted_key(node_key_path, "node", options)?;
                let provider: Arc<dyn SigningProvider> =
                    Arc::new(LocalEncryptedSigningProvider::new(sk.clone(), &meta.storage_mode));
                (provider, meta, sk)
            };

        let node_id = derive_node_id(&node_metadata.public_key_hex);
        let libp2p_keypair = to_libp2p_ed25519(&transport_protected)?;
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
            .filter(|s| !s.is_empty())
            .map(Zeroizing::new);
        let opts = NodeIdentityLoadOptions {
            profile: NetworkProfile::Production,
            passphrase,
            kdf_params: None,
            allow_plaintext_key_fallback: false,
            external_node_signer: None,
            external_validator_signer: None,
            transport_key_path: None,
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
    if options.profile == NetworkProfile::Production && options.allow_plaintext_key_fallback {
        return Err(VNetworkError::Authorization(
            "plaintext private key fallback is forbidden in PRODUCTION profile; use offline key migration"
                .to_string(),
        ));
    }
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
            let passphrase = options.passphrase.as_deref().map(|s| s.as_str()).ok_or_else(|| {
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
            if options.profile == NetworkProfile::Production || !options.allow_plaintext_key_fallback {
                return Err(VNetworkError::Authorization(format!(
                    "plaintext private key file `{:?}` refused (profile={}): run offline `migrate-key` to convert to an encrypted envelope",
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

    let passphrase = options.passphrase.as_deref().map(|s| s.as_str()).ok_or_else(|| {
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

/// Offline migration command helper converting a legacy plaintext key file into an
/// Argon2id + AES-256-GCM encrypted key envelope.
///
/// Follows fail-closed ordering:
/// 1. Verify legacy file exists, enforce strict file permissions (`0600` on Unix), and validate key material.
/// 2. Refuse to overwrite a pre-existing encrypted file at a separate destination path.
/// 3. Optionally write a protected backup copy (`0600`) with fsync.
/// 4. Encrypt & atomically write the encrypted envelope to `encrypted_dest_path`.
/// 5. Reload and decrypt the persisted encrypted file, confirming identical public identity.
/// 6. Only after verified persistence, optionally remove the original legacy file.
#[allow(clippy::too_many_arguments)]
pub fn migrate_plaintext_key_to_encrypted(
    legacy_path: &Path,
    encrypted_dest_path: &Path,
    expected_role: Option<&str>,
    passphrase: &Zeroizing<String>,
    kdf_params: Option<KeyKdfParams>,
    backup_path: Option<&Path>,
    remove_legacy_source: bool,
    timestamp_ms: u64,
) -> VResult<NodeIdentityMetadata> {
    if passphrase.is_empty() {
        return Err(VNetworkError::Authorization(
            "migration requires a non-empty passphrase".to_string(),
        ));
    }
    if !legacy_path.exists() {
        return Err(VNetworkError::NotFound(format!(
            "legacy plaintext key `{:?}` does not exist",
            legacy_path
        )));
    }
    enforce_strict_key_file_permissions(legacy_path)?;

    let raw = Zeroizing::new(
        fs::read_to_string(legacy_path)
            .map_err(|e| VNetworkError::Storage(format!("read legacy key {:?} failed: {e}", legacy_path)))?,
    );
    let val: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
        VNetworkError::Serialization(format!("parse legacy key {:?} failed: {e}", legacy_path))
    })?;
    if val.get("ciphertext_hex").is_some() {
        return Err(VNetworkError::Validation(format!(
            "source `{:?}` is already an encrypted key envelope",
            legacy_path
        )));
    }
    if val.get("private_key_hex").is_none() {
        return Err(VNetworkError::Validation(format!(
            "source `{:?}` is not a legacy plaintext private_key_hex file",
            legacy_path
        )));
    }
    let legacy: LegacyPlaintextKeyFile = serde_json::from_value(val).map_err(|e| {
        VNetworkError::Serialization(format!("parse legacy key {:?} failed: {e}", legacy_path))
    })?;
    let role = expected_role
        .or(legacy.key_role.as_deref())
        .unwrap_or("node");
    if let (Some(exp), Some(actual)) = (expected_role, legacy.key_role.as_deref()) {
        if exp != actual {
            return Err(VNetworkError::Authorization(format!(
                "legacy key role `{actual}` does not match expected role `{exp}`"
            )));
        }
    }
    let sk = ProtectedSigningKey::from_private_hex(role, &legacy.private_key_hex)?;
    if let Some(expected_pk) = &legacy.public_key_hex {
        if expected_pk != &sk.public_key_hex {
            return Err(VNetworkError::Signature(
                "legacy plaintext key public_key_hex does not match private seed".to_string(),
            ));
        }
    }

    if encrypted_dest_path != legacy_path && encrypted_dest_path.exists() {
        return Err(VNetworkError::Storage(format!(
            "refusing to overwrite existing destination key file `{:?}`",
            encrypted_dest_path
        )));
    }

    if let Some(bak) = backup_path {
        write_protected_file_atomic(bak, raw.as_bytes())?;
    }

    let history = vec![KeyRotationRecord {
        version: 1,
        previous_public_key_hex: None,
        new_public_key_hex: sk.public_key_hex.clone(),
        previous_derived_id: None,
        new_derived_id: sk.derived_id.clone(),
        rotated_at_ms: timestamp_ms,
        reason: "migrated_from_legacy_plaintext".to_string(),
    }];
    let env = sk.encrypt_to_envelope(
        passphrase.as_str(),
        kdf_params,
        1,
        timestamp_ms,
        None,
        history,
    )?;
    write_encrypted_envelope_atomic(encrypted_dest_path, &env)?;

    // Reload persisted file and verify decryption recovers identical public identity
    enforce_strict_key_file_permissions(encrypted_dest_path)?;
    let reloaded_raw = fs::read_to_string(encrypted_dest_path).map_err(|e| {
        VNetworkError::Storage(format!(
            "reload migrated envelope {:?} failed: {e}",
            encrypted_dest_path
        ))
    })?;
    let reloaded_env: EncryptedKeyEnvelope = serde_json::from_str(&reloaded_raw).map_err(|e| {
        VNetworkError::Serialization(format!(
            "parse reloaded migrated envelope {:?} failed: {e}",
            encrypted_dest_path
        ))
    })?;
    let verified_sk = ProtectedSigningKey::from_envelope(&reloaded_env, passphrase.as_str())?;
    if verified_sk.public_key_hex != sk.public_key_hex
        || verified_sk.derived_id != sk.derived_id
        || verified_sk.pubkey_fingerprint != sk.pubkey_fingerprint
    {
        return Err(VNetworkError::Storage(
            "migrated key verification failed: reloaded public identity diverges from source"
                .to_string(),
        ));
    }

    if remove_legacy_source && legacy_path != encrypted_dest_path {
        fs::remove_file(legacy_path).map_err(|e| {
            VNetworkError::Storage(format!(
                "migrated encrypted copy verified, but removing legacy source {:?} failed: {e}",
                legacy_path
            ))
        })?;
    }

    Ok(reloaded_env.metadata("encrypted-envelope-v1"))
}

pub fn rotate_encrypted_key(
    path: &Path,
    current_passphrase: &str,
    new_passphrase: &str,
    kdf_params: Option<KeyKdfParams>,
    reason: &str,
    timestamp_ms: u64,
) -> VResult<(ProtectedSigningKey, NodeIdentityMetadata)> {
    if new_passphrase.is_empty() {
        return Err(VNetworkError::Authorization(
            "new key rotation passphrase cannot be empty".to_string(),
        ));
    }
    enforce_strict_key_file_permissions(path)?;
    let raw = fs::read_to_string(path)
        .map_err(|e| VNetworkError::Storage(format!("read key {:?} failed: {e}", path)))?;
    let prev_env: EncryptedKeyEnvelope = serde_json::from_str(&raw).map_err(|e| {
        VNetworkError::Serialization(format!("parse encrypted key envelope {:?} failed: {e}", path))
    })?;
    let old_sk = ProtectedSigningKey::from_envelope(&prev_env, current_passphrase)?;

    let new_sk = ProtectedSigningKey::generate(&prev_env.key_role);
    let next_version = prev_env.key_version.checked_add(1).ok_or_else(|| {
        VNetworkError::Validation("key_version u32 overflow during key rotation".to_string())
    })?;
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

    // Verify new encrypted envelope decrypts cleanly BEFORE replacing existing file
    let preflight_sk = ProtectedSigningKey::from_envelope(&next_env, new_passphrase)?;
    if preflight_sk.public_key_hex != new_sk.public_key_hex {
        return Err(VNetworkError::Storage(
            "pre-write verification of rotated key envelope failed".to_string(),
        ));
    }

    write_encrypted_envelope_atomic(path, &next_env)?;

    // Reload & decrypt from disk to verify durable replacement
    enforce_strict_key_file_permissions(path)?;
    let reloaded_raw = fs::read_to_string(path)
        .map_err(|e| VNetworkError::Storage(format!("reload rotated key {:?} failed: {e}", path)))?;
    let reloaded_env: EncryptedKeyEnvelope = serde_json::from_str(&reloaded_raw).map_err(|e| {
        VNetworkError::Serialization(format!(
            "parse reloaded rotated envelope {:?} failed: {e}",
            path
        ))
    })?;
    let verified_sk = ProtectedSigningKey::from_envelope(&reloaded_env, new_passphrase)?;
    if verified_sk.public_key_hex != new_sk.public_key_hex
        || reloaded_env.key_version != next_version
    {
        return Err(VNetworkError::Storage(
            "rotated key verification failed after atomic write".to_string(),
        ));
    }

    let meta = reloaded_env.metadata("encrypted-envelope-v1");
    Ok((verified_sk, meta))
}

fn write_protected_file_atomic(path: &Path, payload: &[u8]) -> VResult<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| VNetworkError::Storage(format!("create key dir failed: {e}")))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|e| {
                    VNetworkError::Storage(format!(
                        "set mode 0700 on key dir {:?} failed: {e}",
                        parent
                    ))
                })?;
            }
        }
    }

    let seq = TMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("key.json");
    let tmp = path.with_file_name(format!("{fname}.tmp.{}.{seq}", std::process::id()));

    let write_res: VResult<()> = (|| {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| {
                    VNetworkError::Storage(format!(
                        "create exclusive tmp key {:?} failed: {e}",
                        tmp
                    ))
                })?
        };
        #[cfg(not(unix))]
        // Windows does not use POSIX 0600 mode bits; operators must rely on user/service ACLs on the directory.
        let mut f = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)
            .map_err(|e| {
                VNetworkError::Storage(format!("create exclusive tmp key {:?} failed: {e}", tmp))
            })?;

        f.write_all(payload)
            .map_err(|e| VNetworkError::Storage(format!("write tmp key {:?} failed: {e}", tmp)))?;
        f.sync_all()
            .map_err(|e| VNetworkError::Storage(format!("fsync tmp key {:?} failed: {e}", tmp)))?;
        drop(f);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
                .map_err(|e| VNetworkError::Storage(format!("chmod 0600 {:?} failed: {e}", tmp)))?;
        }
        fs::rename(&tmp, path)
            .map_err(|e| VNetworkError::Storage(format!("atomic rename {:?} failed: {e}", path)))?;
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }

    #[cfg(unix)]
    {
        let parent_dir = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let d = fs::File::open(parent_dir).map_err(|e| {
            VNetworkError::Storage(format!(
                "open key parent dir {:?} for fsync failed: {e}",
                parent_dir
            ))
        })?;
        d.sync_all().map_err(|e| {
            VNetworkError::Storage(format!("fsync key parent dir {:?} failed: {e}", parent_dir))
        })?;
    }

    Ok(())
}

pub fn write_encrypted_envelope_atomic(path: &Path, envelope: &EncryptedKeyEnvelope) -> VResult<()> {
    let json = Zeroizing::new(
        serde_json::to_vec_pretty(envelope)
            .map_err(|e| VNetworkError::Serialization(e.to_string()))?,
    );
    write_protected_file_atomic(path, &json)
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
    #[cfg(not(unix))]
    {
        // On non-Unix targets (e.g. Windows), POSIX mode bits do not exist; callers should ensure ACL isolation.
        if !path.exists() {
            return Err(VNetworkError::NotFound(format!(
                "key file `{:?}` does not exist",
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
