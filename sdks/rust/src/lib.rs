use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use v_langx::compiler::{compile_source_with_imports, CompiledProgram, FilesystemModuleResolver};
use vnetwork_types::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientIdentityMetadata {
    pub display_name: String,
    pub participant_id: String,
    pub participant_pubkey: String,
    pub node_id: String,
    pub node_pubkey: String,
    pub storage_mode: String,
    pub participant_key_version: u32,
    pub node_key_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedClientIdentity {
    pub envelope_version: u16,
    pub display_name: String,
    pub participant_id: String,
    pub node_id: String,
    pub participant_envelope: EncryptedKeyEnvelope,
    pub node_envelope: EncryptedKeyEnvelope,
}

/// Protected in-memory client identity holding zeroizing signing keys.
/// Does NOT derive `Serialize`/`Deserialize` to prevent accidental plaintext private-key persistence.
#[derive(Clone)]
pub struct ClientIdentity {
    pub participant_key: ProtectedSigningKey,
    pub node_key: ProtectedSigningKey,
    pub display_name: String,
    pub participant_id: String,
    pub node_id: String,
}

impl fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("display_name", &self.display_name)
            .field("participant_id", &self.participant_id)
            .field("participant_pubkey", &self.participant_key.public_key_hex)
            .field("node_id", &self.node_id)
            .field("node_pubkey", &self.node_key.public_key_hex)
            .finish()
    }
}

impl ClientIdentity {
    pub fn generate(display_name: impl Into<String>) -> Self {
        let participant_key = ProtectedSigningKey::generate("participant");
        let node_key = ProtectedSigningKey::generate("node");
        let participant_id = derive_participant_id(&participant_key.public_key_hex);
        let node_id = derive_node_id(&node_key.public_key_hex);
        Self {
            participant_key,
            node_key,
            display_name: display_name.into(),
            participant_id,
            node_id,
        }
    }

    pub fn from_keys(
        display_name: impl Into<String>,
        participant_priv_hex: &str,
        node_priv_hex: &str,
    ) -> VResult<Self> {
        let participant_key =
            ProtectedSigningKey::from_private_hex("participant", participant_priv_hex)?;
        let node_key = ProtectedSigningKey::from_private_hex("node", node_priv_hex)?;
        let participant_id = derive_participant_id(&participant_key.public_key_hex);
        let node_id = derive_node_id(&node_key.public_key_hex);
        Ok(Self {
            participant_key,
            node_key,
            display_name: display_name.into(),
            participant_id,
            node_id,
        })
    }

    pub fn encrypt_envelopes(
        &self,
        passphrase: &str,
        kdf_params: Option<KeyKdfParams>,
    ) -> VResult<EncryptedClientIdentity> {
        let now = now_ms();
        let participant_envelope = self.participant_key.encrypt_to_envelope(
            passphrase,
            kdf_params.clone(),
            1,
            now,
            None,
            Vec::new(),
        )?;
        let node_envelope =
            self.node_key
                .encrypt_to_envelope(passphrase, kdf_params, 1, now, None, Vec::new())?;
        Ok(EncryptedClientIdentity {
            envelope_version: ENCRYPTED_KEY_ENVELOPE_VERSION,
            display_name: self.display_name.clone(),
            participant_id: self.participant_id.clone(),
            node_id: self.node_id.clone(),
            participant_envelope,
            node_envelope,
        })
    }

    pub fn from_envelopes(encrypted: &EncryptedClientIdentity, passphrase: &str) -> VResult<Self> {
        let participant_key =
            ProtectedSigningKey::from_envelope(&encrypted.participant_envelope, passphrase)?;
        let node_key = ProtectedSigningKey::from_envelope(&encrypted.node_envelope, passphrase)?;
        if participant_key.derived_id != encrypted.participant_id
            || node_key.derived_id != encrypted.node_id
        {
            return Err(VNetworkError::Storage(
                "decrypted encrypted client identity does not match derived IDs".to_string(),
            ));
        }
        Ok(Self {
            participant_key,
            node_key,
            display_name: encrypted.display_name.clone(),
            participant_id: encrypted.participant_id.clone(),
            node_id: encrypted.node_id.clone(),
        })
    }

    pub fn metadata(&self, storage_mode: impl Into<String>) -> ClientIdentityMetadata {
        ClientIdentityMetadata {
            display_name: self.display_name.clone(),
            participant_id: self.participant_id.clone(),
            participant_pubkey: self.participant_key.public_key_hex.clone(),
            node_id: self.node_id.clone(),
            node_pubkey: self.node_key.public_key_hex.clone(),
            storage_mode: storage_mode.into(),
            participant_key_version: 1,
            node_key_version: 1,
        }
    }

    pub fn export_legacy_plaintext_keypairs_unsafe(&self) -> (KeypairMaterial, KeypairMaterial) {
        (
            self.participant_key.to_keypair_material_in_memory(),
            self.node_key.to_keypair_material_in_memory(),
        )
    }

    pub fn from_legacy_plaintext_keypairs_unsafe(
        display_name: impl Into<String>,
        participant: &KeypairMaterial,
        node: &KeypairMaterial,
    ) -> VResult<Self> {
        Self::from_keys(
            display_name,
            &participant.private_key_hex,
            &node.private_key_hex,
        )
    }
}

#[derive(Debug, Clone)]
pub struct NetworkConnectionInfo {
    pub network_id: String,
    pub network_name: String,
    pub profile: String,
    pub protocol_version: String,
    pub height: u64,
    pub state_root: String,
    pub raw: serde_json::Value,
}

fn reserve_sdk_nonce_file(
    file_path: &Path,
    network_id: &str,
    actor_pubkey: &str,
    minimum_next_nonce: u64,
    restrict_directory: bool,
) -> VResult<u64> {
    let directory = file_path.parent().ok_or_else(|| {
        VNetworkError::Storage("durable nonce file has no parent directory".to_string())
    })?;
    fs::create_dir_all(directory)
        .map_err(|e| VNetworkError::Storage(format!("create nonce directory failed: {e}")))?;
    if restrict_directory {
        #[cfg(unix)]
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .map_err(|e| VNetworkError::Storage(format!("secure nonce directory failed: {e}")))?;
    }

    let lock_path = PathBuf::from(format!("{}.lock", file_path.display()));
    let mut lock_file: Option<File> = None;
    for _ in 0..400 {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&lock_path) {
            Ok(file) => {
                lock_file = Some(file);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(error) => {
                return Err(VNetworkError::Storage(format!(
                    "create durable nonce lock failed: {error}"
                )));
            }
        }
    }
    let mut lock_file = lock_file.ok_or_else(|| {
        VNetworkError::Storage(format!(
            "timed out acquiring durable nonce lock {}; refusing to risk nonce reuse",
            lock_path.display()
        ))
    })?;
    writeln!(lock_file, "{{\"pid\":{}}}", std::process::id())
        .map_err(|e| VNetworkError::Storage(format!("write nonce lock failed: {e}")))?;
    lock_file
        .sync_all()
        .map_err(|e| VNetworkError::Storage(format!("sync nonce lock failed: {e}")))?;

    let result = (|| -> VResult<u64> {
        let mut current = minimum_next_nonce;
        match File::open(file_path) {
            Ok(mut file) => {
                let mut raw = String::new();
                file.read_to_string(&mut raw)
                    .map_err(|e| VNetworkError::Storage(format!("read nonce state failed: {e}")))?;
                let stored: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
                    VNetworkError::Storage(format!("parse nonce state failed: {e}"))
                })?;
                let stored_nonce = stored.get("next_nonce").and_then(|v| v.as_u64());
                if stored.get("version").and_then(|v| v.as_u64()) != Some(1)
                    || stored.get("network_id").and_then(|v| v.as_str()) != Some(network_id)
                    || stored.get("actor_pubkey").and_then(|v| v.as_str()) != Some(actor_pubkey)
                    || stored_nonce.map_or(true, |value| value == 0)
                {
                    return Err(VNetworkError::Storage(
                        "durable nonce state does not match network/participant or is invalid"
                            .to_string(),
                    ));
                }
                current = current.max(stored_nonce.unwrap());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(VNetworkError::Storage(format!(
                    "read nonce state failed: {error}"
                )));
            }
        }
        let next = current.checked_add(1).ok_or_else(|| {
            VNetworkError::Validation("request nonce exhausted u64 range".to_string())
        })?;
        let encoded = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "network_id": network_id,
            "actor_pubkey": actor_pubkey,
            "next_nonce": next,
        }))
        .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
        let temp_path = PathBuf::from(format!(
            "{}.tmp-{}-{}",
            file_path.display(),
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut temp = options
            .open(&temp_path)
            .map_err(|e| VNetworkError::Storage(format!("create nonce temp file failed: {e}")))?;
        let write_result = (|| -> std::io::Result<()> {
            temp.write_all(&encoded)?;
            temp.write_all(b"\n")?;
            temp.sync_all()
        })();
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(VNetworkError::Storage(format!(
                "write nonce temp file failed: {error}"
            )));
        }
        drop(temp);
        if let Err(error) = fs::rename(&temp_path, file_path) {
            let _ = fs::remove_file(&temp_path);
            return Err(VNetworkError::Storage(format!(
                "replace nonce state failed: {error}"
            )));
        }
        #[cfg(unix)]
        fs::set_permissions(file_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| VNetworkError::Storage(format!("secure nonce file failed: {e}")))?;
        if let Ok(dir) = File::open(directory) {
            let _ = dir.sync_all();
        }
        Ok(current)
    })();

    drop(lock_file);
    let _ = fs::remove_file(&lock_path);
    result
}

pub struct VectorNetworkClient {
    base_url: String,
    expected_network_id: Option<String>,
    http: reqwest::Client,
    identity: ClientIdentity,
    nonce: AtomicU64,
    nonce_store_path: Option<PathBuf>,
    nonce_lock: Mutex<()>,
    connected_network_id: Option<String>,
}

impl VectorNetworkClient {
    pub fn new(base_url: impl Into<String>, identity: ClientIdentity) -> Self {
        let clean = base_url.into().trim_end_matches('/').to_string();
        Self {
            base_url: clean,
            expected_network_id: None,
            http: reqwest::Client::new(),
            identity,
            nonce: AtomicU64::new(1),
            nonce_store_path: None,
            nonce_lock: Mutex::new(()),
            connected_network_id: None,
        }
    }

    pub fn with_expected_network(mut self, network_id: impl Into<String>) -> Self {
        self.expected_network_id = Some(network_id.into());
        self
    }

    pub fn identity(&self) -> &ClientIdentity {
        &self.identity
    }

    /// Configure a durable nonce file. When omitted, a per-network and
    /// per-participant file under ~/.vnetwork/nonces is used.
    pub fn with_nonce_store(mut self, path: impl Into<PathBuf>) -> Self {
        self.nonce_store_path = Some(path.into());
        self
    }

    /// Reserve and persist a unique nonce before constructing a signed request.
    pub fn reserve_nonce(&self) -> VResult<u64> {
        let network_id = self.resolved_network_id()?;
        let actor_pubkey = &self.identity.participant_key.public_key_hex;
        let store_path = match &self.nonce_store_path {
            Some(path) => path.clone(),
            None => {
                let home = std::env::var_os("HOME")
                    .or_else(|| std::env::var_os("USERPROFILE"))
                    .map(PathBuf::from)
                    .ok_or_else(|| {
                        VNetworkError::Storage(
                            "cannot resolve home directory for durable nonce store".to_string(),
                        )
                    })?;
                let key = hex::encode(Sha256::digest(
                    format!("{network_id}::{actor_pubkey}").as_bytes(),
                ));
                home.join(".vnetwork")
                    .join("nonces")
                    .join(format!("{key}.json"))
            }
        };
        let _guard = self
            .nonce_lock
            .lock()
            .map_err(|_| VNetworkError::Storage("durable nonce mutex poisoned".to_string()))?;
        let reserved = reserve_sdk_nonce_file(
            &store_path,
            &network_id,
            actor_pubkey,
            self.nonce.load(Ordering::SeqCst),
            self.nonce_store_path.is_none(),
        )?;
        self.nonce.store(
            reserved.checked_add(1).ok_or_else(|| {
                VNetworkError::Validation("request nonce exhausted u64 range".to_string())
            })?,
            Ordering::SeqCst,
        );
        Ok(reserved)
    }

    /// Source-compatible convenience wrapper. Prefer reserve_nonce() in new
    /// code so storage errors can be propagated instead of panicking.
    pub fn next_nonce(&self) -> u64 {
        self.reserve_nonce()
            .expect("failed to reserve durable request nonce")
    }

    pub fn set_nonce(&self, next: u64) {
        self.nonce.store(next, Ordering::SeqCst);
    }

    pub async fn connect(&mut self) -> VResult<NetworkConnectionInfo> {
        let url = format!("{}/v1/network/info", self.base_url);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| VNetworkError::Storage(format!("connect GET {url} failed: {e}")))?;
        let val = parse_json_response(resp).await?;

        let net_id = val
            .get("network_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let proto = val
            .get("protocol_version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if proto != PROTOCOL_VERSION {
            return Err(VNetworkError::ProfileMismatch(format!(
                "remote protocol_version `{proto}` != `{PROTOCOL_VERSION}`"
            )));
        }
        if let Some(expected) = &self.expected_network_id {
            if expected != &net_id {
                return Err(VNetworkError::ProfileMismatch(format!(
                    "expected network `{expected}`, endpoint reported `{net_id}`"
                )));
            }
        }
        self.connected_network_id = Some(net_id.clone());

        Ok(NetworkConnectionInfo {
            network_id: net_id,
            network_name: val
                .get("network_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            profile: val
                .get("profile")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            protocol_version: proto,
            height: val.get("height").and_then(|v| v.as_u64()).unwrap_or(0),
            state_root: val
                .get("state_root")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            raw: val,
        })
    }

    fn resolved_network_id(&self) -> VResult<String> {
        self.connected_network_id
            .clone()
            .or_else(|| self.expected_network_id.clone())
            .ok_or_else(|| {
                VNetworkError::Validation(
                    "client must connect() before write operations".to_string(),
                )
            })
    }

    pub async fn join(&mut self, scopes: Vec<ParticipationLevel>) -> VResult<serde_json::Value> {
        self.join_with_authorizations(scopes, Vec::new()).await
    }

    pub async fn join_with_authorizations(
        &mut self,
        scopes: Vec<ParticipationLevel>,
        scope_authorizations: Vec<serde_json::Value>,
    ) -> VResult<serde_json::Value> {
        if self.connected_network_id.is_none() {
            self.connect().await?;
        }
        let ch_url = format!("{}/v1/participants/challenge", self.base_url);
        let ch_resp = self
            .http
            .post(&ch_url)
            .send()
            .await
            .map_err(|e| VNetworkError::Storage(e.to_string()))?;
        let challenge: ParticipantChallenge =
            serde_json::from_value(parse_json_response(ch_resp).await?)
                .map_err(|e| VNetworkError::Serialization(e.to_string()))?;

        let scopes_str: Vec<&str> = scopes.iter().map(|s| s.as_str()).collect();
        let signing_obj = serde_json::json!({
            "challenge_id": challenge.challenge_id,
            "network_id": challenge.network_id,
            "node_pubkey": self.identity.node_key.public_key_hex,
            "nonce": challenge.nonce,
            "participant_pubkey": self.identity.participant_key.public_key_hex,
            "requested_scopes": scopes_str,
        });
        let msg = canonical_json_bytes(&signing_obj)?;
        let participant_sig = self.identity.participant_key.sign(&msg)?;
        let node_sig = self.identity.node_key.sign(&msg)?;

        let req_body = serde_json::json!({
            "challenge_id": challenge.challenge_id,
            "participant_pubkey": self.identity.participant_key.public_key_hex,
            "node_pubkey": self.identity.node_key.public_key_hex,
            "display_name": self.identity.display_name,
            "node_kind": NodeKind::FullNode,
            "requested_scopes": scopes,
            "advertised_addresses": [],
            "participant_signature": participant_sig,
            "node_signature": node_sig,
            "scope_authorizations": scope_authorizations,
        });

        let join_url = format!("{}/v1/participants/join", self.base_url);
        let join_resp = self
            .http
            .post(&join_url)
            .json(&req_body)
            .send()
            .await
            .map_err(|e| VNetworkError::Storage(e.to_string()))?;
        parse_json_response(join_resp).await
    }

    pub async fn participant_status(&self) -> VResult<serde_json::Value> {
        let url = format!(
            "{}/v1/participants/{}/scope",
            self.base_url, self.identity.participant_id
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| VNetworkError::Storage(e.to_string()))?;
        parse_json_response(resp).await
    }

    pub fn compile_local(
        &self,
        file_name: &str,
        source_bytes: &str,
        base_dir: Option<&Path>,
    ) -> VResult<(CompiledProgram, BTreeMap<String, String>)> {
        let dir = base_dir.unwrap_or_else(|| Path::new("."));
        let resolver = FilesystemModuleResolver::new(dir);
        let compiled = compile_source_with_imports(source_bytes, file_name, &resolver)
            .map_err(|e| VNetworkError::Language(e.to_string()))?;

        let canonical_dir = std::fs::canonicalize(dir)
            .map_err(|e| VNetworkError::Storage(format!("resolve module base dir failed: {e}")))?;
        let mut module_sources = BTreeMap::new();
        for m in &compiled.imported_modules {
            let rel = Path::new(&m.path);
            if rel.is_absolute()
                || m.path.contains('\\')
                || rel.components().any(|c| {
                    matches!(
                        c,
                        std::path::Component::ParentDir
                            | std::path::Component::RootDir
                            | std::path::Component::Prefix(_)
                    )
                })
            {
                return Err(VNetworkError::Validation(format!(
                    "unsafe imported module path `{}`",
                    m.path
                )));
            }
            let full = std::fs::canonicalize(canonical_dir.join(rel)).map_err(|e| {
                VNetworkError::Storage(format!("resolve imported module `{}` failed: {e}", m.path))
            })?;
            if !full.starts_with(&canonical_dir) {
                return Err(VNetworkError::Validation(format!(
                    "imported module `{}` escapes base directory",
                    m.path
                )));
            }
            let txt = std::fs::read_to_string(&full).map_err(|e| {
                VNetworkError::Storage(format!("read imported module `{}` failed: {e}", m.path))
            })?;
            module_sources.insert(m.path.clone(), txt);
        }
        Ok((compiled, module_sources))
    }

    pub async fn submit_vx_file(&mut self, path: impl AsRef<Path>) -> VResult<ProgramSubmission> {
        let path = path.as_ref();
        let source = std::fs::read_to_string(path)
            .map_err(|e| VNetworkError::Storage(format!("read {:?} failed: {e}", path)))?;
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("program.vx")
            .to_string();
        let (_, modules) = self.compile_local(&file_name, &source, path.parent())?;
        self.submit_program(&file_name, &source, modules).await
    }

    pub async fn submit_program(
        &mut self,
        file_name: &str,
        source_bytes: &str,
        modules: BTreeMap<String, String>,
    ) -> VResult<ProgramSubmission> {
        self.submit_program_with_params(file_name, source_bytes, modules, BTreeMap::new())
            .await
    }

    pub async fn submit_program_with_params(
        &mut self,
        file_name: &str,
        source_bytes: &str,
        modules: BTreeMap<String, String>,
        execution_params: BTreeMap<String, serde_json::Value>,
    ) -> VResult<ProgramSubmission> {
        if self.connected_network_id.is_none() {
            self.connect().await?;
        }
        let network_id = self.resolved_network_id()?;
        let request_id = format!("req_{}", uuid::Uuid::new_v4().simple());
        let nonce = self.reserve_nonce()?;
        let source_hash = blake3_hex(source_bytes.as_bytes());
        let file_kind = if file_name.ends_with(".vdx") {
            "vdx"
        } else {
            "vx"
        };
        let mut module_hashes = BTreeMap::new();
        for (path, src) in &modules {
            module_hashes.insert(path.clone(), blake3_hex(src.as_bytes()));
        }

        let sign_obj = serde_json::json!({
            "actor_pubkey": self.identity.participant_key.public_key_hex,
            "compiler_version": v_langx::compiler::COMPILER_VERSION,
            "execution_params": execution_params,
            "file_kind": file_kind,
            "file_name": file_name,
            "language_version": v_langx::compiler::LANGUAGE_VERSION,
            "module_hashes": module_hashes,
            "network_id": network_id,
            "nonce": nonce,
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request_id,
            "source_hash": source_hash,
        });
        let sig = self
            .identity
            .participant_key
            .sign(&canonical_json_bytes(&sign_obj)?)?;

        let body = serde_json::json!({
            "file_name": file_name,
            "source_bytes": source_bytes,
            "modules": modules,
            "actor_pubkey": self.identity.participant_key.public_key_hex,
            "network_id": network_id,
            "request_id": request_id,
            "nonce": nonce,
            "signature": sig,
            "execution_params": execution_params,
        });

        let url = format!("{}/v1/programs/submit", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| VNetworkError::Storage(e.to_string()))?;
        let val = parse_json_response(resp).await?;
        serde_json::from_value(val).map_err(|e| VNetworkError::Serialization(e.to_string()))
    }

    pub fn sign_wallet_pop(
        &self,
        wallet_id: &str,
        participant_identity: &str,
        purpose: &str,
        pop_nonce: &str,
        expires_at_ms: Option<u64>,
        authorized_key: &dyn SigningProvider,
    ) -> VResult<String> {
        let network_id = self.resolved_network_id()?;
        let obj = serde_json::json!({
            "authorized_pubkey": authorized_key.public_key_hex(),
            "expires_at_ms": expires_at_ms,
            "network_id": network_id,
            "nonce": pop_nonce,
            "participant_identity": participant_identity,
            "protocol_version": PROTOCOL_VERSION,
            "purpose": purpose,
            "wallet_id": wallet_id,
        });
        authorized_key.sign(&canonical_json_bytes(&obj)?)
    }

    /// Domain-separated co-signer approval for a token transfer.
    /// Transfer drain is derived solely from the canonical hierarchy and protocol `DrainPolicy`.
    pub fn sign_transfer_approval(
        &self,
        token_id: &str,
        from_wallet_id: &str,
        to_wallet_id: &str,
        amount: u128,
        cosigner_key: &dyn SigningProvider,
    ) -> VResult<String> {
        let network_id = self.resolved_network_id()?;
        let obj = serde_json::json!({
            "amount": amount.to_string(),
            "domain": DOM_TRANSFER_APPROVAL_V1,
            "from_wallet_id": from_wallet_id,
            "network_id": network_id,
            "protocol_version": PROTOCOL_VERSION,
            "to_wallet_id": to_wallet_id,
            "token_id": token_id,
        });
        cosigner_key.sign(&canonical_json_bytes(&obj)?)
    }

    pub async fn update_wallet_receive_policy(
        &mut self,
        wallet_id: &str,
        mode: &str,
        allowed_senders: Vec<String>,
    ) -> VResult<serde_json::Value> {
        self.submit_operation(NetworkOperation::UpdateWalletReceivePolicy {
            wallet_id: wallet_id.to_string(),
            mode: mode.to_string(),
            allowed_senders,
        })
        .await
    }

    pub async fn submit_operation(
        &mut self,
        operation: NetworkOperation,
    ) -> VResult<serde_json::Value> {
        if self.connected_network_id.is_none() {
            self.connect().await?;
        }
        let network_id = self.resolved_network_id()?;
        let request_id = format!("req_{}", uuid::Uuid::new_v4().simple());
        let nonce = self.reserve_nonce()?;
        let timestamp_ms = now_ms();
        let payload_hash = blake3_hex(&canonical_json_bytes(&operation)?);
        let sign_bytes = SignedRequestEnvelope::canonical_signing_bytes(
            &network_id,
            &request_id,
            &self.identity.participant_key.public_key_hex,
            nonce,
            timestamp_ms,
            &payload_hash,
        )?;
        let signature = self.identity.participant_key.sign(&sign_bytes)?;

        let body = serde_json::json!({
            "request_id": request_id,
            "network_id": network_id,
            "actor_pubkey": self.identity.participant_key.public_key_hex,
            "nonce": nonce,
            "timestamp_ms": timestamp_ms,
            "signature": signature,
            "operation": operation,
        });

        let url = format!("{}/v1/transactions", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| VNetworkError::Storage(e.to_string()))?;
        parse_json_response(resp).await
    }

    pub async fn get_json(&self, path: &str) -> VResult<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| VNetworkError::Storage(e.to_string()))?;
        parse_json_response(resp).await
    }

    pub async fn post_json(
        &self,
        path: &str,
        payload: &serde_json::Value,
    ) -> VResult<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .post(&url)
            .json(payload)
            .send()
            .await
            .map_err(|e| VNetworkError::Storage(e.to_string()))?;
        parse_json_response(resp).await
    }

    pub async fn network_info(&self) -> VResult<serde_json::Value> {
        self.get_json("/v1/network/info").await
    }

    pub async fn network_status(&self) -> VResult<serde_json::Value> {
        self.get_json("/v1/network/status").await
    }

    pub async fn list_nodes(&self) -> VResult<serde_json::Value> {
        self.get_json("/v1/nodes").await
    }

    pub async fn get_node_details(&self, node_id: &str) -> VResult<serde_json::Value> {
        self.get_json(&format!("/v1/nodes/{node_id}")).await
    }

    pub async fn explorer_network(&self) -> VResult<serde_json::Value> {
        self.get_json("/v1/explorer/network").await
    }

    pub async fn compile_source(
        &self,
        file_name: &str,
        source_bytes: &str,
        modules: BTreeMap<String, String>,
    ) -> VResult<serde_json::Value> {
        self.post_json(
            "/v1/language/compile",
            &serde_json::json!({
                "file_name": file_name,
                "source_bytes": source_bytes,
                "modules": modules,
            }),
        )
        .await
    }

    pub async fn get_program(&self, program_id: &str) -> VResult<serde_json::Value> {
        self.get_json(&format!("/v1/programs/{program_id}")).await
    }

    pub async fn get_program_status(&self, program_id: &str) -> VResult<serde_json::Value> {
        self.get_json(&format!("/v1/programs/{program_id}/status"))
            .await
    }

    pub async fn get_transaction(&self, tx_id: &str) -> VResult<serde_json::Value> {
        self.get_json(&format!("/v1/transactions/{tx_id}")).await
    }

    pub async fn list_spaces(&self) -> VResult<serde_json::Value> {
        self.get_json("/v1/spaces").await
    }

    pub async fn list_regions(&self) -> VResult<serde_json::Value> {
        self.get_json("/v1/regions").await
    }

    pub async fn list_wallets(&self) -> VResult<serde_json::Value> {
        self.get_json("/v1/wallets").await
    }

    pub async fn get_wallet(&self, wallet_id: &str) -> VResult<serde_json::Value> {
        self.get_json(&format!("/v1/wallets/{wallet_id}")).await
    }

    pub async fn list_tokens(&self) -> VResult<serde_json::Value> {
        self.get_json("/v1/tokens").await
    }

    pub async fn get_token(&self, token_id: &str) -> VResult<serde_json::Value> {
        self.get_json(&format!("/v1/tokens/{token_id}")).await
    }

    pub async fn list_contracts(&self) -> VResult<serde_json::Value> {
        self.get_json("/v1/contracts").await
    }

    pub async fn get_contract(&self, contract_id: &str) -> VResult<serde_json::Value> {
        self.get_json(&format!("/v1/contracts/{contract_id}")).await
    }

    pub async fn list_loans(&self) -> VResult<serde_json::Value> {
        self.get_json("/v1/loans").await
    }

    pub async fn get_loan(&self, loan_id: &str) -> VResult<serde_json::Value> {
        self.get_json(&format!("/v1/loans/{loan_id}")).await
    }

    pub async fn create_contract(
        &mut self,
        name: &str,
        region_id: Option<String>,
        rules: serde_json::Value,
        actions: Vec<serde_json::Value>,
    ) -> VResult<serde_json::Value> {
        self.submit_operation(NetworkOperation::CreateContract {
            name: name.to_string(),
            region_id,
            rules,
            actions,
        })
        .await
    }

    pub async fn execute_contract(
        &mut self,
        contract_id: &str,
        action: &str,
        args: serde_json::Value,
    ) -> VResult<serde_json::Value> {
        self.submit_operation(NetworkOperation::ExecuteContract {
            contract_id: contract_id.to_string(),
            action: action.to_string(),
            args,
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_loan(
        &mut self,
        name: &str,
        token_id: &str,
        lender_wallet_id: &str,
        borrower_wallet_id: &str,
        principal: u128,
        collateral: u128,
        interest_bps: u64,
        maturity_at_ms: Option<u64>,
    ) -> VResult<serde_json::Value> {
        let interest_bps = u16::try_from(interest_bps).map_err(|_| {
            VNetworkError::Validation(format!(
                "interest_bps exceeds the protocol limit of {} basis points",
                u16::MAX
            ))
        })?;
        self.submit_operation(NetworkOperation::CreateLoan {
            name: name.to_string(),
            token_id: token_id.to_string(),
            lender_wallet_id: lender_wallet_id.to_string(),
            borrower_wallet_id: borrower_wallet_id.to_string(),
            principal,
            collateral,
            interest_bps,
            maturity_at_ms,
        })
        .await
    }

    pub async fn execute_loan(
        &mut self,
        loan_id: &str,
        action: &str,
        amount: u128,
    ) -> VResult<serde_json::Value> {
        self.submit_operation(NetworkOperation::ExecuteLoan {
            loan_id: loan_id.to_string(),
            action: action.to_string(),
            amount,
        })
        .await
    }

    pub async fn ledger_events(&self) -> VResult<serde_json::Value> {
        self.get_json("/v1/ledger/events").await
    }

    pub async fn ledger_proofs(&self) -> VResult<serde_json::Value> {
        self.get_json("/v1/ledger/proofs").await
    }

    pub async fn consensus_status(&self) -> VResult<serde_json::Value> {
        self.get_json("/v1/consensus/status").await
    }

    pub async fn verify_ledger_replay(&self) -> VResult<serde_json::Value> {
        self.get_json("/v1/ledger/replay").await
    }

    pub async fn verify_token_supply(&self, token_id: &str) -> VResult<serde_json::Value> {
        self.get_json(&format!("/v1/tokens/{token_id}/supply"))
            .await
    }

    pub async fn equivocations(&self) -> VResult<serde_json::Value> {
        self.get_json("/v1/consensus/equivocations").await
    }

    pub async fn verify_reconstruction(
        &self,
        entity_kind: &str,
        entity_id: &str,
    ) -> VResult<serde_json::Value> {
        let url = format!("{}/v1/reconstruction/verify", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({
                "entity_kind": entity_kind,
                "entity_id": entity_id,
            }))
            .send()
            .await
            .map_err(|e| VNetworkError::Storage(e.to_string()))?;
        parse_json_response(resp).await
    }
    pub async fn subscribe_events(&self) -> VResult<mpsc::Receiver<serde_json::Value>> {
        let ws_base = if let Some(rest) = self.base_url.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = self.base_url.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            self.base_url.clone()
        };
        let ws_url = format!("{ws_base}/v1/ws");
        let (ws_stream, _) = connect_async(&ws_url)
            .await
            .map_err(|e| VNetworkError::Storage(format!("ws connect failed: {e}")))?;
        let (_, mut read) = ws_stream.split();
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(async move {
            while let Some(Ok(msg)) = read.next().await {
                if let tokio_tungstenite::tungstenite::Message::Text(txt) = msg {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&txt) {
                        if tx.send(val).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(rx)
    }
}

pub fn normalize_verification_status(raw: &str) -> VerificationStatus {
    match raw.trim().to_ascii_uppercase().as_str() {
        "VERIFIED" => VerificationStatus::Verified,
        "UNVERIFIED" => VerificationStatus::Unverified,
        "INVALID" => VerificationStatus::Invalid,
        _ => VerificationStatus::Unavailable,
    }
}

pub struct BlockingVectorNetworkClient {
    rt: tokio::runtime::Runtime,
    inner: VectorNetworkClient,
}

impl BlockingVectorNetworkClient {
    pub fn new(base_url: impl Into<String>, identity: ClientIdentity) -> VResult<Self> {
        let rt =
            tokio::runtime::Runtime::new().map_err(|e| VNetworkError::Storage(e.to_string()))?;
        Ok(Self {
            rt,
            inner: VectorNetworkClient::new(base_url, identity),
        })
    }

    pub fn connect(&mut self) -> VResult<NetworkConnectionInfo> {
        self.rt.block_on(self.inner.connect())
    }

    pub fn join(&mut self, scopes: Vec<ParticipationLevel>) -> VResult<serde_json::Value> {
        self.rt.block_on(self.inner.join(scopes))
    }

    pub fn submit_vx_file(&mut self, path: impl AsRef<Path>) -> VResult<ProgramSubmission> {
        self.rt.block_on(self.inner.submit_vx_file(path))
    }

    pub fn submit_operation(&mut self, operation: NetworkOperation) -> VResult<serde_json::Value> {
        self.rt.block_on(self.inner.submit_operation(operation))
    }

    pub fn get_json(&self, path: &str) -> VResult<serde_json::Value> {
        self.rt.block_on(self.inner.get_json(path))
    }
}

async fn parse_json_response(resp: reqwest::Response) -> VResult<serde_json::Value> {
    let status = resp.status();
    let txt = resp
        .text()
        .await
        .map_err(|e| VNetworkError::Storage(e.to_string()))?;
    let val: serde_json::Value =
        serde_json::from_str(&txt).unwrap_or_else(|_| serde_json::json!({ "raw": txt }));
    if !status.is_success() {
        let msg = val
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("HTTP error");
        return Err(VNetworkError::Validation(format!(
            "HTTP {}: {}",
            status.as_u16(),
            msg
        )));
    }
    Ok(val)
}

#[cfg(test)]
mod durable_nonce_regressions {
    use super::{ClientIdentity, VectorNetworkClient};
    use std::path::PathBuf;

    fn temp_nonce_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "vnetwork-sdk-rust-{label}-{}-{}.json",
            std::process::id(),
            uuid::Uuid::new_v4()
        ))
    }

    fn client(identity: ClientIdentity, path: PathBuf) -> VectorNetworkClient {
        let mut client = VectorNetworkClient::new("http://127.0.0.1:8080", identity)
            .with_expected_network("nonce-test-network")
            .with_nonce_store(path);
        client.connected_network_id = Some("nonce-test-network".to_string());
        client
    }

    #[test]
    fn nonce_reservations_survive_client_restart() {
        let identity = ClientIdentity::generate("rust-nonce-test");
        let path = temp_nonce_path("restart");
        let first = client(identity.clone(), path.clone());
        assert_eq!(first.reserve_nonce().expect("first nonce"), 1);
        assert_eq!(first.reserve_nonce().expect("second nonce"), 2);

        let restarted = client(identity, path.clone());
        assert_eq!(restarted.reserve_nonce().expect("restarted nonce"), 3);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.lock", path.display()));
    }

    #[test]
    fn separate_clients_do_not_reserve_duplicate_nonces() {
        let identity = ClientIdentity::generate("rust-nonce-concurrency");
        let path = temp_nonce_path("concurrent");
        let first = client(identity.clone(), path.clone());
        let second = client(identity, path.clone());
        let a = first.reserve_nonce().expect("first reservation");
        let b = second.reserve_nonce().expect("second reservation");
        assert_ne!(a, b);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.lock", path.display()));
    }

    #[test]
    fn durable_nonce_state_is_bound_to_network_and_participant() {
        let identity = ClientIdentity::generate("rust-nonce-binding");
        let path = temp_nonce_path("binding");
        let original = client(identity.clone(), path.clone());
        assert_eq!(original.reserve_nonce().unwrap(), 1);

        let mut wrong_network = client(identity, path.clone());
        wrong_network.connected_network_id = Some("different-network".to_string());
        assert!(wrong_network.reserve_nonce().is_err());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.lock", path.display()));
    }
}
