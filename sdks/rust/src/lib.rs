use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
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
        let node_envelope = self.node_key.encrypt_to_envelope(
            passphrase,
            kdf_params,
            1,
            now,
            None,
            Vec::new(),
        )?;
        Ok(EncryptedClientIdentity {
            envelope_version: ENCRYPTED_KEY_ENVELOPE_VERSION,
            display_name: self.display_name.clone(),
            participant_id: self.participant_id.clone(),
            node_id: self.node_id.clone(),
            participant_envelope,
            node_envelope,
        })
    }

    pub fn from_envelopes(
        encrypted: &EncryptedClientIdentity,
        passphrase: &str,
    ) -> VResult<Self> {
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

pub struct VectorNetworkClient {
    base_url: String,
    expected_network_id: Option<String>,
    http: reqwest::Client,
    identity: ClientIdentity,
    nonce: AtomicU64,
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

    pub fn next_nonce(&self) -> u64 {
        self.nonce.fetch_add(1, Ordering::SeqCst)
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
            .ok_or_else(|| VNetworkError::Validation("client must connect() before write operations".to_string()))
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

        let mut module_sources = BTreeMap::new();
        for m in &compiled.imported_modules {
            let full = dir.join(&m.path);
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
        let nonce = self.next_nonce();
        let source_hash = blake3_hex(source_bytes.as_bytes());
        let file_kind = if file_name.ends_with(".vdx") { "vdx" } else { "vx" };
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

    pub async fn submit_operation(&mut self, operation: NetworkOperation) -> VResult<serde_json::Value> {
        if self.connected_network_id.is_none() {
            self.connect().await?;
        }
        let network_id = self.resolved_network_id()?;
        let request_id = format!("req_{}", uuid::Uuid::new_v4().simple());
        let nonce = self.next_nonce();
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

    pub async fn verify_ledger_replay(&self) -> VResult<serde_json::Value> {
        self.get_json("/v1/ledger/replay").await
    }

    pub async fn verify_token_supply(&self, token_id: &str) -> VResult<serde_json::Value> {
        self.get_json(&format!("/v1/tokens/{token_id}/supply")).await
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

pub struct BlockingVectorNetworkClient {
    rt: tokio::runtime::Runtime,
    inner: VectorNetworkClient,
}

impl BlockingVectorNetworkClient {
    pub fn new(base_url: impl Into<String>, identity: ClientIdentity) -> VResult<Self> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| VNetworkError::Storage(e.to_string()))?;
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
    let val: serde_json::Value = serde_json::from_str(&txt).unwrap_or_else(|_| {
        serde_json::json!({ "raw": txt })
    });
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
