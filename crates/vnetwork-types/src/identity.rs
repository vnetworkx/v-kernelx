use crate::canonical::blake3_hex;
use crate::error::{VNetworkError, VResult};
use crate::ids::{derive_node_id, derive_participant_id, derive_wallet_id};
use crate::protocol_version::DOM_KEY_ENVELOPE_V1;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub const ENCRYPTED_KEY_ENVELOPE_VERSION: u16 = 1;
pub const KEY_CIPHER_AES_256_GCM: &str = "AES-256-GCM";
pub const KEY_KDF_ARGON2ID: &str = "Argon2id";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ParticipationLevel {
    Network,
    Space,
    Region,
    Wallet,
    Token,
}

impl ParticipationLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            ParticipationLevel::Network => "NETWORK",
            ParticipationLevel::Space => "SPACE",
            ParticipationLevel::Region => "REGION",
            ParticipationLevel::Wallet => "WALLET",
            ParticipationLevel::Token => "TOKEN",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "NETWORK" => Some(Self::Network),
            "SPACE" => Some(Self::Space),
            "REGION" => Some(Self::Region),
            "WALLET" => Some(Self::Wallet),
            "TOKEN" => Some(Self::Token),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeKind {
    LightParticipant,
    FullNode,
    ValidatorNode,
    BootstrapSeed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ParticipationStatus {
    Connecting,
    Challenged,
    Verified,
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeGrant {
    pub level: ParticipationLevel,
    pub target_id: Option<String>,
    pub granted_at_ms: u64,
    #[serde(default)]
    pub grantor_pubkey: String,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    #[serde(default)]
    pub authorization_basis: String,
    #[serde(default)]
    pub revoked: bool,
}

impl ScopeGrant {
    pub fn is_active_at(&self, now_ms: u64) -> bool {
        if self.revoked {
            return false;
        }
        if let Some(exp) = self.expires_at_ms {
            if now_ms >= exp {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipationScope {
    pub levels: BTreeSet<ParticipationLevel>,
    pub grants: Vec<ScopeGrant>,
    pub validator_eligible: bool,
}

impl ParticipationScope {
    pub fn has_level(&self, level: ParticipationLevel) -> bool {
        self.levels.contains(&level)
    }

    pub fn has_active_level(&self, level: ParticipationLevel, now_ms: u64) -> bool {
        if self.grants.is_empty() {
            return self.levels.contains(&level);
        }
        self.levels.contains(&level)
            && self
                .grants
                .iter()
                .any(|g| g.level == level && g.is_active_at(now_ms))
    }

    pub fn has_active_scope(
        &self,
        level: ParticipationLevel,
        target_id: Option<&str>,
        now_ms: u64,
    ) -> bool {
        if !self.levels.contains(&level) {
            return false;
        }
        if self.grants.is_empty() {
            return true;
        }
        self.grants.iter().any(|g| {
            g.level == level
                && g.is_active_at(now_ms)
                && match (&g.target_id, target_id) {
                    (None, _) => true,
                    (Some(g_target), Some(req_target)) => g_target == req_target,
                    (Some(_), None) => false,
                }
        })
    }

    pub fn recompute_levels(&mut self, now_ms: u64) {
        self.levels = self
            .grants
            .iter()
            .filter(|g| g.is_active_at(now_ms))
            .map(|g| g.level)
            .collect();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantRecord {
    pub participant_id: String,
    pub public_key_hex: String,
    pub node_id: String,
    pub node_pubkey_hex: String,
    pub display_name: String,
    pub node_kind: NodeKind,
    pub status: ParticipationStatus,
    pub scope: ParticipationScope,
    pub joined_at_ms: u64,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    pub node_id: String,
    pub node_pubkey_hex: String,
    pub participant_id: Option<String>,
    pub node_kind: NodeKind,
    pub advertised_addresses: Vec<String>,
    pub protocol_version: String,
    pub sync_height: u64,
    pub healthy: bool,
    pub validator_eligible: bool,
    pub scopes: Vec<ParticipationLevel>,
    pub last_seen_ms: u64,
}

pub fn derive_id_for_role(role: &str, public_key_hex: &str) -> String {
    match role {
        "node" => derive_node_id(public_key_hex),
        "participant" => derive_participant_id(public_key_hex),
        _ => derive_wallet_id(public_key_hex),
    }
}

pub fn canonical_ed25519_pubkey_bytes(public_key_hex: &str) -> VResult<[u8; 32]> {
    let trimmed = public_key_hex.trim();
    if trimmed.len() != 64 {
        return Err(VNetworkError::Signature(
            "public key hex must be exactly 64 hex characters (32 bytes)".to_string(),
        ));
    }
    let pk_bytes = hex::decode(trimmed)
        .map_err(|_| VNetworkError::Signature("invalid public key hex".to_string()))?;
    let pk_arr: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| VNetworkError::Signature("public key must be 32 bytes".to_string()))?;
    let vk = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|_| VNetworkError::Signature("invalid Ed25519 public key".to_string()))?;
    let canonical = vk.to_bytes();
    if canonical != pk_arr {
        return Err(VNetworkError::Signature(
            "non-canonical Ed25519 public key encoding".to_string(),
        ));
    }
    // Reject the all-zero and canonical small-order/identity point encodings
    const KNOWN_SMALL_ORDER: [[u8; 32]; 2] = [
        [0u8; 32],
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ],
    ];
    if KNOWN_SMALL_ORDER.iter().any(|bad| bad == &canonical) {
        return Err(VNetworkError::Signature(
            "weak or identity Ed25519 public key rejected".to_string(),
        ));
    }
    Ok(canonical)
}

pub fn pubkey_fingerprint(public_key_hex: &str) -> VResult<String> {
    let canonical = canonical_ed25519_pubkey_bytes(public_key_hex)?;
    Ok(blake3_hex(&canonical))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyKdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KeyKdfParams {
    fn default() -> Self {
        Self {
            m_cost_kib: 65_536, // 64 MiB
            t_cost: 3,
            p_cost: 1,
        }
    }
}

impl KeyKdfParams {
    pub fn fast_for_tests() -> Self {
        Self {
            m_cost_kib: 4_096,
            t_cost: 1,
            p_cost: 1,
        }
    }

    pub fn validate(&self) -> VResult<()> {
        if self.m_cost_kib < 4_096 {
            return Err(VNetworkError::Validation(
                "Argon2id m_cost_kib must be at least 4096 KiB".to_string(),
            ));
        }
        if self.t_cost < 1 || self.p_cost < 1 {
            return Err(VNetworkError::Validation(
                "Argon2id t_cost and p_cost must be >= 1".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationRecord {
    pub version: u32,
    pub previous_public_key_hex: Option<String>,
    pub new_public_key_hex: String,
    pub previous_derived_id: Option<String>,
    pub new_derived_id: String,
    pub rotated_at_ms: u64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeIdentityMetadata {
    pub key_role: String,
    pub derived_id: String,
    pub public_key_hex: String,
    pub pubkey_fingerprint: String,
    pub storage_mode: String,
    pub key_version: u32,
    pub created_at_ms: u64,
    pub rotated_at_ms: Option<u64>,
    #[serde(default)]
    pub rotation_history: Vec<KeyRotationRecord>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedKeyEnvelope {
    pub envelope_version: u16,
    pub cipher: String,
    pub kdf: String,
    pub kdf_params: KeyKdfParams,
    pub key_role: String,
    pub derived_id: String,
    pub public_key_hex: String,
    pub pubkey_fingerprint: String,
    pub key_version: u32,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    pub created_at_ms: u64,
    pub rotated_at_ms: Option<u64>,
    #[serde(default)]
    pub rotation_history: Vec<KeyRotationRecord>,
}

impl fmt::Debug for EncryptedKeyEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedKeyEnvelope")
            .field("envelope_version", &self.envelope_version)
            .field("cipher", &self.cipher)
            .field("kdf", &self.kdf)
            .field("key_role", &self.key_role)
            .field("derived_id", &self.derived_id)
            .field("public_key_hex", &self.public_key_hex)
            .field("pubkey_fingerprint", &self.pubkey_fingerprint)
            .field("key_version", &self.key_version)
            .field("ciphertext_hex", &"[ENCRYPTED]")
            .finish()
    }
}

impl EncryptedKeyEnvelope {
    pub fn aad_bytes(
        envelope_version: u16,
        cipher: &str,
        kdf: &str,
        kdf_params: &KeyKdfParams,
        key_role: &str,
        derived_id: &str,
        public_key_hex: &str,
        pubkey_fingerprint: &str,
        key_version: u32,
    ) -> Vec<u8> {
        format!(
            "{DOM_KEY_ENVELOPE_V1}|v={envelope_version}|cipher={cipher}|kdf={kdf}|m={}|t={}|p={}|role={key_role}|id={derived_id}|pk={public_key_hex}|fp={pubkey_fingerprint}|kv={key_version}",
            kdf_params.m_cost_kib, kdf_params.t_cost, kdf_params.p_cost
        )
        .into_bytes()
    }

    pub fn metadata(&self, storage_mode: &str) -> NodeIdentityMetadata {
        NodeIdentityMetadata {
            key_role: self.key_role.clone(),
            derived_id: self.derived_id.clone(),
            public_key_hex: self.public_key_hex.clone(),
            pubkey_fingerprint: self.pubkey_fingerprint.clone(),
            storage_mode: storage_mode.to_string(),
            key_version: self.key_version,
            created_at_ms: self.created_at_ms,
            rotated_at_ms: self.rotated_at_ms,
            rotation_history: self.rotation_history.clone(),
        }
    }

    pub fn derive_wrapping_key(
        passphrase: &str,
        salt: &[u8],
        kdf_params: &KeyKdfParams,
    ) -> VResult<Zeroizing<[u8; 32]>> {
        if passphrase.is_empty() {
            return Err(VNetworkError::Authorization(
                "keystore passphrase cannot be empty".to_string(),
            ));
        }
        kdf_params.validate()?;
        if salt.len() < 16 {
            return Err(VNetworkError::Signature(
                "encrypted key salt must be at least 16 bytes".to_string(),
            ));
        }
        let params = Params::new(
            kdf_params.m_cost_kib,
            kdf_params.t_cost,
            kdf_params.p_cost,
            Some(32),
        )
        .map_err(|e| VNetworkError::Signature(format!("invalid Argon2id parameters: {e}")))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut derived = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(passphrase.as_bytes(), salt, derived.as_mut())
            .map_err(|e| VNetworkError::Signature(format!("Argon2id key derivation failed: {e}")))?;
        Ok(derived)
    }
}

/// Protected in-memory Ed25519 signing key wrapped in `Zeroizing<[u8; 32]>`.
/// Never serializes secret bytes directly and redacts secrets in `Debug`/`Display`.
#[derive(Clone)]
pub struct ProtectedSigningKey {
    pub key_role: String,
    pub derived_id: String,
    pub public_key_hex: String,
    pub pubkey_fingerprint: String,
    secret_seed: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for ProtectedSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedSigningKey")
            .field("key_role", &self.key_role)
            .field("derived_id", &self.derived_id)
            .field("public_key_hex", &self.public_key_hex)
            .field("pubkey_fingerprint", &self.pubkey_fingerprint)
            .field("secret_seed", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for ProtectedSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProtectedSigningKey(role={}, id={}, pk={})",
            self.key_role, self.derived_id, self.public_key_hex
        )
    }
}

impl ProtectedSigningKey {
    pub fn generate(role: &str) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(seed.as_mut());
        Self::from_seed_zeroizing(role, seed)
    }

    pub fn from_seed_bytes(role: &str, seed_bytes: [u8; 32]) -> Self {
        Self::from_seed_zeroizing(role, Zeroizing::new(seed_bytes))
    }

    pub fn from_private_hex(role: &str, private_hex: &str) -> VResult<Self> {
        let mut bytes = hex::decode(private_hex.trim())
            .map_err(|_| VNetworkError::Signature("invalid hex private key".to_string()))?;
        let arr: [u8; 32] = match bytes.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => {
                bytes.zeroize();
                return Err(VNetworkError::Signature(
                    "private key must be 32 bytes".to_string(),
                ));
            }
        };
        bytes.zeroize();
        Ok(Self::from_seed_zeroizing(role, Zeroizing::new(arr)))
    }

    fn from_seed_zeroizing(role: &str, seed: Zeroizing<[u8; 32]>) -> Self {
        let sk = SigningKey::from_bytes(&seed);
        let pk_bytes = sk.verifying_key().to_bytes();
        let pk_hex = hex::encode(pk_bytes);
        let fp = blake3_hex(&pk_bytes);
        let derived_id = derive_id_for_role(role, &pk_hex);
        Self {
            key_role: role.to_string(),
            derived_id,
            public_key_hex: pk_hex,
            pubkey_fingerprint: fp,
            secret_seed: seed,
        }
    }

    pub fn signing_key_bytes(&self) -> &[u8; 32] {
        &self.secret_seed
    }

    pub fn sign(&self, message: &[u8]) -> VResult<String> {
        let sk = SigningKey::from_bytes(&self.secret_seed);
        Ok(hex::encode(sk.sign(message).to_bytes()))
    }

    pub fn metadata(
        &self,
        storage_mode: &str,
        key_version: u32,
        created_at_ms: u64,
        rotated_at_ms: Option<u64>,
        rotation_history: Vec<KeyRotationRecord>,
    ) -> NodeIdentityMetadata {
        NodeIdentityMetadata {
            key_role: self.key_role.clone(),
            derived_id: self.derived_id.clone(),
            public_key_hex: self.public_key_hex.clone(),
            pubkey_fingerprint: self.pubkey_fingerprint.clone(),
            storage_mode: storage_mode.to_string(),
            key_version,
            created_at_ms,
            rotated_at_ms,
            rotation_history,
        }
    }

    pub fn encrypt_to_envelope(
        &self,
        passphrase: &str,
        kdf_params: Option<KeyKdfParams>,
        key_version: u32,
        created_at_ms: u64,
        rotated_at_ms: Option<u64>,
        rotation_history: Vec<KeyRotationRecord>,
    ) -> VResult<EncryptedKeyEnvelope> {
        let params = kdf_params.unwrap_or_default();
        params.validate()?;

        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce_bytes);

        let wrapping_key = EncryptedKeyEnvelope::derive_wrapping_key(passphrase, &salt, &params)?;
        let cipher = Aes256Gcm::new_from_slice(wrapping_key.as_ref())
            .map_err(|e| VNetworkError::Signature(format!("AES-256-GCM init error: {e}")))?;

        let aad = EncryptedKeyEnvelope::aad_bytes(
            ENCRYPTED_KEY_ENVELOPE_VERSION,
            KEY_CIPHER_AES_256_GCM,
            KEY_KDF_ARGON2ID,
            &params,
            &self.key_role,
            &self.derived_id,
            &self.public_key_hex,
            &self.pubkey_fingerprint,
            key_version,
        );
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: self.secret_seed.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| VNetworkError::Signature("failed to encrypt private key".to_string()))?;

        Ok(EncryptedKeyEnvelope {
            envelope_version: ENCRYPTED_KEY_ENVELOPE_VERSION,
            cipher: KEY_CIPHER_AES_256_GCM.to_string(),
            kdf: KEY_KDF_ARGON2ID.to_string(),
            kdf_params: params,
            key_role: self.key_role.clone(),
            derived_id: self.derived_id.clone(),
            public_key_hex: self.public_key_hex.clone(),
            pubkey_fingerprint: self.pubkey_fingerprint.clone(),
            key_version,
            salt_hex: hex::encode(salt),
            nonce_hex: hex::encode(nonce_bytes),
            ciphertext_hex: hex::encode(ciphertext),
            created_at_ms,
            rotated_at_ms,
            rotation_history,
        })
    }

    pub fn from_envelope(envelope: &EncryptedKeyEnvelope, passphrase: &str) -> VResult<Self> {
        if envelope.envelope_version != ENCRYPTED_KEY_ENVELOPE_VERSION {
            return Err(VNetworkError::Storage(format!(
                "unsupported encrypted key envelope version {}",
                envelope.envelope_version
            )));
        }
        if envelope.cipher != KEY_CIPHER_AES_256_GCM || envelope.kdf != KEY_KDF_ARGON2ID {
            return Err(VNetworkError::Storage(format!(
                "unsupported key envelope cipher/kdf {}/{}",
                envelope.cipher, envelope.kdf
            )));
        }
        envelope.kdf_params.validate()?;
        let _ = canonical_ed25519_pubkey_bytes(&envelope.public_key_hex)?;

        let salt = hex::decode(&envelope.salt_hex)
            .map_err(|_| VNetworkError::Storage("invalid encrypted key salt hex".to_string()))?;
        let nonce_bytes = hex::decode(&envelope.nonce_hex)
            .map_err(|_| VNetworkError::Storage("invalid encrypted key nonce hex".to_string()))?;
        if nonce_bytes.len() != 12 {
            return Err(VNetworkError::Storage(
                "AES-256-GCM nonce must be 12 bytes".to_string(),
            ));
        }
        let ciphertext = hex::decode(&envelope.ciphertext_hex).map_err(|_| {
            VNetworkError::Storage("invalid encrypted key ciphertext hex".to_string())
        })?;

        let wrapping_key =
            EncryptedKeyEnvelope::derive_wrapping_key(passphrase, &salt, &envelope.kdf_params)?;
        let cipher = Aes256Gcm::new_from_slice(wrapping_key.as_ref())
            .map_err(|e| VNetworkError::Signature(format!("AES-256-GCM init error: {e}")))?;

        let aad = EncryptedKeyEnvelope::aad_bytes(
            envelope.envelope_version,
            &envelope.cipher,
            &envelope.kdf,
            &envelope.kdf_params,
            &envelope.key_role,
            &envelope.derived_id,
            &envelope.public_key_hex,
            &envelope.pubkey_fingerprint,
            envelope.key_version,
        );
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                VNetworkError::Authorization(
                    "key decryption failed: wrong passphrase or tampered encrypted envelope"
                        .to_string(),
                )
            })?;
        let seed_arr: [u8; 32] = match plaintext.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => {
                plaintext.zeroize();
                return Err(VNetworkError::Storage(
                    "decrypted signing seed has invalid length".to_string(),
                ));
            }
        };
        plaintext.zeroize();

        let protected = Self::from_seed_zeroizing(&envelope.key_role, Zeroizing::new(seed_arr));
        let pk_match: bool = protected
            .public_key_hex
            .as_bytes()
            .ct_eq(envelope.public_key_hex.as_bytes())
            .into();
        let fp_match: bool = protected
            .pubkey_fingerprint
            .as_bytes()
            .ct_eq(envelope.pubkey_fingerprint.as_bytes())
            .into();
        let id_match: bool = protected
            .derived_id
            .as_bytes()
            .ct_eq(envelope.derived_id.as_bytes())
            .into();
        if !pk_match || !fp_match || !id_match {
            return Err(VNetworkError::Storage(
                "decrypted key does not match envelope public metadata".to_string(),
            ));
        }
        Ok(protected)
    }

    pub fn to_keypair_material_in_memory(&self) -> KeypairMaterial {
        KeypairMaterial {
            key_role: self.key_role.clone(),
            derived_id: self.derived_id.clone(),
            public_key_hex: self.public_key_hex.clone(),
            private_key_hex: hex::encode(self.secret_seed.as_ref()),
        }
    }
}

pub trait SigningProvider: Send + Sync {
    fn key_role(&self) -> &str;
    fn derived_id(&self) -> &str;
    fn public_key_hex(&self) -> &str;
    fn pubkey_fingerprint(&self) -> &str;
    fn provider_kind(&self) -> &str;
    fn sign(&self, message: &[u8]) -> VResult<String>;
}

#[derive(Debug, Clone)]
pub struct LocalEncryptedSigningProvider {
    signing_key: ProtectedSigningKey,
    storage_mode: String,
}

impl LocalEncryptedSigningProvider {
    pub fn new(signing_key: ProtectedSigningKey, storage_mode: impl Into<String>) -> Self {
        Self {
            signing_key,
            storage_mode: storage_mode.into(),
        }
    }

    pub fn signing_key(&self) -> &ProtectedSigningKey {
        &self.signing_key
    }
}

impl SigningProvider for LocalEncryptedSigningProvider {
    fn key_role(&self) -> &str {
        &self.signing_key.key_role
    }
    fn derived_id(&self) -> &str {
        &self.signing_key.derived_id
    }
    fn public_key_hex(&self) -> &str {
        &self.signing_key.public_key_hex
    }
    fn pubkey_fingerprint(&self) -> &str {
        &self.signing_key.pubkey_fingerprint
    }
    fn provider_kind(&self) -> &str {
        &self.storage_mode
    }
    fn sign(&self, message: &[u8]) -> VResult<String> {
        self.signing_key.sign(message)
    }
}

pub type ExternalSignCallback = Arc<dyn Fn(&[u8]) -> VResult<String> + Send + Sync>;

#[derive(Clone)]
pub struct ExternalSignerProvider {
    pub metadata: NodeIdentityMetadata,
    pub backend_name: String,
    callback: ExternalSignCallback,
}

impl fmt::Debug for ExternalSignerProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalSignerProvider")
            .field("backend_name", &self.backend_name)
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl ExternalSignerProvider {
    pub fn new(
        metadata: NodeIdentityMetadata,
        backend_name: impl Into<String>,
        callback: ExternalSignCallback,
    ) -> VResult<Self> {
        let _ = canonical_ed25519_pubkey_bytes(&metadata.public_key_hex)?;
        Ok(Self {
            metadata,
            backend_name: backend_name.into(),
            callback,
        })
    }
}

impl SigningProvider for ExternalSignerProvider {
    fn key_role(&self) -> &str {
        &self.metadata.key_role
    }
    fn derived_id(&self) -> &str {
        &self.metadata.derived_id
    }
    fn public_key_hex(&self) -> &str {
        &self.metadata.public_key_hex
    }
    fn pubkey_fingerprint(&self) -> &str {
        &self.metadata.pubkey_fingerprint
    }
    fn provider_kind(&self) -> &str {
        &self.backend_name
    }
    fn sign(&self, message: &[u8]) -> VResult<String> {
        let sig_hex = (self.callback)(message)?;
        verify_ed25519(&self.metadata.public_key_hex, message, &sig_hex)?;
        Ok(sig_hex)
    }
}

/// Independent Ed25519 keypair for in-memory signing and verification.
/// Custom `Debug` redacts `private_key_hex` and `Drop` zeroizes the secret string.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeypairMaterial {
    pub key_role: String,
    pub derived_id: String,
    pub public_key_hex: String,
    pub private_key_hex: String,
}

impl fmt::Debug for KeypairMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeypairMaterial")
            .field("key_role", &self.key_role)
            .field("derived_id", &self.derived_id)
            .field("public_key_hex", &self.public_key_hex)
            .field("private_key_hex", &"[REDACTED]")
            .finish()
    }
}

impl Drop for KeypairMaterial {
    fn drop(&mut self) {
        self.private_key_hex.zeroize();
    }
}

impl KeypairMaterial {
    pub fn generate(role: &str) -> Self {
        ProtectedSigningKey::generate(role).to_keypair_material_in_memory()
    }

    pub fn from_private_hex(role: &str, private_hex: &str) -> VResult<Self> {
        Ok(ProtectedSigningKey::from_private_hex(role, private_hex)?.to_keypair_material_in_memory())
    }

    pub fn to_protected(&self) -> VResult<ProtectedSigningKey> {
        ProtectedSigningKey::from_private_hex(&self.key_role, &self.private_key_hex)
    }

    pub fn to_signing_provider(&self) -> VResult<LocalEncryptedSigningProvider> {
        Ok(LocalEncryptedSigningProvider::new(
            self.to_protected()?,
            "in-memory-keypair",
        ))
    }

    pub fn sign(&self, message: &[u8]) -> VResult<String> {
        let protected = self.to_protected()?;
        protected.sign(message)
    }
}

impl SigningProvider for ProtectedSigningKey {
    fn key_role(&self) -> &str {
        &self.key_role
    }
    fn derived_id(&self) -> &str {
        &self.derived_id
    }
    fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }
    fn pubkey_fingerprint(&self) -> &str {
        &self.pubkey_fingerprint
    }
    fn provider_kind(&self) -> &str {
        "protected-in-memory"
    }
    fn sign(&self, message: &[u8]) -> VResult<String> {
        ProtectedSigningKey::sign(self, message)
    }
}

impl SigningProvider for KeypairMaterial {
    fn key_role(&self) -> &str {
        &self.key_role
    }
    fn derived_id(&self) -> &str {
        &self.derived_id
    }
    fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }
    fn pubkey_fingerprint(&self) -> &str {
        &self.derived_id
    }
    fn provider_kind(&self) -> &str {
        "in-memory-keypair"
    }
    fn sign(&self, message: &[u8]) -> VResult<String> {
        KeypairMaterial::sign(self, message)
    }
}

pub fn verify_ed25519(public_key_hex: &str, message: &[u8], signature_hex: &str) -> VResult<()> {
    let pk_arr = canonical_ed25519_pubkey_bytes(public_key_hex)?;
    let vk = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|_| VNetworkError::Signature("invalid Ed25519 public key".to_string()))?;

    let sig_trimmed = signature_hex.trim();
    if sig_trimmed.len() != 128 {
        return Err(VNetworkError::Signature(
            "signature hex must be exactly 128 hex characters (64 bytes)".to_string(),
        ));
    }
    let sig_bytes = hex::decode(sig_trimmed)
        .map_err(|_| VNetworkError::Signature("invalid signature hex".to_string()))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| VNetworkError::Signature("invalid Ed25519 signature bytes".to_string()))?;

    vk.verify_strict(message, &sig)
        .map_err(|_| VNetworkError::Signature("Ed25519 signature verification failed".to_string()))
}
