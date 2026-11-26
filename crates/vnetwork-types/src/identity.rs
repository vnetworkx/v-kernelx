use crate::error::{VNetworkError, VResult};
use crate::ids::{derive_node_id, derive_participant_id, derive_wallet_id};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

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

/// Independent Ed25519 keypair (used distinctly for Node, Participant, Wallet, or Validator keys).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeypairMaterial {
    pub key_role: String,
    pub derived_id: String,
    pub public_key_hex: String,
    pub private_key_hex: String,
}

impl KeypairMaterial {
    pub fn generate(role: &str) -> Self {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        Self::from_signing_key(role, &sk)
    }

    pub fn from_private_hex(role: &str, private_hex: &str) -> VResult<Self> {
        let bytes = hex::decode(private_hex.trim())
            .map_err(|_| VNetworkError::Signature("invalid hex private key".to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| VNetworkError::Signature("private key must be 32 bytes".to_string()))?;
        let sk = SigningKey::from_bytes(&arr);
        Ok(Self::from_signing_key(role, &sk))
    }

    fn from_signing_key(role: &str, sk: &SigningKey) -> Self {
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let sk_hex = hex::encode(sk.to_bytes());
        let derived_id = match role {
            "node" => derive_node_id(&pk_hex),
            "participant" => derive_participant_id(&pk_hex),
            _ => derive_wallet_id(&pk_hex),
        };
        Self {
            key_role: role.to_string(),
            derived_id,
            public_key_hex: pk_hex,
            private_key_hex: sk_hex,
        }
    }

    pub fn sign(&self, message: &[u8]) -> VResult<String> {
        let bytes = hex::decode(&self.private_key_hex)
            .map_err(|_| VNetworkError::Signature("invalid stored private key".to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| VNetworkError::Signature("invalid key length".to_string()))?;
        let sk = SigningKey::from_bytes(&arr);
        Ok(hex::encode(sk.sign(message).to_bytes()))
    }
}

pub fn verify_ed25519(public_key_hex: &str, message: &[u8], signature_hex: &str) -> VResult<()> {
    let pk_bytes = hex::decode(public_key_hex.trim())
        .map_err(|_| VNetworkError::Signature("invalid public key hex".to_string()))?;
    let pk_arr: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| VNetworkError::Signature("public key must be 32 bytes".to_string()))?;
    let vk = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|_| VNetworkError::Signature("invalid Ed25519 public key".to_string()))?;

    let sig_bytes = hex::decode(signature_hex.trim())
        .map_err(|_| VNetworkError::Signature("invalid signature hex".to_string()))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| VNetworkError::Signature("invalid Ed25519 signature bytes".to_string()))?;

    vk.verify(message, &sig)
        .map_err(|_| VNetworkError::Signature("Ed25519 signature verification failed".to_string()))
}
