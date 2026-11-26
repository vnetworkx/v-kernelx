use crate::error::KernelXError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletIdentity {
    pub public_key_hex: String,
    pub metadata: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletKeypair {
    pub wallet_id: String,
    pub public_key_hex: String,
    pub private_key_hex: String,
}

pub struct WalletContext {
    signing_key: SigningKey,
    public_key_hex: String,
    pub metadata: std::collections::BTreeMap<String, String>,
}

pub fn derive_wallet_id(public_key_hex: &str) -> Result<String, KernelXError> {
    let pk_bytes = hex::decode(public_key_hex).map_err(|_| KernelXError::Signature)?;
    if pk_bytes.len() != 32 {
        return Err(KernelXError::Signature);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"v-kernelx/wallet-id-v1:");
    hasher.update(&pk_bytes);
    let digest = hasher.finalize().to_hex().to_string();
    Ok(format!("wlt_{}", &digest[..24]))
}

impl WalletContext {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        Self {
            signing_key,
            public_key_hex,
            metadata: std::collections::BTreeMap::new(),
        }
    }

    pub fn from_private_key_hex(private_key_hex: &str) -> Result<Self, KernelXError> {
        let seed_bytes = hex::decode(private_key_hex.trim()).map_err(|_| KernelXError::Signature)?;
        let seed_array: [u8; 32] = seed_bytes.try_into().map_err(|_| KernelXError::Signature)?;
        let signing_key = SigningKey::from_bytes(&seed_array);
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        Ok(Self {
            signing_key,
            public_key_hex,
            metadata: std::collections::BTreeMap::new(),
        })
    }

    pub fn public_key_hex(&self) -> String {
        self.public_key_hex.clone()
    }

    pub fn private_key_hex(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }

    pub fn wallet_id(&self) -> Result<String, KernelXError> {
        derive_wallet_id(&self.public_key_hex)
    }

    pub fn export_keypair(&self) -> Result<WalletKeypair, KernelXError> {
        Ok(WalletKeypair {
            wallet_id: self.wallet_id()?,
            public_key_hex: self.public_key_hex(),
            private_key_hex: self.private_key_hex(),
        })
    }

    pub fn identity(&self) -> WalletIdentity {
        WalletIdentity {
            public_key_hex: self.public_key_hex(),
            metadata: self.metadata.clone(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> String {
        let signature = self.signing_key.sign(message);
        hex::encode(signature.to_bytes())
    }
}

pub fn verifying_key_from_hex(public_key_hex: &str) -> Result<VerifyingKey, KernelXError> {
    let pk_bytes = hex::decode(public_key_hex).map_err(|_| KernelXError::Signature)?;
    let pk_array: [u8; 32] = pk_bytes.try_into().map_err(|_| KernelXError::Signature)?;
    VerifyingKey::from_bytes(&pk_array).map_err(|_| KernelXError::Signature)
}

pub fn verify_signature(
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<(), KernelXError> {
    let verifying_key = verifying_key_from_hex(public_key_hex)?;
    let sig_bytes = hex::decode(signature_hex).map_err(|_| KernelXError::Signature)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| KernelXError::Signature)?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| KernelXError::Signature)
}
