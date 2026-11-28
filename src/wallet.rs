use crate::error::KernelXError;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletIdentity {
    pub public_key_hex: String,
    pub metadata: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletKeypair {
    pub wallet_id: String,
    pub public_key_hex: String,
    pub private_key_hex: String,
}

impl std::fmt::Debug for WalletKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletKeypair")
            .field("wallet_id", &self.wallet_id)
            .field("public_key_hex", &self.public_key_hex)
            .field("private_key_hex", &"[REDACTED]")
            .finish()
    }
}

impl Drop for WalletKeypair {
    fn drop(&mut self) {
        unsafe {
            let bytes = self.private_key_hex.as_bytes_mut();
            for b in bytes.iter_mut() {
                std::ptr::write_volatile(b, 0);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        self.private_key_hex.clear();
    }
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
        let seed_bytes =
            hex::decode(private_key_hex.trim()).map_err(|_| KernelXError::Signature)?;
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
    let trimmed = public_key_hex.trim();
    if trimmed.len() != 64 {
        return Err(KernelXError::Signature);
    }
    let pk_bytes = hex::decode(trimmed).map_err(|_| KernelXError::Signature)?;
    let pk_array: [u8; 32] = pk_bytes.try_into().map_err(|_| KernelXError::Signature)?;
    let vk = VerifyingKey::from_bytes(&pk_array).map_err(|_| KernelXError::Signature)?;
    let canonical = vk.to_bytes();
    if canonical != pk_array
        || canonical == [0u8; 32]
        || canonical
            == [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]
    {
        return Err(KernelXError::Signature);
    }
    Ok(vk)
}

pub fn verify_signature(
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<(), KernelXError> {
    let verifying_key = verifying_key_from_hex(public_key_hex)?;
    let sig_trimmed = signature_hex.trim();
    if sig_trimmed.len() != 128 {
        return Err(KernelXError::Signature);
    }
    let sig_bytes = hex::decode(sig_trimmed).map_err(|_| KernelXError::Signature)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| KernelXError::Signature)?;
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| KernelXError::Signature)
}
