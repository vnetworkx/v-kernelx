use crate::canonical::canonical_json_bytes;
use crate::error::VResult;
use crate::identity::verify_ed25519;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRequestEnvelope {
    pub request_id: String,
    pub network_id: String,
    pub actor_pubkey: String,
    pub nonce: u64,
    pub timestamp_ms: u64,
    pub signature: String,
    pub payload_hash: String,
}

impl SignedRequestEnvelope {
    pub fn canonical_signing_bytes(
        network_id: &str,
        request_id: &str,
        actor_pubkey: &str,
        nonce: u64,
        timestamp_ms: u64,
        payload_hash: &str,
    ) -> VResult<Vec<u8>> {
        let obj = serde_json::json!({
            "actor_pubkey": actor_pubkey,
            "network_id": network_id,
            "nonce": nonce,
            "payload_hash": payload_hash,
            "request_id": request_id,
            "timestamp_ms": timestamp_ms,
        });
        canonical_json_bytes(&obj)
    }

    pub fn verify(&self) -> VResult<()> {
        let bytes = Self::canonical_signing_bytes(
            &self.network_id,
            &self.request_id,
            &self.actor_pubkey,
            self.nonce,
            self.timestamp_ms,
            &self.payload_hash,
        )?;
        verify_ed25519(&self.actor_pubkey, &bytes, &self.signature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantChallenge {
    pub challenge_id: String,
    pub network_id: String,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}
