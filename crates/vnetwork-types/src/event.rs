use crate::canonical::{blake3_hex, canonical_json_bytes};
use crate::error::VResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEvent {
    pub sequence: u64,
    pub event_id: String,
    pub parent_hashes: Vec<String>,
    pub network_id: String,
    pub entity_kind: String,
    pub entity_id: String,
    pub operation: String,
    pub actor_pubkey: String,
    pub logical_clock: u64,
    pub timestamp_ms: u64,
    pub payload: serde_json::Value,
    pub before_hash: String,
    pub after_hash: String,
    pub payload_hash: String,
    pub event_hash: String,
}

impl LedgerEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        sequence: u64,
        parent_hashes: Vec<String>,
        network_id: impl Into<String>,
        entity_kind: impl Into<String>,
        entity_id: impl Into<String>,
        operation: impl Into<String>,
        actor_pubkey: impl Into<String>,
        logical_clock: u64,
        timestamp_ms: u64,
        payload: serde_json::Value,
        before_hash: impl Into<String>,
        after_hash: impl Into<String>,
    ) -> VResult<Self> {
        let network_id = network_id.into();
        let entity_kind = entity_kind.into();
        let entity_id = entity_id.into();
        let operation = operation.into();
        let actor_pubkey = actor_pubkey.into();
        let before_hash = before_hash.into();
        let after_hash = after_hash.into();

        let payload_bytes = canonical_json_bytes(&payload)?;
        let payload_hash = blake3_hex(&payload_bytes);
        let event_id =
            format!("{entity_kind}::{entity_id}::{operation}::{logical_clock}::{sequence}");

        let hash_input = serde_json::json!({
            "after_hash": after_hash,
            "actor_pubkey": actor_pubkey,
            "before_hash": before_hash,
            "entity_id": entity_id,
            "entity_kind": entity_kind,
            "event_id": event_id,
            "logical_clock": logical_clock,
            "network_id": network_id,
            "operation": operation,
            "parent_hashes": parent_hashes,
            "payload_hash": payload_hash,
            "sequence": sequence,
            "timestamp_ms": timestamp_ms,
        });
        let event_hash = blake3_hex(&canonical_json_bytes(&hash_input)?);

        Ok(Self {
            sequence,
            event_id,
            parent_hashes,
            network_id,
            entity_kind,
            entity_id,
            operation,
            actor_pubkey,
            logical_clock,
            timestamp_ms,
            payload,
            before_hash,
            after_hash,
            payload_hash,
            event_hash,
        })
    }

    pub fn verify_hashes(&self) -> VResult<bool> {
        let payload_hash = blake3_hex(&canonical_json_bytes(&self.payload)?);
        if payload_hash != self.payload_hash {
            return Ok(false);
        }
        let hash_input = serde_json::json!({
            "after_hash": self.after_hash,
            "actor_pubkey": self.actor_pubkey,
            "before_hash": self.before_hash,
            "entity_id": self.entity_id,
            "entity_kind": self.entity_kind,
            "event_id": self.event_id,
            "logical_clock": self.logical_clock,
            "network_id": self.network_id,
            "operation": self.operation,
            "parent_hashes": self.parent_hashes,
            "payload_hash": self.payload_hash,
            "sequence": self.sequence,
            "timestamp_ms": self.timestamp_ms,
        });
        let expected = blake3_hex(&canonical_json_bytes(&hash_input)?);
        Ok(expected == self.event_hash)
    }
}
