use crate::canonical::blake3_hex;
use serde::{Deserialize, Serialize};

pub fn derive_prefixed_id(prefix: &str, domain: &str, material: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(b":");
    hasher.update(material);
    let digest = hasher.finalize().to_hex().to_string();
    format!("{prefix}_{}", &digest[..24])
}

pub fn derive_node_id(pubkey_hex: &str) -> String {
    derive_prefixed_id("nod", "vnetwork/node-id-v1", pubkey_hex.as_bytes())
}

pub fn derive_participant_id(pubkey_hex: &str) -> String {
    derive_prefixed_id("prt", "vnetwork/participant-id-v1", pubkey_hex.as_bytes())
}

pub fn derive_space_id(name: &str, creator_pubkey: &str) -> String {
    let key = format!("{}::{}", name.trim().to_ascii_lowercase(), creator_pubkey);
    derive_prefixed_id("spc", "vnetwork/space-id-v1", key.as_bytes())
}

pub fn derive_region_id(space_id: &str, name: &str, prefix: Option<&str>) -> String {
    let pfx = prefix.unwrap_or("").trim().to_ascii_uppercase();
    let key = format!("{space_id}::{pfx}::{}", name.trim().to_ascii_lowercase());
    derive_prefixed_id("reg", "vnetwork/region-id-v1", key.as_bytes())
}

pub fn derive_wallet_id(pubkey_hex: &str) -> String {
    derive_prefixed_id("wlt", "vnetwork/wallet-id-v1", pubkey_hex.as_bytes())
}

pub fn derive_named_wallet_id(region_id: &str, name: &str, owner_pubkey: &str) -> String {
    let key = format!(
        "{region_id}::{}::{owner_pubkey}",
        name.trim().to_ascii_lowercase()
    );
    derive_prefixed_id("wlt", "vnetwork/named-wallet-id-v1", key.as_bytes())
}

pub fn derive_token_id(wallet_id: &str, symbol: &str) -> String {
    let key = format!("{wallet_id}::{}", symbol.trim().to_ascii_uppercase());
    derive_prefixed_id("tkn", "vnetwork/token-id-v1", key.as_bytes())
}

pub fn derive_contract_id(name: &str, creator_pubkey: &str, nonce: u64) -> String {
    let key = format!(
        "{}::{creator_pubkey}::{nonce}",
        name.trim().to_ascii_lowercase()
    );
    derive_prefixed_id("cnt", "vnetwork/contract-id-v1", key.as_bytes())
}

pub fn derive_loan_id(name: &str, creator_pubkey: &str, nonce: u64) -> String {
    let key = format!(
        "{}::{creator_pubkey}::{nonce}",
        name.trim().to_ascii_lowercase()
    );
    derive_prefixed_id("lon", "vnetwork/loan-id-v1", key.as_bytes())
}

pub fn derive_program_id(source_hash: &str, submitter_id: &str, nonce: u64) -> String {
    let key = format!("{source_hash}::{submitter_id}::{nonce}");
    derive_prefixed_id("prg", "vnetwork/program-id-v1", key.as_bytes())
}

pub fn derive_tx_id(payload_bytes: &[u8]) -> String {
    let h = blake3_hex(payload_bytes);
    format!("tx_{}", &h[..24])
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntityRef {
    pub kind: String,
    pub id: String,
}
