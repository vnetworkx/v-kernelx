use crate::hierarchy::Visibility;
use crate::token::TokenVector;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceEntity {
    pub space_id: String,
    pub name: String,
    pub visibility: Visibility,
    pub ghost: bool,
    pub owner_pubkey: String,
    pub created_at_ms: u64,
    pub version: u64,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionEntity {
    pub region_id: String,
    pub space_id: String,
    pub name: String,
    pub prefix: Option<String>,
    pub title: Option<String>,
    pub visibility: Visibility,
    pub section: u64,
    pub ghost: bool,
    pub auth_ratio_bps: u64,
    pub creator_pubkey: String,
    pub created_at_ms: u64,
    pub version: u64,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletKeyBinding {
    pub public_key_hex: String,
    pub role: String,
    pub added_by: String,
    pub added_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletEntity {
    pub wallet_id: String,
    pub name: String,
    pub region_id: String,
    pub space_id: String,
    pub ghost: bool,
    pub owner_pubkey: String,
    pub authorized_keys: BTreeMap<String, WalletKeyBinding>,
    pub created_at_ms: u64,
    pub version: u64,
}

impl WalletEntity {
    pub fn is_authorized_signer(&self, pubkey_hex: &str) -> bool {
        self.owner_pubkey == pubkey_hex || self.authorized_keys.contains_key(pubkey_hex)
    }

    pub fn signer_keys(&self) -> BTreeSet<String> {
        let mut set = BTreeSet::new();
        set.insert(self.owner_pubkey.clone());
        for k in self.authorized_keys.keys() {
            set.insert(k.clone());
        }
        set
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenEntity {
    pub token_id: String,
    pub name: String,
    pub symbol: String,
    pub wallet_id: String,
    pub region_id: String,
    pub space_id: String,
    pub ghost: bool,
    pub dimensions: usize,
    pub initial_vector: TokenVector,
    pub total_supply: u128,
    pub max_supply: u128,
    pub drain_bps: u16,
    pub purpose: String,
    pub external_monetary_value: String,
    pub authority_pubkey: String,
    pub created_at_ms: u64,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBalanceRecord {
    pub token_id: String,
    pub wallet_id: String,
    pub vector: TokenVector,
    pub updated_at_ms: u64,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VContractEntity {
    pub contract_id: String,
    pub name: String,
    pub space_id: Option<String>,
    pub region_id: Option<String>,
    pub creator_pubkey: String,
    pub rules: BTreeMap<String, serde_json::Value>,
    pub actions: Vec<serde_json::Value>,
    pub execution_count: u64,
    pub active: bool,
    pub created_at_ms: u64,
    pub version: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LoanStatus {
    Created,
    Active,
    Repaid,
    Liquidated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VLoanEntity {
    pub loan_id: String,
    pub name: String,
    pub token_id: String,
    pub lender_wallet_id: String,
    pub borrower_wallet_id: String,
    pub principal: u128,
    pub collateral_locked: u128,
    pub repaid_amount: u128,
    pub interest_bps: u16,
    pub status: LoanStatus,
    pub creator_pubkey: String,
    pub created_at_ms: u64,
    pub version: u64,
}
