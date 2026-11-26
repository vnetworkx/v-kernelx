use crate::error::{VNetworkError, VResult};
use crate::hierarchy::Visibility;
use crate::token::{TokenVector, TOKEN_SCHEMA_VERSION};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

fn default_approval_threshold() -> u16 {
    1
}

fn default_token_schema_version() -> u16 {
    TOKEN_SCHEMA_VERSION
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WalletPermission {
    View,
    Receive,
    Send,
    Drain,
    ManageKeys,
    ContractInteract,
    LoanInteract,
}

impl WalletPermission {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "VIEW" => Some(Self::View),
            "RECEIVE" => Some(Self::Receive),
            "SEND" | "TRANSFER" => Some(Self::Send),
            "DRAIN" => Some(Self::Drain),
            "MANAGE_KEYS" | "MANAGEKEYS" | "ADMIN" => Some(Self::ManageKeys),
            "CONTRACT_INTERACT" | "CONTRACT" => Some(Self::ContractInteract),
            "LOAN_INTERACT" | "LOAN" => Some(Self::LoanInteract),
            _ => None,
        }
    }

    pub fn for_role(role: &str) -> Vec<Self> {
        match role.trim().to_ascii_lowercase().as_str() {
            "owner" | "admin" | "controller" => vec![
                Self::View,
                Self::Receive,
                Self::Send,
                Self::Drain,
                Self::ManageKeys,
                Self::ContractInteract,
                Self::LoanInteract,
            ],
            "operator" | "treasurer" | "delegate" => vec![
                Self::View,
                Self::Receive,
                Self::Send,
                Self::Drain,
                Self::ContractInteract,
                Self::LoanInteract,
            ],
            "signer" | "spender" => vec![
                Self::View,
                Self::Receive,
                Self::Send,
                Self::ContractInteract,
                Self::LoanInteract,
            ],
            "receiver" | "deposit_only" => vec![Self::View, Self::Receive],
            "viewer" | "auditor" | "read_only" => vec![Self::View],
            _ => Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletKeyBinding {
    pub public_key_hex: String,
    pub role: String,
    #[serde(default)]
    pub permissions: Vec<WalletPermission>,
    #[serde(default)]
    pub allowed_token_ids: Vec<String>,
    #[serde(default)]
    pub max_amount_per_op: Option<u128>,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub revoked_at_ms: Option<u64>,
    #[serde(default)]
    pub pop_nonce: Option<String>,
    pub added_by: String,
    pub added_at_ms: u64,
}

impl WalletKeyBinding {
    pub fn effective_permissions(&self) -> Vec<WalletPermission> {
        if !self.permissions.is_empty() {
            self.permissions.clone()
        } else {
            WalletPermission::for_role(&self.role)
        }
    }

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
pub struct WalletEntity {
    pub wallet_id: String,
    pub name: String,
    pub region_id: String,
    pub space_id: String,
    pub ghost: bool,
    pub owner_pubkey: String,
    pub authorized_keys: BTreeMap<String, WalletKeyBinding>,
    #[serde(default = "default_approval_threshold")]
    pub approval_threshold: u16,
    pub created_at_ms: u64,
    pub version: u64,
}

impl WalletEntity {
    pub fn is_authorized_signer(&self, pubkey_hex: &str) -> bool {
        if self.owner_pubkey == pubkey_hex {
            return true;
        }
        matches!(self.authorized_keys.get(pubkey_hex), Some(binding) if !binding.revoked)
    }

    pub fn verify_permission(
        &self,
        pubkey_hex: &str,
        required: WalletPermission,
        token_id: Option<&str>,
        amount: Option<u128>,
        now_ms: u64,
    ) -> VResult<()> {
        if self.owner_pubkey == pubkey_hex {
            return Ok(());
        }
        let binding = self.authorized_keys.get(pubkey_hex).ok_or_else(|| {
            VNetworkError::Authorization(format!(
                "actor `{pubkey_hex}` is not authorized for wallet `{}`",
                self.wallet_id
            ))
        })?;
        if binding.revoked {
            return Err(VNetworkError::Authorization(format!(
                "wallet key `{pubkey_hex}` on `{}` is revoked",
                self.wallet_id
            )));
        }
        if let Some(exp) = binding.expires_at_ms {
            if now_ms >= exp {
                return Err(VNetworkError::Authorization(format!(
                    "wallet key `{pubkey_hex}` on `{}` expired at {exp}",
                    self.wallet_id
                )));
            }
        }
        let perms = binding.effective_permissions();
        if !perms.contains(&required) {
            return Err(VNetworkError::Authorization(format!(
                "wallet key `{pubkey_hex}` with role `{}` lacks permission `{required:?}` on `{}`",
                binding.role, self.wallet_id
            )));
        }
        if let (Some(tid), false) = (token_id, binding.allowed_token_ids.is_empty()) {
            if !binding.allowed_token_ids.iter().any(|t| t == tid) {
                return Err(VNetworkError::Authorization(format!(
                    "wallet key `{pubkey_hex}` is not permitted for token `{tid}`"
                )));
            }
        }
        if let (Some(amt), Some(limit)) = (amount, binding.max_amount_per_op) {
            if amt > limit {
                return Err(VNetworkError::Authorization(format!(
                    "amount {amt} exceeds wallet key per-operation limit {limit}"
                )));
            }
        }
        Ok(())
    }

    pub fn signer_keys(&self) -> BTreeSet<String> {
        let mut set = BTreeSet::new();
        set.insert(self.owner_pubkey.clone());
        for (k, binding) in &self.authorized_keys {
            if !binding.revoked {
                set.insert(k.clone());
            }
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
    #[serde(default = "default_token_schema_version")]
    pub schema_version: u16,
    pub initial_vector: TokenVector,
    pub total_supply: u128,
    pub max_supply: u128,
    #[serde(default)]
    pub unlimited_supply: bool,
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
    #[serde(default)]
    pub authorized_actors: BTreeSet<String>,
    #[serde(default)]
    pub max_executions: Option<u64>,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    #[serde(default)]
    pub min_auth_ratio_bps: u64,
    #[serde(default)]
    pub execution_history: Vec<String>,
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
    #[serde(default)]
    pub collateral_token_id: String,
    pub lender_wallet_id: String,
    pub borrower_wallet_id: String,
    #[serde(default)]
    pub lender_pubkey: String,
    #[serde(default)]
    pub borrower_pubkey: String,
    pub principal: u128,
    pub collateral_locked: u128,
    pub repaid_amount: u128,
    #[serde(default)]
    pub accrued_interest: u128,
    pub interest_bps: u16,
    #[serde(default)]
    pub maturity_at_ms: Option<u64>,
    pub status: LoanStatus,
    pub creator_pubkey: String,
    pub created_at_ms: u64,
    pub version: u64,
}
