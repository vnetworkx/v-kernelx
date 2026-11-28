use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", content = "payload")]
pub enum NetworkOperation {
    CreateSpace {
        name: String,
        visibility: String,
        ghost: bool,
    },
    CreateRegion {
        space_id: String,
        name: String,
        prefix: Option<String>,
        title: Option<String>,
        visibility: String,
        section: u64,
        ghost: bool,
    },
    CreateWallet {
        region_id: String,
        name: String,
        ghost: bool,
        #[serde(default)]
        approval_threshold: Option<u16>,
    },
    AuthorizeWalletKey {
        wallet_id: String,
        authorized_pubkey: String,
        role: String,
        #[serde(default)]
        permissions: Vec<String>,
        #[serde(default)]
        allowed_token_ids: Vec<String>,
        #[serde(default)]
        max_amount_per_op: Option<u128>,
        #[serde(default)]
        expires_at_ms: Option<u64>,
        #[serde(default)]
        pop_nonce: Option<String>,
        #[serde(default)]
        pop_signature: Option<String>,
        #[serde(default)]
        participant_identity: Option<String>,
    },
    RevokeWalletKey {
        wallet_id: String,
        target_pubkey: String,
    },
    RotateWalletKey {
        wallet_id: String,
        old_pubkey: String,
        new_pubkey: String,
        role: Option<String>,
        #[serde(default)]
        pop_nonce: Option<String>,
        #[serde(default)]
        pop_signature: Option<String>,
        #[serde(default)]
        participant_identity: Option<String>,
    },
    GrantParticipantScope {
        target_participant_id: String,
        level: String,
        target_id: Option<String>,
        expires_at_ms: Option<u64>,
    },
    RevokeParticipantScope {
        target_participant_id: String,
        level: String,
        target_id: Option<String>,
    },
    ReinstateParticipant {
        target_participant_id: String,
    },
    CreateToken {
        wallet_id: String,
        name: String,
        symbol: String,
        initial_supply: u128,
        max_supply: u128,
        #[serde(default)]
        unlimited_supply: bool,
        auth_ratio_au: u128,
        energy: u128,
        drain_bps: u16,
        purpose: String,
        external_monetary_value: String,
        ghost: bool,
    },
    TransferToken {
        token_id: String,
        from_wallet_id: String,
        to_wallet_id: String,
        amount: u128,
        #[serde(default)]
        cosignatures: Vec<(String, String)>,
    },
    UpdateWalletReceivePolicy {
        wallet_id: String,
        mode: String,
        #[serde(default)]
        allowed_senders: Vec<String>,
    },
    DrainToken {
        token_id: String,
        wallet_id: String,
        amount: u128,
    },
    AdjustNonTransferableDimensions {
        token_id: String,
        wallet_id: String,
        new_auth_ratio_au: Option<u128>,
        new_energy: Option<u128>,
        reason: String,
    },
    CreateContract {
        name: String,
        region_id: Option<String>,
        rules: serde_json::Value,
        actions: Vec<serde_json::Value>,
    },
    ExecuteContract {
        contract_id: String,
        action: String,
        args: serde_json::Value,
    },
    CreateLoan {
        name: String,
        token_id: String,
        lender_wallet_id: String,
        borrower_wallet_id: String,
        principal: u128,
        collateral: u128,
        interest_bps: u16,
        #[serde(default)]
        maturity_at_ms: Option<u64>,
    },
    ExecuteLoan {
        loan_id: String,
        action: String,
        amount: u128,
    },
}
