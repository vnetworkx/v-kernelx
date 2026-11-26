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
    },
    AuthorizeWalletKey {
        wallet_id: String,
        authorized_pubkey: String,
        role: String,
    },
    CreateToken {
        wallet_id: String,
        name: String,
        symbol: String,
        initial_supply: u128,
        max_supply: u128,
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
        drain_bps: Option<u16>,
    },
    DrainToken {
        token_id: String,
        wallet_id: String,
        amount: u128,
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
    },
    ExecuteLoan {
        loan_id: String,
        action: String,
        amount: u128,
    },
}
