use crate::state::NetworkLedgerState;
use vnetwork_types::*;

pub fn validate_operation_preconditions(
    state: &NetworkLedgerState,
    op: &NetworkOperation,
) -> VResult<()> {
    validate_operation_preconditions_with_policy(
        state,
        state.profile.allows_dev_atlas_fixture(),
        op,
    )
}

pub fn validate_operation_preconditions_with_policy(
    state: &NetworkLedgerState,
    allow_bootstrap_atlas: bool,
    op: &NetworkOperation,
) -> VResult<()> {
    let atlas_allowed = state.profile.allows_dev_atlas_fixture() || allow_bootstrap_atlas;
    match op {
        NetworkOperation::CreateSpace { name, visibility, .. } => {
            if name.trim().is_empty() {
                return Err(VNetworkError::Validation("space name cannot be empty".to_string()));
            }
            Visibility::parse(visibility).ok_or_else(|| {
                VNetworkError::Validation(format!("invalid visibility `{visibility}`"))
            })?;
            if !atlas_allowed && name.trim().eq_ignore_ascii_case("Atlas Core Space") {
                return Err(VNetworkError::ProfileMismatch(
                    "ATLAS development bootstrap is forbidden in PRODUCTION profile unless explicitly genesis-authorized".to_string(),
                ));
            }
            Ok(())
        }
        NetworkOperation::CreateRegion {
            space_id,
            name,
            prefix,
            visibility,
            ..
        } => {
            if space_id.trim().is_empty() || name.trim().is_empty() {
                return Err(VNetworkError::Validation(
                    "space_id and region name are required".to_string(),
                ));
            }
            Visibility::parse(visibility).ok_or_else(|| {
                VNetworkError::Validation(format!("invalid visibility `{visibility}`"))
            })?;
            let is_atlas = name.trim().eq_ignore_ascii_case("ATLAS")
                || name.trim().eq_ignore_ascii_case("Atlas Genesis Region")
                || prefix
                    .as_deref()
                    .map(|p| p.trim().eq_ignore_ascii_case("ATLAS"))
                    .unwrap_or(false);
            if !atlas_allowed && is_atlas {
                return Err(VNetworkError::ProfileMismatch(
                    "ATLAS development bootstrap is forbidden in PRODUCTION profile unless explicitly genesis-authorized".to_string(),
                ));
            }
            Ok(())
        }
        NetworkOperation::CreateWallet { region_id, name, .. } => {
            if region_id.trim().is_empty() || name.trim().is_empty() {
                return Err(VNetworkError::Validation(
                    "region_id and wallet name are required".to_string(),
                ));
            }
            Ok(())
        }
        NetworkOperation::AuthorizeWalletKey {
            wallet_id,
            authorized_pubkey,
            ..
        } => {
            if wallet_id.trim().is_empty() || authorized_pubkey.trim().is_empty() {
                return Err(VNetworkError::Validation(
                    "wallet_id and authorized_pubkey are required".to_string(),
                ));
            }
            Ok(())
        }
        NetworkOperation::CreateToken {
            wallet_id,
            name,
            symbol,
            initial_supply,
            max_supply,
            drain_bps,
            ..
        } => {
            if wallet_id.trim().is_empty() || name.trim().is_empty() || symbol.trim().is_empty() {
                return Err(VNetworkError::Validation(
                    "wallet_id, token name, and symbol are required".to_string(),
                ));
            }
            if !atlas_allowed
                && (name.trim().eq_ignore_ascii_case("ATLAS")
                    || symbol.trim().eq_ignore_ascii_case("ATLAS"))
            {
                return Err(VNetworkError::ProfileMismatch(
                    "ATLAS development bootstrap is forbidden in PRODUCTION profile unless explicitly genesis-authorized".to_string(),
                ));
            }
            if *max_supply > 0 && *initial_supply > *max_supply {
                return Err(VNetworkError::Validation(
                    "initial_supply exceeds max_supply".to_string(),
                ));
            }
            if *drain_bps > 10_000 {
                return Err(VNetworkError::Validation(
                    "drain_bps cannot exceed 10000".to_string(),
                ));
            }
            Ok(())
        }
        NetworkOperation::TransferToken {
            token_id,
            from_wallet_id,
            to_wallet_id,
            amount,
            drain_bps,
        } => {
            if token_id.trim().is_empty()
                || from_wallet_id.trim().is_empty()
                || to_wallet_id.trim().is_empty()
            {
                return Err(VNetworkError::Validation(
                    "token_id, from_wallet_id, and to_wallet_id are required".to_string(),
                ));
            }
            if *amount == 0 {
                return Err(VNetworkError::Validation(
                    "transfer amount must be positive".to_string(),
                ));
            }
            if let Some(d) = drain_bps {
                if *d > 10_000 {
                    return Err(VNetworkError::Validation(
                        "drain_bps cannot exceed 10000".to_string(),
                    ));
                }
            }
            Ok(())
        }
        NetworkOperation::DrainToken {
            token_id,
            wallet_id,
            amount,
        } => {
            if token_id.trim().is_empty() || wallet_id.trim().is_empty() || *amount == 0 {
                return Err(VNetworkError::Validation(
                    "token_id, wallet_id, and positive amount required for drain".to_string(),
                ));
            }
            Ok(())
        }
        NetworkOperation::CreateContract { name, .. } => {
            if name.trim().is_empty() {
                return Err(VNetworkError::Validation(
                    "contract name cannot be empty".to_string(),
                ));
            }
            Ok(())
        }
        NetworkOperation::ExecuteContract {
            contract_id,
            action,
            ..
        } => {
            if contract_id.trim().is_empty() || action.trim().is_empty() {
                return Err(VNetworkError::Validation(
                    "contract_id and action are required".to_string(),
                ));
            }
            Ok(())
        }
        NetworkOperation::CreateLoan {
            name,
            token_id,
            lender_wallet_id,
            borrower_wallet_id,
            principal,
            ..
        } => {
            if name.trim().is_empty()
                || token_id.trim().is_empty()
                || lender_wallet_id.trim().is_empty()
                || borrower_wallet_id.trim().is_empty()
                || *principal == 0
            {
                return Err(VNetworkError::Validation(
                    "invalid loan parameters".to_string(),
                ));
            }
            Ok(())
        }
        NetworkOperation::ExecuteLoan { loan_id, action, .. } => {
            if loan_id.trim().is_empty() || action.trim().is_empty() {
                return Err(VNetworkError::Validation(
                    "loan_id and action are required".to_string(),
                ));
            }
            Ok(())
        }
    }
}
