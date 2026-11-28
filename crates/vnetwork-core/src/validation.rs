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
            ghost,
            ..
        } => {
            if (!*ghost && space_id.trim().is_empty()) || name.trim().is_empty() {
                return Err(VNetworkError::Validation(
                    "region name is required, and non-ghost regions require space_id".to_string(),
                ));
            }
            Visibility::parse(visibility).ok_or_else(|| {
                VNetworkError::Validation(format!("invalid visibility `{visibility}`"))
            })?;
            let is_atlas = name.trim().eq_ignore_ascii_case("ATLAS")
                || name.trim().eq_ignore_ascii_case("Atlas Genesis Region")
                || prefix
                    .as_deref()
                    .map(|p| {
                        let up = p.trim();
                        up.eq_ignore_ascii_case("ATL") || up.eq_ignore_ascii_case("ATLAS")
                    })
                    .unwrap_or(false);
            if !atlas_allowed && is_atlas {
                return Err(VNetworkError::ProfileMismatch(
                    "ATLAS development bootstrap is forbidden in PRODUCTION profile unless explicitly genesis-authorized".to_string(),
                ));
            }
            Ok(())
        }
        NetworkOperation::CreateWallet {
            region_id,
            name,
            ghost,
            approval_threshold,
        } => {
            if (!*ghost && region_id.trim().is_empty()) || name.trim().is_empty() {
                return Err(VNetworkError::Validation(
                    "wallet name is required, and non-ghost wallets require region_id".to_string(),
                ));
            }
            if let Some(t) = approval_threshold {
                if *t == 0 {
                    return Err(VNetworkError::Validation(
                        "approval_threshold must be >= 1".to_string(),
                    ));
                }
            }
            Ok(())
        }
        NetworkOperation::AuthorizeWalletKey {
            wallet_id,
            authorized_pubkey,
            pop_nonce,
            pop_signature,
            ..
        } => {
            if wallet_id.trim().is_empty() || authorized_pubkey.trim().is_empty() {
                return Err(VNetworkError::Validation(
                    "wallet_id and authorized_pubkey are required".to_string(),
                ));
            }
            if pop_nonce.as_deref().map(str::trim).unwrap_or("").is_empty()
                || pop_signature.as_deref().map(str::trim).unwrap_or("").is_empty()
            {
                return Err(VNetworkError::Authorization(
                    "AuthorizeWalletKey requires non-empty pop_nonce and pop_signature".to_string(),
                ));
            }
            Ok(())
        }
        NetworkOperation::RevokeWalletKey {
            wallet_id,
            target_pubkey,
        } => {
            if wallet_id.trim().is_empty() || target_pubkey.trim().is_empty() {
                return Err(VNetworkError::Validation(
                    "wallet_id and target_pubkey are required".to_string(),
                ));
            }
            Ok(())
        }
        NetworkOperation::RotateWalletKey {
            wallet_id,
            old_pubkey,
            new_pubkey,
            pop_nonce,
            pop_signature,
            ..
        } => {
            if wallet_id.trim().is_empty()
                || old_pubkey.trim().is_empty()
                || new_pubkey.trim().is_empty()
            {
                return Err(VNetworkError::Validation(
                    "wallet_id, old_pubkey, and new_pubkey are required".to_string(),
                ));
            }
            if pop_nonce.as_deref().map(str::trim).unwrap_or("").is_empty()
                || pop_signature.as_deref().map(str::trim).unwrap_or("").is_empty()
            {
                return Err(VNetworkError::Authorization(
                    "RotateWalletKey requires non-empty pop_nonce and pop_signature".to_string(),
                ));
            }
            Ok(())
        }
        NetworkOperation::ReinstateParticipant {
            target_participant_id,
        } => {
            if target_participant_id.trim().is_empty() {
                return Err(VNetworkError::Validation(
                    "target_participant_id is required".to_string(),
                ));
            }
            Ok(())
        }
        NetworkOperation::GrantParticipantScope {
            target_participant_id,
            level,
            ..
        }
        | NetworkOperation::RevokeParticipantScope {
            target_participant_id,
            level,
            ..
        } => {
            if target_participant_id.trim().is_empty() {
                return Err(VNetworkError::Validation(
                    "target_participant_id is required".to_string(),
                ));
            }
            ParticipationLevel::parse(level).ok_or_else(|| {
                VNetworkError::Validation(format!("invalid participation level `{level}`"))
            })?;
            Ok(())
        }
        NetworkOperation::CreateToken {
            wallet_id,
            name,
            symbol,
            initial_supply,
            max_supply,
            unlimited_supply,
            drain_bps,
            ghost,
            ..
        } => {
            if (!*ghost && wallet_id.trim().is_empty())
                || name.trim().is_empty()
                || symbol.trim().is_empty()
            {
                return Err(VNetworkError::Validation(
                    "token name and symbol are required, and non-ghost tokens require wallet_id"
                        .to_string(),
                ));
            }
            if !atlas_allowed
                && (name.trim().eq_ignore_ascii_case("ATLAS")
                    || name.trim().eq_ignore_ascii_case("ATLAS TOKEN")
                    || symbol.trim().eq_ignore_ascii_case("ATLAS"))
            {
                return Err(VNetworkError::ProfileMismatch(
                    "ATLAS development bootstrap is forbidden in PRODUCTION profile unless explicitly genesis-authorized".to_string(),
                ));
            }
            if !*unlimited_supply {
                if *max_supply == 0 {
                    return Err(VNetworkError::Validation(
                        "max_supply must be > 0 unless unlimited_supply is true".to_string(),
                    ));
                }
                if *initial_supply > *max_supply {
                    return Err(VNetworkError::Validation(
                        "initial_supply exceeds max_supply".to_string(),
                    ));
                }
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
            ..
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
            Ok(())
        }
        NetworkOperation::UpdateWalletReceivePolicy {
            wallet_id,
            mode,
            allowed_senders,
        } => {
            if wallet_id.trim().is_empty() || mode.trim().is_empty() {
                return Err(VNetworkError::Validation(
                    "wallet_id and mode are required".to_string(),
                ));
            }
            let norm = mode.trim().to_ascii_uppercase();
            if !matches!(norm.as_str(), "OPEN" | "RESTRICTED" | "FROZEN") {
                return Err(VNetworkError::Validation(format!(
                    "unsupported receive policy mode `{mode}`"
                )));
            }
            if norm == "RESTRICTED" && allowed_senders.iter().all(|s| s.trim().is_empty()) {
                return Err(VNetworkError::Validation(
                    "RESTRICTED receive policy requires at least one allowed sender".to_string(),
                ));
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
        NetworkOperation::AdjustNonTransferableDimensions {
            token_id,
            wallet_id,
            new_auth_ratio_au,
            new_energy,
            reason,
        } => {
            if token_id.trim().is_empty()
                || wallet_id.trim().is_empty()
                || reason.trim().is_empty()
                || (new_auth_ratio_au.is_none() && new_energy.is_none())
            {
                return Err(VNetworkError::Validation(
                    "token_id, wallet_id, reason, and at least one non-transferable dimension required"
                        .to_string(),
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
            interest_bps,
            ..
        } => {
            if name.trim().is_empty()
                || token_id.trim().is_empty()
                || lender_wallet_id.trim().is_empty()
                || borrower_wallet_id.trim().is_empty()
                || *principal == 0
                || *interest_bps > 10_000
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
