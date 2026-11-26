use crate::hierarchy::{verify_token_exists, verify_wallet_exists};
use crate::state::NetworkLedgerState;
use crate::token::apply_transfer_token;
use vnetwork_types::*;

#[allow(clippy::too_many_arguments)]
pub fn apply_create_loan(
    state: &mut NetworkLedgerState,
    name: &str,
    token_ref: &str,
    lender_wallet_ref: &str,
    borrower_wallet_ref: &str,
    principal: u128,
    collateral: u128,
    interest_bps: u16,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(VLoanEntity, LedgerEvent)> {
    if principal == 0 {
        return Err(VNetworkError::Validation("loan principal must be > 0".to_string()));
    }
    let token = verify_token_exists(state, token_ref)?.clone();
    let lender = verify_wallet_exists(state, lender_wallet_ref)?.clone();
    let borrower = verify_wallet_exists(state, borrower_wallet_ref)?.clone();

    if lender.wallet_id == borrower.wallet_id {
        return Err(VNetworkError::Validation(
            "lender and borrower wallets must differ".to_string(),
        ));
    }
    if !lender.is_authorized_signer(actor_pubkey) && !borrower.is_authorized_signer(actor_pubkey) {
        return Err(VNetworkError::Authorization(
            "loan creation requires lender or borrower wallet authorization".to_string(),
        ));
    }

    let nonce = (state.loans.len() as u64) + 1;
    let loan_id = derive_loan_id(name, actor_pubkey, nonce);
    let loan = VLoanEntity {
        loan_id: loan_id.clone(),
        name: name.trim().to_string(),
        token_id: token.token_id,
        lender_wallet_id: lender.wallet_id,
        borrower_wallet_id: borrower.wallet_id,
        principal,
        collateral_locked: collateral,
        repaid_amount: 0,
        interest_bps,
        status: LoanStatus::Created,
        creator_pubkey: actor_pubkey.to_string(),
        created_at_ms: timestamp_ms,
        version: 1,
    };

    state.loans.insert(loan_id.clone(), loan.clone());
    state.logical_clock += 1;
    let sequence = (state.events.len() as u64) + 1;
    let parents = state.latest_event_hash().into_iter().collect();
    let after_hash = blake3_hex(&canonical_json_bytes(&loan)?);
    let event = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "loan",
        &loan_id,
        "LOAN_CREATE",
        actor_pubkey,
        state.logical_clock,
        timestamp_ms,
        serde_json::to_value(&loan).unwrap_or_default(),
        "",
        after_hash,
    )?;
    state.events.push(event.clone());
    Ok((loan, event))
}

pub fn apply_execute_loan(
    state: &mut NetworkLedgerState,
    loan_ref: &str,
    action: &str,
    amount: u128,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(VLoanEntity, Vec<LedgerEvent>)> {
    let mut loan = state
        .loans
        .get(loan_ref)
        .or_else(|| {
            state
                .loans
                .values()
                .find(|l| l.name.eq_ignore_ascii_case(loan_ref))
        })
        .cloned()
        .ok_or_else(|| VNetworkError::NotFound(format!("loan `{loan_ref}` not found")))?;

    let before_hash = blake3_hex(&canonical_json_bytes(&loan)?);
    let mut events = Vec::new();
    let norm = action.trim().to_ascii_lowercase();

    match norm.as_str() {
        "fund" | "draw" => {
            if loan.status != LoanStatus::Created {
                return Err(VNetworkError::Validation("loan already funded".to_string()));
            }
            let draw_amt = if amount == 0 { loan.principal } else { amount };
            let (_, _, _, tx_ev) = apply_transfer_token(
                state,
                &loan.token_id,
                &loan.lender_wallet_id,
                &loan.borrower_wallet_id,
                draw_amt,
                Some(0),
                actor_pubkey,
                timestamp_ms,
            )?;
            events.push(tx_ev);
            loan.status = LoanStatus::Active;
        }
        "repay" => {
            if loan.status != LoanStatus::Active && loan.status != LoanStatus::Created {
                return Err(VNetworkError::Validation("loan is not repayable".to_string()));
            }
            let repay_amt = if amount == 0 {
                loan.principal.saturating_sub(loan.repaid_amount)
            } else {
                amount
            };
            let (_, _, _, tx_ev) = apply_transfer_token(
                state,
                &loan.token_id,
                &loan.borrower_wallet_id,
                &loan.lender_wallet_id,
                repay_amt,
                Some(0),
                actor_pubkey,
                timestamp_ms,
            )?;
            events.push(tx_ev);
            loan.repaid_amount = loan.repaid_amount.saturating_add(repay_amt);
            if loan.repaid_amount >= loan.principal {
                loan.status = LoanStatus::Repaid;
            } else {
                loan.status = LoanStatus::Active;
            }
        }
        "liquidate" => {
            if loan.status != LoanStatus::Active {
                return Err(VNetworkError::Validation("only active loans can liquidate".to_string()));
            }
            loan.status = LoanStatus::Liquidated;
        }
        _ => {
            return Err(VNetworkError::Validation(format!(
                "unsupported loan action `{action}`"
            )));
        }
    }

    loan.version += 1;
    state.loans.insert(loan.loan_id.clone(), loan.clone());
    state.logical_clock += 1;
    let sequence = (state.events.len() as u64) + 1;
    let parents = state.latest_event_hash().into_iter().collect();
    let after_hash = blake3_hex(&canonical_json_bytes(&loan)?);
    let loan_ev = LedgerEvent::build(
        sequence,
        parents,
        &state.network_id,
        "loan",
        &loan.loan_id,
        &format!("LOAN_{}", norm.to_ascii_uppercase()),
        actor_pubkey,
        state.logical_clock,
        timestamp_ms,
        serde_json::to_value(&loan).unwrap_or_default(),
        before_hash,
        after_hash,
    )?;
    state.events.push(loan_ev.clone());
    events.push(loan_ev);
    Ok((loan, events))
}
