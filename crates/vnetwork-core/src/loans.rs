use crate::hierarchy::{verify_token_exists, verify_wallet_exists};
use crate::state::NetworkLedgerState;
use crate::supply::verify_token_supply_conservation;
use crate::token::apply_protocol_settlement_transfer;
use vnetwork_types::*;

pub fn loan_escrow_wallet_id(loan_id: &str) -> String {
    format!("escrow::{loan_id}")
}

pub fn move_loan_escrow_balance(
    state: &mut NetworkLedgerState,
    token_id: &str,
    from_id: &str,
    to_id: &str,
    amount: u128,
    timestamp_ms: u64,
) -> VResult<()> {
    if amount == 0 {
        return Ok(());
    }
    let from_key = NetworkLedgerState::balance_key(token_id, from_id);
    let to_key = NetworkLedgerState::balance_key(token_id, to_id);

    let mut from_bal = state
        .balances
        .get(&from_key)
        .cloned()
        .ok_or_else(|| VNetworkError::InsufficientBalance(format!("missing balance for escrow move from `{from_id}`")))?;
    from_bal.vector = from_bal.vector.checked_sub_token(amount)?;
    from_bal.updated_at_ms = timestamp_ms;
    from_bal.version = from_bal
        .version
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("balance version overflow".to_string()))?;

    let mut to_bal = state.balances.get(&to_key).cloned().unwrap_or(TokenBalanceRecord {
        token_id: token_id.to_string(),
        wallet_id: to_id.to_string(),
        vector: TokenVector::zero(),
        updated_at_ms: timestamp_ms,
        version: 0,
    });
    to_bal.vector = to_bal.vector.checked_add_token(amount)?;
    to_bal.updated_at_ms = timestamp_ms;
    to_bal.version = to_bal
        .version
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("balance version overflow".to_string()))?;

    state.balances.insert(from_key, from_bal);
    state.balances.insert(to_key, to_bal);
    Ok(())
}

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
    maturity_at_ms: Option<u64>,
    actor_pubkey: &str,
    timestamp_ms: u64,
) -> VResult<(VLoanEntity, LedgerEvent)> {
    if principal == 0 {
        return Err(VNetworkError::Validation("loan principal must be > 0".to_string()));
    }
    if interest_bps > 10_000 {
        return Err(VNetworkError::Validation("interest_bps must be <= 10000".to_string()));
    }
    if let Some(mat) = maturity_at_ms {
        if timestamp_ms >= mat {
            return Err(VNetworkError::Validation(
                "loan maturity_at_ms must be in the future".to_string(),
            ));
        }
    }

    let token = verify_token_exists(state, token_ref)?.clone();
    let lender = verify_wallet_exists(state, lender_wallet_ref)?.clone();
    let borrower = verify_wallet_exists(state, borrower_wallet_ref)?.clone();

    if lender.wallet_id == borrower.wallet_id {
        return Err(VNetworkError::Validation(
            "lender and borrower wallets must differ".to_string(),
        ));
    }

    let lender_ok = lender
        .verify_permission(
            actor_pubkey,
            WalletPermission::LoanInteract,
            Some(&token.token_id),
            Some(principal),
            timestamp_ms,
        )
        .is_ok();
    let borrower_ok = borrower
        .verify_permission(
            actor_pubkey,
            WalletPermission::LoanInteract,
            Some(&token.token_id),
            Some(collateral),
            timestamp_ms,
        )
        .is_ok();
    if !lender_ok && !borrower_ok {
        return Err(VNetworkError::Authorization(
            "loan creation requires lender or borrower wallet LoanInteract authorization"
                .to_string(),
        ));
    }
    if collateral > 0 && !borrower_ok {
        return Err(VNetworkError::Authorization(
            "locking borrower collateral requires borrower wallet LoanInteract authorization"
                .to_string(),
        ));
    }

    let nonce = (state.loans.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("loan nonce overflow".to_string()))?;
    let loan_id = derive_loan_id(name, actor_pubkey, nonce);

    if collateral > 0 {
        let escrow_id = loan_escrow_wallet_id(&loan_id);
        move_loan_escrow_balance(
            state,
            &token.token_id,
            &borrower.wallet_id,
            &escrow_id,
            collateral,
            timestamp_ms,
        )?;
        if !verify_token_supply_conservation(state, &token.token_id)? {
            return Err(VNetworkError::Validation(
                "token supply conservation check failed during collateral lock".to_string(),
            ));
        }
    }

    let loan = VLoanEntity {
        loan_id: loan_id.clone(),
        name: name.trim().to_string(),
        token_id: token.token_id.clone(),
        collateral_token_id: token.token_id,
        lender_wallet_id: lender.wallet_id,
        borrower_wallet_id: borrower.wallet_id,
        lender_pubkey: lender.owner_pubkey,
        borrower_pubkey: borrower.owner_pubkey,
        principal,
        disbursed_amount: 0,
        collateral_locked: collateral,
        repaid_amount: 0,
        accrued_interest: 0,
        interest_bps,
        maturity_at_ms,
        defaulted: false,
        repayment_history: Vec::new(),
        status: LoanStatus::Created,
        creator_pubkey: actor_pubkey.to_string(),
        created_at_ms: timestamp_ms,
        version: 1,
    };

    state.loans.insert(loan_id.clone(), loan.clone());
    state.logical_clock = state
        .logical_clock
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
    let sequence = (state.events.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
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
        serde_json::to_value(&loan).map_err(|e| VNetworkError::Serialization(e.to_string()))?,
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

    let lender = verify_wallet_exists(state, &loan.lender_wallet_id)?.clone();
    let borrower = verify_wallet_exists(state, &loan.borrower_wallet_id)?.clone();

    let before_hash = blake3_hex(&canonical_json_bytes(&loan)?);
    let mut events = Vec::new();
    let norm = action.trim().to_ascii_lowercase();

    match norm.as_str() {
        "fund" => {
            if loan.status != LoanStatus::Created {
                return Err(VNetworkError::Validation("loan already funded".to_string()));
            }
            let draw_amt = if amount == 0 { loan.principal } else { amount };
            if draw_amt == 0 || draw_amt > loan.principal {
                return Err(VNetworkError::Validation(format!(
                    "loan fund amount `{draw_amt}` must be in 1..={}",
                    loan.principal
                )));
            }
            lender.verify_permission(
                actor_pubkey,
                WalletPermission::LoanInteract,
                Some(&loan.token_id),
                Some(draw_amt),
                timestamp_ms,
            )?;
            let (_, _, _, tx_ev) = apply_protocol_settlement_transfer(
                state,
                &loan.token_id,
                &loan.lender_wallet_id,
                &loan.borrower_wallet_id,
                draw_amt,
                actor_pubkey,
                timestamp_ms,
            )?;
            events.push(tx_ev);
            loan.disbursed_amount = draw_amt;
            let interest = draw_amt
                .checked_mul(loan.interest_bps as u128)
                .ok_or_else(|| VNetworkError::Validation("loan interest overflow".to_string()))?
                / 10_000;
            loan.accrued_interest = loan
                .accrued_interest
                .checked_add(interest)
                .ok_or_else(|| VNetworkError::Validation("accrued interest overflow".to_string()))?;
            loan.status = LoanStatus::Active;
        }
        "draw" => {
            if loan.status != LoanStatus::Created && loan.status != LoanStatus::Active {
                return Err(VNetworkError::Validation(
                    "loan cannot be drawn after settlement or liquidation".to_string(),
                ));
            }
            let remaining_facility = loan
                .principal
                .checked_sub(loan.disbursed_amount)
                .ok_or_else(|| VNetworkError::Validation("disbursed exceeds principal".to_string()))?;
            if remaining_facility == 0 {
                return Err(VNetworkError::Validation(
                    "loan principal facility is already fully disbursed".to_string(),
                ));
            }
            let draw_amt = if amount == 0 { remaining_facility } else { amount };
            if draw_amt == 0 || draw_amt > remaining_facility {
                return Err(VNetworkError::Validation(format!(
                    "loan draw amount `{draw_amt}` exceeds remaining authorized principal `{remaining_facility}`"
                )));
            }
            lender.verify_permission(
                actor_pubkey,
                WalletPermission::LoanInteract,
                Some(&loan.token_id),
                Some(draw_amt),
                timestamp_ms,
            )?;
            let (_, _, _, tx_ev) = apply_protocol_settlement_transfer(
                state,
                &loan.token_id,
                &loan.lender_wallet_id,
                &loan.borrower_wallet_id,
                draw_amt,
                actor_pubkey,
                timestamp_ms,
            )?;
            events.push(tx_ev);
            loan.disbursed_amount = loan
                .disbursed_amount
                .checked_add(draw_amt)
                .ok_or_else(|| VNetworkError::Validation("disbursed_amount overflow".to_string()))?;
            let interest = draw_amt
                .checked_mul(loan.interest_bps as u128)
                .ok_or_else(|| VNetworkError::Validation("loan interest overflow".to_string()))?
                / 10_000;
            loan.accrued_interest = loan
                .accrued_interest
                .checked_add(interest)
                .ok_or_else(|| VNetworkError::Validation("accrued interest overflow".to_string()))?;
            loan.status = LoanStatus::Active;
        }
        "repay" => {
            if loan.status != LoanStatus::Active {
                return Err(VNetworkError::Validation(
                    "loan must be Active before repayment".to_string(),
                ));
            }
            borrower.verify_permission(
                actor_pubkey,
                WalletPermission::LoanInteract,
                Some(&loan.token_id),
                None,
                timestamp_ms,
            )?;
            let base_principal = if loan.disbursed_amount > 0 {
                loan.disbursed_amount
            } else {
                loan.principal
            };
            let total_owed = base_principal
                .checked_add(loan.accrued_interest)
                .ok_or_else(|| VNetworkError::Validation("loan total owed overflow".to_string()))?;
            let remaining = total_owed
                .checked_sub(loan.repaid_amount)
                .ok_or_else(|| {
                    VNetworkError::Validation("loan repaid_amount exceeds total owed".to_string())
                })?;
            if remaining == 0 {
                return Err(VNetworkError::Validation("loan is already fully repaid".to_string()));
            }
            let repay_amt = if amount == 0 { remaining } else { amount };
            if repay_amt > remaining {
                return Err(VNetworkError::Validation(format!(
                    "repayment amount `{repay_amt}` exceeds remaining owed `{remaining}`"
                )));
            }
            let (_, _, _, tx_ev) = apply_protocol_settlement_transfer(
                state,
                &loan.token_id,
                &loan.borrower_wallet_id,
                &loan.lender_wallet_id,
                repay_amt,
                actor_pubkey,
                timestamp_ms,
            )?;
            events.push(tx_ev);
            loan.repaid_amount = loan
                .repaid_amount
                .checked_add(repay_amt)
                .ok_or_else(|| VNetworkError::Validation("repaid_amount overflow".to_string()))?;
            loan.repayment_history.push(LoanRepaymentRecord {
                amount: repay_amt,
                actor_pubkey: actor_pubkey.to_string(),
                timestamp_ms,
            });
            if loan.repaid_amount >= total_owed {
                loan.status = LoanStatus::Repaid;
                if loan.collateral_locked > 0 {
                    let escrow_id = loan_escrow_wallet_id(&loan.loan_id);
                    let col = loan.collateral_locked;
                    let c_token = if loan.collateral_token_id.is_empty() {
                        loan.token_id.as_str()
                    } else {
                        loan.collateral_token_id.as_str()
                    };
                    move_loan_escrow_balance(
                        state,
                        c_token,
                        &escrow_id,
                        &loan.borrower_wallet_id,
                        col,
                        timestamp_ms,
                    )?;
                    loan.collateral_locked = 0;
                    if !verify_token_supply_conservation(state, c_token)? {
                        return Err(VNetworkError::Validation(
                            "token supply conservation check failed releasing collateral"
                                .to_string(),
                        ));
                    }
                }
            }
        }
        "default" => {
            if loan.status != LoanStatus::Active {
                return Err(VNetworkError::Validation(
                    "only active loans can transition to defaulted".to_string(),
                ));
            }
            if loan.defaulted {
                return Err(VNetworkError::Validation("loan is already marked defaulted".to_string()));
            }
            lender.verify_permission(
                actor_pubkey,
                WalletPermission::LoanInteract,
                Some(&loan.token_id),
                None,
                timestamp_ms,
            )?;
            match loan.maturity_at_ms {
                Some(mat) if timestamp_ms >= mat => {
                    loan.defaulted = true;
                }
                Some(mat) => {
                    return Err(VNetworkError::Validation(format!(
                        "cannot mark loan `{}` defaulted before maturity_at_ms {mat}",
                        loan.name
                    )));
                }
                None => {
                    return Err(VNetworkError::Validation(format!(
                        "cannot mark loan `{}` defaulted without an explicit matured schedule",
                        loan.name
                    )));
                }
            }
        }
        "liquidate" => {
            if loan.status != LoanStatus::Active {
                return Err(VNetworkError::Validation("only active loans can liquidate".to_string()));
            }
            lender.verify_permission(
                actor_pubkey,
                WalletPermission::LoanInteract,
                Some(&loan.token_id),
                None,
                timestamp_ms,
            )?;
            let matured = loan.maturity_at_ms.is_some_and(|mat| timestamp_ms >= mat);
            if !matured && !loan.defaulted {
                return Err(VNetworkError::Validation(match loan.maturity_at_ms {
                    Some(mat) => format!(
                        "cannot liquidate loan `{}` before maturity_at_ms {mat}",
                        loan.name
                    ),
                    None => format!(
                        "cannot liquidate loan `{}` without maturity_at_ms or active default",
                        loan.name
                    ),
                }));
            }
            if loan.collateral_locked > 0 {
                let escrow_id = loan_escrow_wallet_id(&loan.loan_id);
                let col = loan.collateral_locked;
                let c_token = if loan.collateral_token_id.is_empty() {
                    loan.token_id.as_str()
                } else {
                    loan.collateral_token_id.as_str()
                };
                move_loan_escrow_balance(
                    state,
                    c_token,
                    &escrow_id,
                    &loan.lender_wallet_id,
                    col,
                    timestamp_ms,
                )?;
                loan.collateral_locked = 0;
                if !verify_token_supply_conservation(state, c_token)? {
                    return Err(VNetworkError::Validation(
                        "token supply conservation check failed seizing collateral".to_string(),
                    ));
                }
            }
            loan.status = LoanStatus::Liquidated;
        }
        _ => {
            return Err(VNetworkError::Validation(format!(
                "unsupported loan action `{action}`"
            )));
        }
    }

    loan.version = loan
        .version
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("loan version overflow".to_string()))?;
    state.loans.insert(loan.loan_id.clone(), loan.clone());
    state.logical_clock = state
        .logical_clock
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("logical_clock overflow".to_string()))?;
    let sequence = (state.events.len() as u64)
        .checked_add(1)
        .ok_or_else(|| VNetworkError::Validation("event sequence overflow".to_string()))?;
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
        serde_json::to_value(&loan).map_err(|e| VNetworkError::Serialization(e.to_string()))?,
        before_hash,
        after_hash,
    )?;
    state.events.push(loan_ev.clone());
    events.push(loan_ev);
    Ok((loan, events))
}
