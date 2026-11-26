use crate::consensus_gate::{replay_validator_epoch_history, verify_quorum_certificate_strict};
use crate::events::verify_event_chain;
use crate::state::{GenesisConfig, NetworkLedgerState};
use crate::supply::{compute_token_supply_breakdown, SupplyConservationBreakdown};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use vnetwork_types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateVerificationSummary {
    pub certificate_id: String,
    pub proposal_id: String,
    pub proposal_digest: String,
    pub network_id: String,
    pub genesis_commitment: String,
    pub protocol_version: String,
    pub height: u64,
    pub epoch: u64,
    pub quorum_threshold_bps: u16,
    pub approving_weight: u64,
    pub total_weight: u64,
    pub valid_vote_count: usize,
    pub ordered_event_ids: Vec<String>,
    pub event_hashes: Vec<String>,
    pub post_state_root: String,
    pub verification_status: VerificationStatus,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerProofReport {
    pub network_id: String,
    pub protocol_version: String,
    pub height: u64,
    pub logical_clock: u64,
    pub event_count: usize,
    pub certified_event_count: usize,
    pub chain_valid: bool,
    pub state_root: String,
    pub event_history_root: String,
    pub replay_hash: String,
    pub certificate_count: usize,
    pub verified_certificate_count: usize,
    pub verification_status: VerificationStatus,
    pub certificate_verifications: Vec<CertificateVerificationSummary>,
    pub token_conservation: Vec<TokenConservationSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConservationSummary {
    pub token_id: String,
    pub symbol: String,
    pub total_supply: u128,
    pub max_supply: u128,
    pub wallet_balances_total: u128,
    pub escrow_balances_total: u128,
    pub locked_collateral_total: u128,
    pub reserve_balances_total: u128,
    pub unknown_account_balances_total: u128,
    pub burned_supply: u128,
    pub drained_fees_total: u128,
    pub burned_or_drained_total: u128,
    pub verification_status: VerificationStatus,
    pub verification_reason: Option<String>,
    pub conserved: bool,
}

impl From<SupplyConservationBreakdown> for TokenConservationSummary {
    fn from(b: SupplyConservationBreakdown) -> Self {
        Self {
            token_id: b.token_id,
            symbol: b.symbol,
            total_supply: b.recorded_total_supply,
            max_supply: b.max_supply,
            wallet_balances_total: b.wallet_balances_total,
            escrow_balances_total: b.escrow_balances_total,
            locked_collateral_total: b.locked_collateral_total,
            reserve_balances_total: b.reserve_balances_total,
            unknown_account_balances_total: b.unknown_account_balances_total,
            burned_supply: b.burned_supply,
            drained_fees_total: b.drained_fees_total,
            burned_or_drained_total: b.burned_or_drained_total,
            verification_status: b.verification_status,
            verification_reason: b.verification_reason,
            conserved: b.conserved,
        }
    }
}

pub fn build_verified_ledger_proof_report(
    state: &NetworkLedgerState,
    genesis: Option<&GenesisConfig>,
) -> VResult<LedgerProofReport> {
    let chain_valid = verify_event_chain(&state.events)?;
    let state_root = state.compute_state_root()?;
    let replay_hash = state.compute_replay_hash();
    let event_history_root = state.compute_event_history_root();

    let mut token_conservation = Vec::new();
    for token in state.tokens.values() {
        let breakdown = compute_token_supply_breakdown(state, &token.token_id)?;
        token_conservation.push(breakdown.into());
    }

    let mut epoch_map_opt = None;
    let mut membership_err: Option<String> = None;
    if let Some(g) = genesis {
        match g.validate().and_then(|_| {
            let expected_hash = g.commitment_hash()?;
            if expected_hash != state.genesis_commitment
                || g.network_id != state.network_id
                || g.protocol_version != state.protocol_version
                || g.consensus_parameters != state.consensus_parameters
            {
                return Err(VNetworkError::ProfileMismatch(
                    "ledger state genesis or consensus policy diverges from local GenesisConfig"
                        .to_string(),
                ));
            }
            let ctx = g.consensus_context()?;
            replay_validator_epoch_history(
                &g.initial_validators,
                g.genesis_epoch,
                &ctx,
                &state.validator_membership_history,
            )
            .map(|(_, _, map)| map)
        }) {
            Ok(map) => epoch_map_opt = Some(map),
            Err(e) => membership_err = Some(e.to_string()),
        }
    }

    let state_event_hashes: BTreeSet<&str> =
        state.events.iter().map(|e| e.event_hash.as_str()).collect();
    let state_event_ids: BTreeSet<&str> =
        state.events.iter().map(|e| e.event_id.as_str()).collect();
    let mut certified_event_ids: BTreeSet<String> = BTreeSet::new();
    let mut certificate_verifications = Vec::with_capacity(state.certificates.len());
    let mut verified_certificate_count = 0usize;
    let mut any_invalid_cert = false;

    for cert in state.certificates.values() {
        let (cert_status, cert_reason) = if let Some(ref m_err) = membership_err {
            any_invalid_cert = true;
            (VerificationStatus::Invalid, Some(m_err.clone()))
        } else if let (Some(g), Some(epoch_map)) = (genesis, epoch_map_opt.as_ref()) {
            let events_present = cert.ordered_event_ids.len() == cert.event_hashes.len()
                && cert
                    .ordered_event_ids
                    .iter()
                    .all(|id| state_event_ids.contains(id.as_str()))
                && cert
                    .event_hashes
                    .iter()
                    .all(|h| state_event_hashes.contains(h.as_str()));
            if !events_present {
                any_invalid_cert = true;
                (
                    VerificationStatus::Invalid,
                    Some("certificate references missing or mismatched ledger events".to_string()),
                )
            } else if let Some(vals) = epoch_map.get(&cert.epoch) {
                match g
                    .consensus_context_for_epoch(cert.epoch)
                    .and_then(|ctx| verify_quorum_certificate_strict(cert, vals, &ctx))
                {
                    Ok(()) => {
                        verified_certificate_count += 1;
                        for id in &cert.ordered_event_ids {
                            certified_event_ids.insert(id.clone());
                        }
                        (VerificationStatus::Verified, None)
                    }
                    Err(e) => {
                        any_invalid_cert = true;
                        (VerificationStatus::Invalid, Some(e.to_string()))
                    }
                }
            } else {
                any_invalid_cert = true;
                (
                    VerificationStatus::Invalid,
                    Some(format!(
                        "certificate references unproven validator epoch {}",
                        cert.epoch
                    )),
                )
            }
        } else {
            (
                VerificationStatus::Unverified,
                Some("genesis consensus context not supplied for certificate verification".to_string()),
            )
        };

        certificate_verifications.push(CertificateVerificationSummary {
            certificate_id: cert.certificate_id.clone(),
            proposal_id: cert.proposal_id.clone(),
            proposal_digest: cert.proposal_digest.clone(),
            network_id: cert.network_id.clone(),
            genesis_commitment: cert.genesis_commitment.clone(),
            protocol_version: cert.protocol_version.clone(),
            height: cert.height,
            epoch: cert.epoch,
            quorum_threshold_bps: cert.quorum_threshold_bps,
            approving_weight: cert.approving_weight,
            total_weight: cert.total_weight,
            valid_vote_count: cert.votes.iter().filter(|v| v.approve).count(),
            ordered_event_ids: cert.ordered_event_ids.clone(),
            event_hashes: cert.event_hashes.clone(),
            post_state_root: cert.post_state_root.clone(),
            verification_status: cert_status,
            reason: cert_reason,
        });
    }

    let certified_event_count = certified_event_ids.len();
    let supply_invalid = token_conservation
        .iter()
        .any(|s| s.verification_status == VerificationStatus::Invalid);
    let supply_unverified = token_conservation
        .iter()
        .any(|s| s.verification_status != VerificationStatus::Verified);

    let verification_status = if !chain_valid
        || event_history_root != state.event_history_root
        || membership_err.is_some()
        || any_invalid_cert
        || supply_invalid
    {
        VerificationStatus::Invalid
    } else if genesis.is_none()
        || verified_certificate_count != certificate_verifications.len()
        || supply_unverified
    {
        VerificationStatus::Unverified
    } else {
        VerificationStatus::Verified
    };

    Ok(LedgerProofReport {
        network_id: state.network_id.clone(),
        protocol_version: state.protocol_version.clone(),
        height: state.height,
        logical_clock: state.logical_clock,
        event_count: state.events.len(),
        certified_event_count,
        chain_valid,
        state_root,
        event_history_root,
        replay_hash,
        certificate_count: state.certificates.len(),
        verified_certificate_count,
        verification_status,
        certificate_verifications,
        token_conservation,
    })
}

pub fn build_ledger_proof_report(state: &NetworkLedgerState) -> VResult<LedgerProofReport> {
    build_verified_ledger_proof_report(state, None)
}
