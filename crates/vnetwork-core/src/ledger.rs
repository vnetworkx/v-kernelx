use crate::consensus_gate::{replay_validator_epoch_history, verify_quorum_certificate_strict};
use crate::events::verify_event_chain;
use crate::ghost::inspect_ghost_entities;
use crate::state::{GenesisConfig, NetworkLedgerState};
use crate::supply::{compute_token_supply_breakdown, SupplyConservationBreakdown};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HierarchyCommitmentSummary {
    pub network_commitment: String,
    pub ghost_commitment: String,
    pub space_commitments: BTreeMap<String, String>,
    pub region_commitments: BTreeMap<String, String>,
    pub wallet_commitments: BTreeMap<String, String>,
    pub token_commitments: BTreeMap<String, String>,
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
    #[serde(default)]
    pub hierarchy_commitments: HierarchyCommitmentSummary,
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
    #[serde(default)]
    pub ghost_custody_balances_total: u128,
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
            ghost_custody_balances_total: b.ghost_custody_balances_total,
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

pub fn compute_hierarchy_commitments(
    state: &NetworkLedgerState,
    state_root: &str,
    event_history_root: &str,
) -> VResult<HierarchyCommitmentSummary> {
    let network_commitment = blake3_hex(&canonical_json_bytes(&serde_json::json!({
        "domain": "vnetwork/network-ledger-v1",
        "event_history_root": event_history_root,
        "genesis_commitment": state.genesis_commitment,
        "height": state.height,
        "network_id": state.network_id,
        "state_root": state_root,
    }))?);
    let ghost_commitment = inspect_ghost_entities(state)?.ghost_ledger_commitment;

    let mut events_by_entity: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for ev in &state.events {
        events_by_entity
            .entry(ev.entity_id.as_str())
            .or_default()
            .push(ev.event_hash.as_str());
    }

    let mut space_commitments = BTreeMap::new();
    for (sid, space) in &state.spaces {
        let evs = events_by_entity.get(sid.as_str()).cloned().unwrap_or_default();
        let commit = blake3_hex(&canonical_json_bytes(&serde_json::json!({
            "domain": "vnetwork/space-ledger-v1",
            "event_hashes": evs,
            "parent_commitment": network_commitment,
            "space": space,
        }))?);
        space_commitments.insert(sid.clone(), commit);
    }

    let mut region_commitments = BTreeMap::new();
    for (rid, region) in &state.regions {
        let parent_commitment = if region.space_id.is_empty() && region.ghost {
            network_commitment.as_str()
        } else if region.space_id.is_empty() {
            return Err(VNetworkError::Validation(format!(
                "non-Ghost Region `{rid}` is missing its parent Space"
            )));
        } else {
            space_commitments
                .get(&region.space_id)
                .map(String::as_str)
                .ok_or_else(|| VNetworkError::Validation(format!(
                    "Region `{rid}` references missing parent Space `{}`",
                    region.space_id
                )))?
        };
        let evs = events_by_entity.get(rid.as_str()).cloned().unwrap_or_default();
        let commit = blake3_hex(&canonical_json_bytes(&serde_json::json!({
            "domain": "vnetwork/region-ledger-v1",
            "event_hashes": evs,
            "parent_commitment": parent_commitment,
            "region": region,
        }))?);
        region_commitments.insert(rid.clone(), commit);
    }

    let mut wallet_commitments = BTreeMap::new();
    for (wid, wallet) in &state.wallets {
        let parent_commitment = if wallet.region_id.is_empty() && wallet.ghost {
            network_commitment.as_str()
        } else if wallet.region_id.is_empty() {
            return Err(VNetworkError::Validation(format!(
                "non-Ghost Wallet `{wid}` is missing its parent Region"
            )));
        } else {
            region_commitments
                .get(&wallet.region_id)
                .map(String::as_str)
                .ok_or_else(|| VNetworkError::Validation(format!(
                    "Wallet `{wid}` references missing parent Region `{}`",
                    wallet.region_id
                )))?
        };
        let evs = events_by_entity.get(wid.as_str()).cloned().unwrap_or_default();
        let commit = blake3_hex(&canonical_json_bytes(&serde_json::json!({
            "domain": "vnetwork/wallet-ledger-v1",
            "event_hashes": evs,
            "parent_commitment": parent_commitment,
            "wallet": wallet,
        }))?);
        wallet_commitments.insert(wid.clone(), commit);
    }

    let mut token_commitments = BTreeMap::new();
    for (tid, token) in &state.tokens {
        let parent_commitment = if token.wallet_id.is_empty() && token.ghost {
            network_commitment.as_str()
        } else if token.wallet_id.is_empty() {
            return Err(VNetworkError::Validation(format!(
                "non-Ghost Token `{tid}` is missing its parent Wallet"
            )));
        } else {
            wallet_commitments
                .get(&token.wallet_id)
                .map(String::as_str)
                .ok_or_else(|| VNetworkError::Validation(format!(
                    "Token `{tid}` references missing parent Wallet `{}`",
                    token.wallet_id
                )))?
        };
        let evs = events_by_entity.get(tid.as_str()).cloned().unwrap_or_default();
        let commit = blake3_hex(&canonical_json_bytes(&serde_json::json!({
            "domain": "vnetwork/token-ledger-v1",
            "event_hashes": evs,
            "parent_commitment": parent_commitment,
            "token": token,
        }))?);
        token_commitments.insert(tid.clone(), commit);
    }

    Ok(HierarchyCommitmentSummary {
        network_commitment,
        ghost_commitment,
        space_commitments,
        region_commitments,
        wallet_commitments,
        token_commitments,
    })
}

pub fn build_verified_ledger_proof_report(
    state: &NetworkLedgerState,
    genesis: Option<&GenesisConfig>,
) -> VResult<LedgerProofReport> {
    let chain_valid = verify_event_chain(&state.events)?;
    let state_root = state.compute_state_root()?;
    let replay_hash = state.compute_replay_hash();
    let event_history_root = state.compute_event_history_root();

    let mut token_conservation: Vec<TokenConservationSummary> = Vec::new();
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

    let hierarchy_commitments =
        compute_hierarchy_commitments(state, &state_root, &event_history_root)?;

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
        hierarchy_commitments,
    })
}

pub fn build_ledger_proof_report(state: &NetworkLedgerState) -> VResult<LedgerProofReport> {
    build_verified_ledger_proof_report(state, None)
}


#[cfg(test)]
mod hierarchy_commitment_regressions {
    use super::compute_hierarchy_commitments;
    use crate::state::{GenesisConfig, NetworkLedgerState};
    use std::collections::BTreeMap;
    use vnetwork_types::*;

    fn empty_state() -> NetworkLedgerState {
        let validator = KeypairMaterial::generate("hierarchy-commitment-test");
        let genesis = GenesisConfig::for_profile(
            NetworkProfile::Development,
            "hierarchy-commitment-regression",
            "Hierarchy commitment regression",
            vec![ConsensusValidator {
                validator_id: "validator-1".to_string(),
                node_id: "node-1".to_string(),
                validator_pubkey_hex: validator.public_key_hex.clone(),
                weight: 100,
                active: true,
                joined_epoch: 1,
            }],
        );
        NetworkLedgerState::try_new(&genesis).expect("valid genesis")
    }

    #[test]
    fn parentless_ghost_region_is_committed_to_network_root() {
        let mut state = empty_state();
        state.regions.insert("ghost-region".to_string(), RegionEntity {
            region_id: "ghost-region".to_string(),
            space_id: String::new(),
            name: "Ghost Region".to_string(),
            prefix: None,
            title: None,
            visibility: Visibility::Private,
            section: 0,
            ghost: true,
            auth_ratio_bps: 0,
            creator_pubkey: "test-owner".to_string(),
            created_at_ms: 1,
            version: 1,
            metadata: BTreeMap::new(),
        });
        let summary = compute_hierarchy_commitments(&state, "root", "events")
            .expect("parentless Ghost Region is a supported Network child");
        assert!(summary.region_commitments.contains_key("ghost-region"));
    }

    #[test]
    fn ordinary_region_with_missing_parent_is_rejected_not_attached_to_network() {
        let mut state = empty_state();
        state.regions.insert("orphan-region".to_string(), RegionEntity {
            region_id: "orphan-region".to_string(),
            space_id: "missing-space".to_string(),
            name: "Orphan Region".to_string(),
            prefix: None,
            title: None,
            visibility: Visibility::Private,
            section: 0,
            ghost: false,
            auth_ratio_bps: 0,
            creator_pubkey: "test-owner".to_string(),
            created_at_ms: 1,
            version: 1,
            metadata: BTreeMap::new(),
        });
        assert!(compute_hierarchy_commitments(&state, "root", "events").is_err());
    }

    #[test]
    fn ordinary_wallet_with_missing_parent_is_rejected() {
        let mut state = empty_state();
        state.wallets.insert("orphan-wallet".to_string(), WalletEntity {
            wallet_id: "orphan-wallet".to_string(),
            name: "Orphan Wallet".to_string(),
            region_id: "missing-region".to_string(),
            space_id: "missing-space".to_string(),
            ghost: false,
            owner_pubkey: "test-owner".to_string(),
            authorized_keys: BTreeMap::new(),
            approval_threshold: 1,
            receive_policy: WalletReceivePolicy::default(),
            created_at_ms: 1,
            version: 1,
        });
        assert!(compute_hierarchy_commitments(&state, "root", "events").is_err());
    }
}
