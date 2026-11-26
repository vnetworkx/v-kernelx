use crate::events::EventWal;
use crate::indexes::persist_entity_index;
use crate::snapshots::{load_certified_checkpoint, save_certified_checkpoint_from_state};
use crate::transactions::{
    save_transactions_and_programs, CommittedCommitMarker, CommittedProposalRecord, ConsensusWal,
    PendingCommitRecord,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use vnetwork_core::consensus_gate::{
    commit_verified_proposal, replay_validator_epoch_history, verify_membership_chain_from_genesis,
    verify_quorum_certificate_strict,
};
use vnetwork_core::events::verify_event_chain;
use vnetwork_core::state::{GenesisConfig, NetworkLedgerState};
use vnetwork_types::*;

#[derive(Debug, Clone)]
pub struct RecoveryReport {
    pub recovered_from_snapshot: bool,
    pub rolled_back_uncommitted: usize,
    pub wal_events_verified: usize,
    pub proposals_replayed: usize,
    pub final_height: u64,
    pub state_root: String,
    pub wal_consistency_ok: bool,
    pub quarantined_artifacts: Vec<String>,
}

fn wal_tx_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("wal_tx")
}

pub fn pending_tx_path(data_dir: &Path, height: u64) -> PathBuf {
    wal_tx_dir(data_dir).join(format!("tx_{height:012}_pending.json"))
}

pub fn committed_tx_path(data_dir: &Path, height: u64) -> PathBuf {
    wal_tx_dir(data_dir).join(format!("tx_{height:012}_committed.marker"))
}

fn quarantine_artifact(data_dir: &Path, path: &Path, tag: &str) -> VResult<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let qdir = data_dir.join("forensic_quarantine");
    fs::create_dir_all(&qdir).map_err(|e| {
        VNetworkError::Storage(format!("create forensic_quarantine failed: {e}"))
    })?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("artifact");
    let dest = qdir.join(format!("{}_{}_{}", now_ms(), tag, name));
    fs::rename(path, &dest).map_err(|e| {
        VNetworkError::Storage(format!(
            "failed quarantining forensic artifact {:?} -> {:?}: {e}",
            path, dest
        ))
    })?;
    Ok(Some(dest.display().to_string()))
}

pub fn verify_wal_exact_alignment(
    committed_proposals: &[CommittedProposalRecord],
    wal_events: &[LedgerEvent],
    expected_genesis: &GenesisConfig,
) -> VResult<()> {
    expected_genesis.validate()?;
    let expected_genesis_commitment = expected_genesis.commitment_hash()?;
    let expected_params_hash = expected_genesis.consensus_parameters.parameters_hash()?;
    let genesis_state_root = NetworkLedgerState::try_new(expected_genesis)?.compute_state_root()?;
    verify_event_chain(wal_events)?;

    let mut expected_height = 1u64;
    let mut expected_parent = expected_genesis_commitment.clone();
    let mut expected_pre_root = genesis_state_root;
    let mut seen_heights = BTreeSet::new();
    let mut expected_events: Vec<&LedgerEvent> = Vec::new();
    for rec in committed_proposals {
        if !seen_heights.insert(rec.proposal.height) {
            return Err(VNetworkError::Storage(format!(
                "duplicate consensus WAL height {}",
                rec.proposal.height
            )));
        }
        if rec.proposal.height != expected_height {
            return Err(VNetworkError::Storage(format!(
                "consensus WAL height continuity gap: expected height {expected_height}, got {}",
                rec.proposal.height
            )));
        }
        expected_height = expected_height
            .checked_add(1)
            .ok_or_else(|| VNetworkError::Storage("consensus WAL height overflow".to_string()))?;

        rec.proposal.verify_digest_and_metadata()?;
        rec.certificate.verify_certificate_id()?;
        if rec.proposal.network_id != expected_genesis.network_id
            || rec.proposal.genesis_commitment != expected_genesis_commitment
            || rec.proposal.protocol_version != expected_genesis.protocol_version
            || rec.certificate.network_id != expected_genesis.network_id
            || rec.certificate.genesis_commitment != expected_genesis_commitment
            || rec.certificate.protocol_version != expected_genesis.protocol_version
        {
            return Err(VNetworkError::ProfileMismatch(format!(
                "consensus WAL entry at height {} diverges from genesis metadata",
                rec.proposal.height
            )));
        }
        if rec.proposal.consensus_parameters_hash != expected_params_hash
            || rec.certificate.consensus_parameters_hash != expected_params_hash
            || rec.certificate.quorum_threshold_bps
                != expected_genesis.consensus_parameters.quorum_threshold_bps
        {
            return Err(VNetworkError::Consensus(format!(
                "consensus WAL entry at height {} diverges from genesis consensus policy",
                rec.proposal.height
            )));
        }
        if rec.proposal.parent_commitment != expected_parent {
            return Err(VNetworkError::Storage(format!(
                "consensus WAL parent_commitment break at height {}: expected `{expected_parent}`, got `{}`",
                rec.proposal.height, rec.proposal.parent_commitment
            )));
        }
        if rec.proposal.pre_state_root != expected_pre_root {
            return Err(VNetworkError::Storage(format!(
                "consensus WAL pre_state_root break at height {}: expected `{expected_pre_root}`, got `{}`",
                rec.proposal.height, rec.proposal.pre_state_root
            )));
        }
        if rec.certificate.proposal_id != rec.proposal.proposal_id
            || rec.certificate.proposal_digest != rec.proposal.proposal_digest
            || rec.certificate.height != rec.proposal.height
            || rec.certificate.round != rec.proposal.round
            || rec.certificate.epoch != rec.proposal.epoch
            || rec.certificate.validator_set_hash != rec.proposal.validator_set_hash
            || rec.certificate.parent_commitment != rec.proposal.parent_commitment
            || rec.certificate.pre_state_root != rec.proposal.pre_state_root
            || rec.certificate.ordered_event_ids != rec.proposal.ordered_event_ids()
            || rec.certificate.event_hashes != rec.proposal.ordered_event_hashes()
            || rec.certificate.post_state_root != rec.proposal.post_state_root
            || rec.certificate.operation_scope != rec.proposal.operation_scope
        {
            return Err(VNetworkError::Storage(format!(
                "consensus WAL certificate/proposal commitment mismatch at height {}",
                rec.proposal.height
            )));
        }
        expected_parent = rec.proposal.proposal_digest.clone();
        expected_pre_root = rec.proposal.post_state_root.clone();
        for ev in &rec.proposal.events {
            expected_events.push(ev);
        }
    }

    if wal_events.len() != expected_events.len() {
        return Err(VNetworkError::Storage(format!(
            "strict WAL divergence: events.wal has {} events vs {} certified events in consensus_commits.wal",
            wal_events.len(),
            expected_events.len()
        )));
    }

    for (idx, (wal_ev, cert_ev)) in wal_events.iter().zip(expected_events.iter()).enumerate() {
        if wal_ev.event_id != cert_ev.event_id
            || wal_ev.event_hash != cert_ev.event_hash
            || wal_ev.prev_event_hash != cert_ev.prev_event_hash
            || wal_ev.sequence != cert_ev.sequence
            || wal_ev.payload_hash != cert_ev.payload_hash
        {
            return Err(VNetworkError::Storage(format!(
                "strict WAL divergence at event index {idx}: events.wal `{}` ({}) != certified event `{}` ({})",
                wal_ev.event_id, wal_ev.event_hash, cert_ev.event_id, cert_ev.event_hash
            )));
        }
    }

    Ok(())
}

pub fn recover_state_from_disk(
    data_dir: &Path,
    expected_genesis: &GenesisConfig,
) -> VResult<(NetworkLedgerState, RecoveryReport)> {
    expected_genesis.validate()?;
    let expected_genesis_hash = expected_genesis.commitment_hash()?;

    let genesis_path = data_dir.join("genesis.json");
    if genesis_path.exists() {
        let raw = fs::read_to_string(&genesis_path)
            .map_err(|e| VNetworkError::Storage(e.to_string()))?;
        let stored: GenesisConfig =
            serde_json::from_str(&raw).map_err(|e| VNetworkError::Storage(e.to_string()))?;
        let stored_hash = stored.commitment_hash()?;
        if stored_hash != expected_genesis_hash {
            return Err(VNetworkError::ProfileMismatch(format!(
                "persisted storage genesis commitment `{stored_hash}` ({}, {}) != node genesis `{expected_genesis_hash}` ({}, {})",
                stored.network_id,
                stored.profile.as_str(),
                expected_genesis.network_id,
                expected_genesis.profile.as_str()
            )));
        }
    }

    // 1. Inspect incomplete WAL transactions before trusting checkpoints or WAL tails
    let tx_dir = wal_tx_dir(data_dir);
    let mut rolled_back_uncommitted = 0usize;
    let mut invalidated_min_height: Option<u64> = None;
    let mut rollback_event_limit: Option<usize> = None;
    let mut quarantined_artifacts = Vec::new();
    let mut committed_pending_records: BTreeMap<u64, PendingCommitRecord> = BTreeMap::new();

    if tx_dir.exists() {
        let mut pending_files = Vec::new();
        for entry in fs::read_dir(&tx_dir).map_err(|e| VNetworkError::Storage(e.to_string()))? {
            let path = entry.map_err(|e| VNetworkError::Storage(e.to_string()))?.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.ends_with("_pending.json") {
                    pending_files.push(path);
                }
            }
        }
        pending_files.sort();
        for p_path in pending_files {
            let raw = fs::read_to_string(&p_path)
                .map_err(|e| VNetworkError::Storage(format!("read pending tx {:?}: {e}", p_path)))?;
            let pending: PendingCommitRecord = serde_json::from_str(&raw)
                .map_err(|e| VNetworkError::Storage(format!("parse pending tx {:?}: {e}", p_path)))?;
            let expected_path = pending_tx_path(data_dir, pending.height);
            if p_path != expected_path {
                return Err(VNetworkError::Storage(format!(
                    "pending tx path {:?} does not match recorded height {}",
                    p_path, pending.height
                )));
            }
            if committed_pending_records.contains_key(&pending.height) {
                return Err(VNetworkError::Storage(format!(
                    "duplicate pending commit marker for height {}",
                    pending.height
                )));
            }
            let c_path = committed_tx_path(data_dir, pending.height);
            if !c_path.exists() {
                rolled_back_uncommitted += 1;
                invalidated_min_height = Some(
                    invalidated_min_height
                        .map_or(pending.height, |m| m.min(pending.height)),
                );
                rollback_event_limit = Some(
                    rollback_event_limit
                        .map_or(pending.prior_event_count, |m| m.min(pending.prior_event_count)),
                );
                if let Some(q) = quarantine_artifact(data_dir, &p_path, "uncommitted_pending")? {
                    quarantined_artifacts.push(q);
                }
            } else {
                committed_pending_records.insert(pending.height, pending);
            }
        }
    }

    let (mut committed_proposals, mut commit_quarantined) =
        ConsensusWal::new(data_dir).read_all_with_trailing_recovery(data_dir)?;
    quarantined_artifacts.append(&mut commit_quarantined);
    let (mut wal_events, mut event_quarantined) =
        EventWal::new(data_dir).read_all_with_trailing_recovery(data_dir)?;
    quarantined_artifacts.append(&mut event_quarantined);

    if let Some(min_h) = invalidated_min_height {
        let orig_commits = committed_proposals.len();
        committed_proposals.retain(|c| c.proposal.height < min_h);
        if committed_proposals.len() != orig_commits {
            if let Some(q) = quarantine_artifact(
                data_dir,
                &data_dir.join("consensus_commits.wal.bak"),
                "pre_rollback",
            )? {
                quarantined_artifacts.push(q);
            }
            ConsensusWal::new(data_dir).rewrite_all(&committed_proposals)?;
        }
        if let Some(limit) = rollback_event_limit {
            if wal_events.len() > limit {
                wal_events.truncate(limit);
                EventWal::new(data_dir).rewrite_all(&wal_events)?;
            }
        }
    }

    // 2. Strict per-event WAL <-> certified QuorumCertificate alignment
    verify_wal_exact_alignment(&committed_proposals, &wal_events, expected_genesis)?;

    if tx_dir.exists() {
        let mut seen_marker_heights = BTreeSet::new();
        for entry in fs::read_dir(&tx_dir).map_err(|e| VNetworkError::Storage(e.to_string()))? {
            let path = entry.map_err(|e| VNetworkError::Storage(e.to_string()))?.path();
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .map_or(false, |s| s.ends_with("_committed.marker"))
            {
                let raw = fs::read_to_string(&path)
                    .map_err(|e| VNetworkError::Storage(e.to_string()))?;
                let marker: CommittedCommitMarker = serde_json::from_str(&raw)
                    .map_err(|e| VNetworkError::Storage(format!("corrupt committed marker: {e}")))?;
                if path != committed_tx_path(data_dir, marker.height) {
                    return Err(VNetworkError::Storage(format!(
                        "committed marker path {:?} does not match height {}",
                        path, marker.height
                    )));
                }
                if !seen_marker_heights.insert(marker.height) {
                    return Err(VNetworkError::Storage(format!(
                        "duplicate committed marker for height {}",
                        marker.height
                    )));
                }
                if marker.event_count > wal_events.len() {
                    return Err(VNetworkError::Storage(format!(
                        "committed marker event_count {} exceeds events.wal length {}",
                        marker.event_count,
                        wal_events.len()
                    )));
                }
                if let Some(pending) = committed_pending_records.get(&marker.height) {
                    if pending.proposal_id != marker.proposal_id
                        || (!pending.proposal_digest.is_empty()
                            && !marker.proposal_digest.is_empty()
                            && pending.proposal_digest != marker.proposal_digest)
                        || pending.certificate_id != marker.certificate_id
                        || pending.post_state_root != marker.post_state_root
                        || pending.event_count != marker.event_count
                    {
                        return Err(VNetworkError::Storage(format!(
                            "pending/committed WAL markers disagree at height {}",
                            marker.height
                        )));
                    }
                }
                let found = committed_proposals.iter().any(|c| {
                    c.proposal.height == marker.height
                        && c.proposal.proposal_id == marker.proposal_id
                        && (marker.proposal_digest.is_empty()
                            || c.proposal.proposal_digest == marker.proposal_digest)
                        && c.certificate.certificate_id == marker.certificate_id
                        && c.certificate.post_state_root == marker.post_state_root
                });
                if !found {
                    return Err(VNetworkError::Storage(format!(
                        "committed marker at height {} lacks matching consensus WAL entry",
                        marker.height
                    )));
                }
            }
        }
    }

    // 3. Verify CertifiedCheckpoint (never accept raw uncertified state.snapshot.json)
    let cert_ckpt = load_certified_checkpoint(data_dir, expected_genesis)?;
    let (mut state, recovered_from_snapshot) = match cert_ckpt {
        Some(ckpt) => {
            if invalidated_min_height.map_or(false, |min_h| ckpt.height >= min_h) {
                if let Some(q) = quarantine_artifact(
                    data_dir,
                    &data_dir.join(crate::snapshots::CERTIFIED_CHECKPOINT_FILE),
                    "rolled_back_ckpt",
                )? {
                    quarantined_artifacts.push(q);
                }
                (NetworkLedgerState::try_new(expected_genesis)?, false)
            } else {
                let matching_commit = committed_proposals
                    .iter()
                    .find(|c| c.proposal.height == ckpt.height)
                    .ok_or_else(|| {
                        VNetworkError::Storage(format!(
                            "certified checkpoint at height {} has no matching commit in consensus_commits.wal",
                            ckpt.height
                        ))
                    })?;
                if matching_commit.proposal.proposal_digest != ckpt.proposal_digest
                    || matching_commit.certificate.certificate_id
                        != ckpt.quorum_certificate.certificate_id
                    || matching_commit.proposal.post_state_root != ckpt.state_root
                {
                    return Err(VNetworkError::Storage(format!(
                        "certified checkpoint at height {} diverges from consensus_commits.wal",
                        ckpt.height
                    )));
                }
                (ckpt.state, true)
            }
        }
        None => (NetworkLedgerState::try_new(expected_genesis)?, false),
    };

    // 4. Verify cryptographic QCs and proposer signatures on ALL commits at or below checkpoint height
    if recovered_from_snapshot && state.height > 0 {
        let genesis_ctx = expected_genesis.consensus_context()?;
        let (_, _, epoch_validators) = replay_validator_epoch_history(
            &expected_genesis.initial_validators,
            expected_genesis.genesis_epoch,
            &genesis_ctx,
            &state.validator_membership_history,
        )?;
        for rec in committed_proposals
            .iter()
            .filter(|c| c.proposal.height <= state.height)
        {
            let vals = epoch_validators.get(&rec.proposal.epoch).ok_or_else(|| {
                VNetworkError::Consensus(format!(
                    "historical commit at height {} references unproven validator epoch {}",
                    rec.proposal.height, rec.proposal.epoch
                ))
            })?;
            let epoch_ctx = expected_genesis.consensus_context_for_epoch(rec.proposal.epoch)?;
            verify_quorum_certificate_strict(&rec.certificate, vals, &epoch_ctx)?;
            let proposer = vals
                .iter()
                .find(|v| {
                    v.active && v.weight > 0 && v.validator_id == rec.proposal.proposer_validator_id
                })
                .ok_or_else(|| {
                    VNetworkError::Consensus(format!(
                        "historical commit at height {} has ineligible proposer `{}`",
                        rec.proposal.height, rec.proposal.proposer_validator_id
                    ))
                })?;
            rec.proposal.verify_proposer_signature(proposer)?;
        }
    }

    // 5. Replay all certified commits strictly above current verified checkpoint height
    let mut proposals_replayed = 0usize;
    for rec in &committed_proposals {
        if rec.proposal.height > state.height {
            let vset_hash = validate_validator_set(&state.validators)?;
            let ctx = expected_genesis.consensus_context_for_epoch(state.validator_epoch)?;
            let proven_validators = verify_membership_chain_from_genesis(
                &expected_genesis.initial_validators,
                expected_genesis.genesis_epoch,
                &ctx,
                &state.validator_membership_history,
                state.validator_epoch,
                &vset_hash,
                &state.validators,
            )?;
            commit_verified_proposal(&mut state, &rec.proposal, &rec.certificate, &proven_validators)?;
            proposals_replayed += 1;
        }
    }

    if let Some(last) = committed_proposals.last() {
        let final_root = state.compute_state_root()?;
        if state.height != last.proposal.height || final_root != last.proposal.post_state_root {
            return Err(VNetworkError::Storage(format!(
                "recovered state root `{final_root}` at height {} != last certified root `{}` at height {}",
                state.height, last.proposal.post_state_root, last.proposal.height
            )));
        }
        if proposals_replayed > 0 || rolled_back_uncommitted > 0 {
            save_certified_checkpoint_from_state(
                data_dir,
                &state,
                &last.certificate,
                &last.proposal.proposal_digest,
                &last.proposal.parent_commitment,
                last.certificate.finalized_at_ms,
            )?;
        }
    }

    // Verify recovered state events match verified WAL events identically
    if state.events.len() != wal_events.len()
        || state
            .events
            .iter()
            .zip(wal_events.iter())
            .any(|(a, b)| a.event_id != b.event_id || a.event_hash != b.event_hash)
    {
        return Err(VNetworkError::Storage(
            "recovered state event history diverges from certified events.wal".to_string(),
        ));
    }

    if rolled_back_uncommitted > 0 || proposals_replayed > 0 {
        save_transactions_and_programs(data_dir, &state.programs, &state.transactions)?;
        persist_entity_index(data_dir, &state)?;
    }

    if tx_dir.exists() {
        for entry in fs::read_dir(&tx_dir).map_err(|e| VNetworkError::Storage(e.to_string()))? {
            let path = entry.map_err(|e| VNetworkError::Storage(e.to_string()))?.path();
            if path.is_file() {
                fs::remove_file(&path).map_err(|e| {
                    VNetworkError::Storage(format!("remove processed wal_tx marker {:?}: {e}", path))
                })?;
            }
        }
    }

    let root = state.compute_state_root()?;
    let report = RecoveryReport {
        recovered_from_snapshot,
        rolled_back_uncommitted,
        wal_events_verified: state.events.len(),
        proposals_replayed,
        final_height: state.height,
        state_root: root,
        wal_consistency_ok: true,
        quarantined_artifacts,
    };

    Ok((state, report))
}
