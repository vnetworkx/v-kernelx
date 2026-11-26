use vnetwork_consensus::{apply_verified_sync_batch, ValidatorMembership};
use vnetwork_core::engine::ProtocolEngine;
use vnetwork_storage::{CommittedProposalRecord, StorageDatabase};
use vnetwork_types::*;

/// Reconciles verified commits received from peers one height at a time,
/// persisting each commit to durable storage BEFORE advancing live engine state.
pub fn reconcile_sync_commits(
    engine: &mut ProtocolEngine,
    storage: &StorageDatabase,
    membership: &ValidatorMembership,
    commits: &[CommittedProposalRecord],
    timestamp_ms: u64,
) -> VResult<usize> {
    let mut ordered = commits.to_vec();
    ordered.sort_by_key(|r| r.proposal.height);
    let mut applied = 0usize;

    for rec in ordered {
        if rec.proposal.height <= engine.state.height {
            continue;
        }
        if rec.proposal.height != engine.state.height + 1 {
            return Err(VNetworkError::Consensus(format!(
                "non-contiguous sync commit height {} (expected {})",
                rec.proposal.height,
                engine.state.height + 1
            )));
        }
        let mut staged = engine.clone();
        let count = apply_verified_sync_batch(
            &mut staged,
            membership,
            &[(rec.proposal.clone(), rec.certificate.clone())],
            timestamp_ms,
        )?;
        if count == 0 {
            continue;
        }
        storage.persist_commit(&staged.state, &rec.proposal, &rec.certificate)?;
        *engine = staged;
        applied += count;
    }

    Ok(applied)
}
