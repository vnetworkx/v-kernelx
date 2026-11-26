use vnetwork_consensus::{apply_verified_sync_batch, ValidatorMembership};
use vnetwork_core::engine::ProtocolEngine;
use vnetwork_storage::{CommittedProposalRecord, StorageDatabase};
use vnetwork_types::*;

pub fn reconcile_sync_commits(
    engine: &mut ProtocolEngine,
    storage: &StorageDatabase,
    membership: &ValidatorMembership,
    commits: &[CommittedProposalRecord],
    timestamp_ms: u64,
) -> VResult<usize> {
    let mut ordered = commits.to_vec();
    ordered.sort_by_key(|r| r.proposal.height);
    let pairs: Vec<(ConsensusProposal, QuorumCertificate)> = ordered
        .iter()
        .map(|r| (r.proposal.clone(), r.certificate.clone()))
        .collect();
    let before_height = engine.state.height;
    let applied = apply_verified_sync_batch(engine, membership, &pairs, timestamp_ms)?;
    if applied > 0 {
        let mut last_persisted = before_height;
        for rec in ordered {
            if rec.proposal.height > last_persisted && rec.proposal.height <= engine.state.height {
                storage.persist_commit(&engine.state, &rec.proposal, &rec.certificate)?;
                last_persisted = rec.proposal.height;
            }
        }
    }
    Ok(applied)
}
