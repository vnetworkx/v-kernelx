use crate::equivocation::{EquivocationDetector, EquivocationStore};
use crate::membership::ValidatorMembership;
use crate::vote::verify_consensus_vote;
use std::collections::{BTreeMap, BTreeSet};
use vnetwork_types::*;

#[derive(Debug, Clone)]
pub struct ProposalVoteCollector {
    pub proposal: ConsensusProposal,
    pub votes: BTreeMap<String, ConsensusVote>,
}

#[derive(Debug, Clone)]
pub struct QuorumTracker {
    proposals: BTreeMap<String, ProposalVoteCollector>,
    orphan_votes: BTreeMap<String, Vec<ConsensusVote>>,
    equivocation: EquivocationDetector,
}

impl Default for QuorumTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn vote_matches_proposal(vote: &ConsensusVote, prop: &ConsensusProposal) -> bool {
    vote.proposal_id == prop.proposal_id
        && vote.proposal_digest == prop.proposal_digest
        && vote.network_id == prop.network_id
        && vote.genesis_commitment == prop.genesis_commitment
        && vote.protocol_version == prop.protocol_version
        && vote.height == prop.height
        && vote.round == prop.round
        && vote.epoch == prop.epoch
        && vote.validator_set_hash == prop.validator_set_hash
        && vote.parent_commitment == prop.parent_commitment
        && vote.pre_state_root == prop.pre_state_root
        && vote.post_state_root == prop.post_state_root
        && vote.operation_scope == prop.operation_scope
}

impl QuorumTracker {
    pub fn new() -> Self {
        Self {
            proposals: BTreeMap::new(),
            orphan_votes: BTreeMap::new(),
            equivocation: EquivocationDetector::new(),
        }
    }

    pub fn register_proposal(&mut self, proposal: ConsensusProposal) -> VResult<()> {
        proposal.verify_digest_and_metadata()?;
        let pid = proposal.proposal_id.clone();
        self.proposals
            .entry(pid.clone())
            .or_insert(ProposalVoteCollector {
                proposal,
                votes: BTreeMap::new(),
            });
        if let Some(buffered) = self.orphan_votes.remove(&pid) {
            if let Some(collector) = self.proposals.get_mut(&pid) {
                for v in buffered {
                    if vote_matches_proposal(&v, &collector.proposal) {
                        collector.votes.insert(v.validator_id.clone(), v);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn record_vote(
        &mut self,
        membership: &ValidatorMembership,
        vote: ConsensusVote,
        timestamp_ms: u64,
    ) -> VResult<Option<QuorumCertificate>> {
        self.record_vote_with_store(membership, vote, None, timestamp_ms)
    }

    pub fn record_vote_with_store(
        &mut self,
        membership: &ValidatorMembership,
        vote: ConsensusVote,
        durable_store: Option<&mut EquivocationStore>,
        timestamp_ms: u64,
    ) -> VResult<Option<QuorumCertificate>> {
        let _validator = verify_consensus_vote(membership, &vote)?;
        if let Some(store) = durable_store {
            store.record_observed_vote(&vote, timestamp_ms)?;
        }
        if let Err(ev) = self.equivocation.check_and_record(&vote, timestamp_ms) {
            return Err(VNetworkError::Consensus(format!(
                "equivocation detected from validator `{}` at height {}",
                ev.validator_id, ev.height
            )));
        }

        let Some(collector) = self.proposals.get_mut(&vote.proposal_id) else {
            self.orphan_votes
                .entry(vote.proposal_id.clone())
                .or_default()
                .push(vote);
            return Ok(None);
        };

        if !vote_matches_proposal(&vote, &collector.proposal) {
            return Err(VNetworkError::Consensus(
                "vote commitments do not match proposal commitments".to_string(),
            ));
        }

        collector
            .votes
            .insert(vote.validator_id.clone(), vote.clone());

        self.try_build_certificate(membership, &vote.proposal_id, timestamp_ms)
    }

    pub fn try_build_certificate(
        &self,
        membership: &ValidatorMembership,
        proposal_id: &str,
        timestamp_ms: u64,
    ) -> VResult<Option<QuorumCertificate>> {
        let collector = self
            .proposals
            .get(proposal_id)
            .ok_or_else(|| VNetworkError::NotFound(format!("proposal `{proposal_id}`")))?;

        collector.proposal.verify_digest_and_metadata()?;

        let validator_set_hash = membership.validator_set_hash()?;
        if collector.proposal.validator_set_hash != validator_set_hash {
            return Err(VNetworkError::Consensus(format!(
                "proposal validator_set_hash `{}` != membership `{validator_set_hash}`",
                collector.proposal.validator_set_hash
            )));
        }

        let total_weight = membership.total_active_weight();
        if total_weight == 0 {
            return Ok(None);
        }

        let mut approving_weight: u64 = 0;
        let mut approving_votes = Vec::new();
        let mut seen_pubkeys: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut vote_phase: Option<VotePhase> = None;

        for vote in collector.votes.values() {
            if !vote.approve || !vote_matches_proposal(vote, &collector.proposal) {
                continue;
            }
            if let Some(phase) = vote_phase {
                if vote.vote_phase != phase {
                    continue;
                }
            } else {
                vote_phase = Some(vote.vote_phase);
            }
            if let Some(val) = membership.get(&vote.validator_id) {
                if val.active && val.weight > 0 {
                    let pk = canonical_ed25519_pubkey_bytes(&vote.validator_pubkey_hex)?;
                    if !seen_pubkeys.insert(pk) {
                        return Err(VNetworkError::Consensus(format!(
                            "duplicate public key across votes for proposal `{proposal_id}`"
                        )));
                    }
                    approving_weight = approving_weight.checked_add(val.weight).ok_or_else(|| {
                        VNetworkError::Consensus("approving quorum weight overflow".to_string())
                    })?;
                    approving_votes.push(vote.clone());
                }
            }
        }

        let bps = membership.quorum_threshold_bps();
        if bps < DEFAULT_BFT_QUORUM_BPS || bps > 10_000 {
            return Err(VNetworkError::Consensus(format!(
                "invalid quorum_threshold_bps `{bps}`"
            )));
        }
        if (approving_weight as u128) * 10_000 < (total_weight as u128) * (bps as u128) {
            return Ok(None);
        }

        let ordered_event_ids = collector.proposal.ordered_event_ids();
        let event_hashes = collector.proposal.ordered_event_hashes();

        let mut qc = QuorumCertificate {
            certificate_id: String::new(),
            proposal_id: collector.proposal.proposal_id.clone(),
            proposal_digest: collector.proposal.proposal_digest.clone(),
            network_id: collector.proposal.network_id.clone(),
            genesis_commitment: collector.proposal.genesis_commitment.clone(),
            protocol_version: collector.proposal.protocol_version.clone(),
            height: collector.proposal.height,
            round: collector.proposal.round,
            epoch: collector.proposal.epoch,
            validator_set_hash,
            parent_commitment: collector.proposal.parent_commitment.clone(),
            pre_state_root: collector.proposal.pre_state_root.clone(),
            post_state_root: collector.proposal.post_state_root.clone(),
            operation_scope: collector.proposal.operation_scope.clone(),
            vote_phase: vote_phase.unwrap_or(VotePhase::Commit),
            ordered_event_ids,
            event_hashes,
            total_weight,
            approving_weight,
            quorum_threshold_bps: bps,
            votes: approving_votes,
            finalized_at_ms: timestamp_ms,
        };
        let qc_digest = qc.certificate_digest()?;
        qc.certificate_id = format!("qc_{}_{}", qc.height, &qc_digest[..32]);
        Ok(Some(qc))
    }

    pub fn equivocations(&self) -> &[EquivocationEvidence] {
        &self.equivocation.evidence
    }

    pub fn vote_count(&self, proposal_id: &str) -> usize {
        self.proposals
            .get(proposal_id)
            .map(|c| c.votes.len())
            .unwrap_or(0)
    }
}
