use crate::equivocation::EquivocationDetector;
use crate::membership::ValidatorMembership;
use crate::vote::verify_consensus_vote;
use std::collections::BTreeMap;
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

impl QuorumTracker {
    pub fn new() -> Self {
        Self {
            proposals: BTreeMap::new(),
            orphan_votes: BTreeMap::new(),
            equivocation: EquivocationDetector::new(),
        }
    }

    pub fn register_proposal(&mut self, proposal: ConsensusProposal) {
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
                    if v.height == collector.proposal.height
                        && v.post_state_root == collector.proposal.post_state_root
                    {
                        collector.votes.insert(v.validator_id.clone(), v);
                    }
                }
            }
        }
    }

    pub fn record_vote(
        &mut self,
        membership: &ValidatorMembership,
        vote: ConsensusVote,
        timestamp_ms: u64,
    ) -> VResult<Option<QuorumCertificate>> {
        let _validator = verify_consensus_vote(membership, &vote)?;
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

        if vote.height != collector.proposal.height
            || vote.post_state_root != collector.proposal.post_state_root
        {
            return Err(VNetworkError::Consensus(
                "vote metadata does not match proposal".to_string(),
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

        let total_weight = membership.total_active_weight();
        if total_weight == 0 {
            return Ok(None);
        }

        let mut approving_weight: u64 = 0;
        let mut approving_votes = Vec::new();
        for vote in collector.votes.values() {
            if vote.approve {
                if let Some(val) = membership.get(&vote.validator_id) {
                    if val.active {
                        approving_weight = approving_weight.saturating_add(val.weight);
                        approving_votes.push(vote.clone());
                    }
                }
            }
        }

        let bps = membership.quorum_threshold_bps();
        if (approving_weight as u128) * 10_000 < (total_weight as u128) * (bps as u128) {
            return Ok(None);
        }

        let event_hashes: Vec<String> = collector
            .proposal
            .events
            .iter()
            .map(|e| e.event_hash.clone())
            .collect();
        let cert_seed = format!(
            "{}:{}:{}",
            collector.proposal.proposal_id, collector.proposal.height, collector.proposal.post_state_root
        );
        let certificate_id = format!("qc_{}", &blake3_hex(cert_seed.as_bytes())[..20]);

        Ok(Some(QuorumCertificate {
            certificate_id,
            proposal_id: collector.proposal.proposal_id.clone(),
            network_id: collector.proposal.network_id.clone(),
            height: collector.proposal.height,
            round: collector.proposal.round,
            epoch: collector.proposal.epoch,
            post_state_root: collector.proposal.post_state_root.clone(),
            event_hashes,
            total_weight,
            approving_weight,
            quorum_threshold_bps: bps,
            votes: approving_votes,
            finalized_at_ms: timestamp_ms,
        }))
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
