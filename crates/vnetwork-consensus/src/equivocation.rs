use std::collections::BTreeMap;
use vnetwork_types::*;

#[derive(Debug, Default, Clone)]
pub struct EquivocationDetector {
    /// Keyed by (validator_id, height, round) -> first seen vote
    seen_votes: BTreeMap<(String, u64, u64), ConsensusVote>,
    pub evidence: Vec<EquivocationEvidence>,
}

impl EquivocationDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check_and_record(
        &mut self,
        vote: &ConsensusVote,
        timestamp_ms: u64,
    ) -> Result<(), EquivocationEvidence> {
        let key = (vote.validator_id.clone(), vote.height, vote.round);
        if let Some(prev) = self.seen_votes.get(&key) {
            if prev.proposal_id != vote.proposal_id || prev.post_state_root != vote.post_state_root {
                let ev = EquivocationEvidence {
                    validator_id: vote.validator_id.clone(),
                    height: vote.height,
                    round: vote.round,
                    vote_a: prev.clone(),
                    vote_b: vote.clone(),
                    detected_at_ms: timestamp_ms,
                };
                self.evidence.push(ev.clone());
                return Err(ev);
            }
        } else {
            self.seen_votes.insert(key, vote.clone());
        }
        Ok(())
    }
}
