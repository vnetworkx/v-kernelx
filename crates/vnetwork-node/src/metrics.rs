use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct NodeMetrics {
    pub proposals_proposed: AtomicU64,
    pub proposals_committed: AtomicU64,
    pub proposals_rejected: AtomicU64,
    pub votes_cast: AtomicU64,
    pub programs_submitted: AtomicU64,
    pub programs_failed: AtomicU64,
    pub sync_batches_applied: AtomicU64,
    pub api_requests_total: AtomicU64,
}

impl NodeMetrics {
    pub fn render_prometheus(
        &self,
        network_id: &str,
        node_id: &str,
        height: u64,
        committed_events: usize,
        connected_peers: usize,
        active_validators: usize,
    ) -> String {
        format!(
            "# HELP vnetwork_height Current finalized consensus height\n\
             # TYPE vnetwork_height gauge\n\
             vnetwork_height{{network_id=\"{network_id}\",node_id=\"{node_id}\"}} {height}\n\
             # HELP vnetwork_committed_events Total committed ledger events\n\
             # TYPE vnetwork_committed_events counter\n\
             vnetwork_committed_events{{network_id=\"{network_id}\",node_id=\"{node_id}\"}} {committed_events}\n\
             # HELP vnetwork_connected_peers Connected authenticated P2P peers\n\
             # TYPE vnetwork_connected_peers gauge\n\
             vnetwork_connected_peers{{network_id=\"{network_id}\",node_id=\"{node_id}\"}} {connected_peers}\n\
             # HELP vnetwork_active_validators Active validators in consensus set\n\
             # TYPE vnetwork_active_validators gauge\n\
             vnetwork_active_validators{{network_id=\"{network_id}\",node_id=\"{node_id}\"}} {active_validators}\n\
             # HELP vnetwork_proposals_committed Committed consensus proposals\n\
             # TYPE vnetwork_proposals_committed counter\n\
             vnetwork_proposals_committed{{network_id=\"{network_id}\",node_id=\"{node_id}\"}} {}\n\
             # HELP vnetwork_proposals_rejected Rejected or failed consensus proposals\n\
             # TYPE vnetwork_proposals_rejected counter\n\
             vnetwork_proposals_rejected{{network_id=\"{network_id}\",node_id=\"{node_id}\"}} {}\n\
             # HELP vnetwork_votes_cast Consensus votes signed by this validator\n\
             # TYPE vnetwork_votes_cast counter\n\
             vnetwork_votes_cast{{network_id=\"{network_id}\",node_id=\"{node_id}\"}} {}\n\
             # HELP vnetwork_programs_submitted Total Vector Language programs submitted\n\
             # TYPE vnetwork_programs_submitted counter\n\
             vnetwork_programs_submitted{{network_id=\"{network_id}\",node_id=\"{node_id}\"}} {}\n",
            self.proposals_committed.load(Ordering::Relaxed),
            self.proposals_rejected.load(Ordering::Relaxed),
            self.votes_cast.load(Ordering::Relaxed),
            self.programs_submitted.load(Ordering::Relaxed),
        )
    }
}
