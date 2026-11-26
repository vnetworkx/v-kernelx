use serde::{Deserialize, Serialize};
use vnetwork_storage::CommittedProposalRecord;
use vnetwork_types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2pGossipMessage {
    Proposal(ConsensusProposal),
    Vote(ConsensusVote),
    Certificate {
        proposal_id: String,
        certificate: QuorumCertificate,
    },
    Heartbeat {
        node_id: String,
        height: u64,
        state_root: String,
        timestamp_ms: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2pSyncRequest {
    GetMissingCommits {
        network_id: String,
        from_height: u64,
    },
    RelayProposal(ConsensusProposal),
    RelayVote(ConsensusVote),
    RelayCertificate {
        proposal_id: String,
        certificate: QuorumCertificate,
    },
    RelayProgramSubmission {
        request_json: serde_json::Value,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2pSyncResponse {
    Commits {
        network_id: String,
        head_height: u64,
        commits: Vec<CommittedProposalRecord>,
    },
    Ack {
        accepted: bool,
        message: String,
    },
    ProgramForwardResult {
        ok: bool,
        response: serde_json::Value,
    },
}
