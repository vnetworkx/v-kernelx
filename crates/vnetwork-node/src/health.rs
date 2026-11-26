use serde::{Deserialize, Serialize};
use vnetwork_types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHealthReport {
    pub healthy: bool,
    pub ready: bool,
    pub node_id: String,
    pub peer_id: String,
    pub network_id: String,
    pub profile: NetworkProfile,
    pub node_kind: NodeKind,
    pub height: u64,
    pub state_root: String,
    pub connected_peers: usize,
    pub validator_active: bool,
    pub storage_ok: bool,
    pub api_enabled: bool,
    pub p2p_enabled: bool,
    pub protocol_version: String,
}
