use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use vnetwork_types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectedPeerInfo {
    pub peer_id: String,
    pub node_id: Option<String>,
    pub addresses: Vec<String>,
    pub sync_height: u64,
    pub agent_version: String,
    pub connected: bool,
    pub last_seen_ms: u64,
}

#[derive(Debug, Default, Clone)]
pub struct PeerRegistry {
    pub peers: BTreeMap<String, ConnectedPeerInfo>,
}

impl PeerRegistry {
    pub fn upsert_connected(&mut self, peer_id: String, addr: Option<String>, timestamp_ms: u64) {
        let entry = self.peers.entry(peer_id.clone()).or_insert(ConnectedPeerInfo {
            peer_id,
            node_id: None,
            addresses: Vec::new(),
            sync_height: 0,
            agent_version: String::new(),
            connected: true,
            last_seen_ms: timestamp_ms,
        });
        entry.connected = true;
        entry.last_seen_ms = timestamp_ms;
        if let Some(a) = addr {
            if !entry.addresses.contains(&a) {
                entry.addresses.push(a);
            }
        }
    }

    pub fn mark_disconnected(&mut self, peer_id: &str, timestamp_ms: u64) {
        if let Some(p) = self.peers.get_mut(peer_id) {
            p.connected = false;
            p.last_seen_ms = timestamp_ms;
        }
    }

    pub fn update_identify(
        &mut self,
        peer_id: &str,
        node_id: Option<String>,
        agent_version: String,
        listen_addrs: Vec<String>,
        timestamp_ms: u64,
    ) {
        let entry = self
            .peers
            .entry(peer_id.to_string())
            .or_insert(ConnectedPeerInfo {
                peer_id: peer_id.to_string(),
                node_id: node_id.clone(),
                addresses: Vec::new(),
                sync_height: 0,
                agent_version: agent_version.clone(),
                connected: true,
                last_seen_ms: timestamp_ms,
            });
        entry.node_id = node_id.or_else(|| entry.node_id.clone());
        entry.agent_version = agent_version;
        entry.last_seen_ms = timestamp_ms;
        for a in listen_addrs {
            if !entry.addresses.contains(&a) {
                entry.addresses.push(a);
            }
        }
    }

    pub fn connected_count(&self) -> usize {
        self.peers.values().filter(|p| p.connected).count()
    }

    pub fn parse_agent_header(network_id: &str, node_id: &str, height: u64) -> String {
        format!("vnetwork|{}|{}|{}|{}", network_id, PROTOCOL_VERSION, node_id, height)
    }

    pub fn check_agent_compatible(expected_network: &str, agent: &str) -> Result<(String, u64), String> {
        let parts: Vec<&str> = agent.split('|').collect();
        if parts.len() < 5 || parts[0] != "vnetwork" {
            return Err("unrecognized peer agent string".to_string());
        }
        if parts[1] != expected_network {
            return Err(format!(
                "network mismatch: expected `{expected_network}`, peer `{}`",
                parts[1]
            ));
        }
        if parts[2] != PROTOCOL_VERSION {
            return Err(format!(
                "protocol mismatch: expected `{PROTOCOL_VERSION}`, peer `{}`",
                parts[2]
            ));
        }
        let h = parts[4].parse::<u64>().unwrap_or(0);
        Ok((parts[3].to_string(), h))
    }
}
