# Network Connectivity & Libp2p Topology

Each `vnetwork-node` process runs an independent `libp2p` swarm using:
- **Transport**: TCP + Noise encryption + Yamux stream multiplexing + DNS resolution
- **Discovery**: Kademlia DHT + Bootstrap Seed multiaddrs (`/ip4/.../tcp/.../p2p/<PeerId>`) + Identify handshake
- **Messaging**: Gossipsub pub/sub topic `vnetwork/{network_id}/consensus` for proposals, validator votes, quorum certificates, and periodic height heartbeats
- **Catch-up Sync**: Request-Response sync protocol (`/vnetwork/sync/1.0.0`) fetching verified `CommittedProposalRecord` batches from peers whenever local height trails peer height or upon reconnection
- **NAT Traversal**: libp2p Relay client + optional relay server mode (`enable_relay_server = true`)

Identify handshakes check the peer's `network_id` and protocol agent header (`vnetwork/{network_id}/1.0.0/...`) and immediately disconnect peers on mismatched networks or profiles.
