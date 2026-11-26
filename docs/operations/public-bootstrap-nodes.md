# Public Bootstrap Nodes

Bootstrap seed nodes run with `node_kind = "BOOTSTRAP_SEED"`, `enable_p2p = true`, `enable_relay_server = true`, and static PeerIds derived from `node.key.json`.
Configure peers using `NETWORK_BOOTSTRAP_PEERS=/dns4/seed1.example.com/tcp/7001/p2p/<PeerId>,/dns4/seed2.example.com/tcp/7001/p2p/<PeerId>`.
