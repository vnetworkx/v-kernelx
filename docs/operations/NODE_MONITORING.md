# Node Monitoring & Health Probes

Every node with `enable_public_api = true` serves:
- `GET /healthz` — Node ID, PeerId, network/profile, height, state root, peer count, validator active status.
- `GET /readyz` — Kubernetes readiness gate (checks P2P mesh / bootstrap connectivity).
- `GET /metrics` — Prometheus text exposition (`vnetwork_height`, `vnetwork_committed_events`, `vnetwork_connected_peers`, `vnetwork_proposals_committed`, `vnetwork_proposals_rejected`, `vnetwork_votes_cast`, `vnetwork_programs_submitted`).
- `GET /v1/consensus/status` — Active validator weights, quorum threshold bps (`6667`), and certificate count.
- `GET /v1/ledger/proofs` — Hash-chain and deterministic replay equivalence check (`chain_valid: true`).
