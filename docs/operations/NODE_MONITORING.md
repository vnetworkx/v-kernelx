# Node Monitoring & Health Probes

Every node with `enable_public_api = true` serves live operational probes derived from actual storage and consensus state:
- `GET /healthz` — Returns `200 OK` only when storage is verified healthy (`storage_ok: true`); returns `503 Service Unavailable` with real error details if WAL/storage health fails. Reports `node_id`, `peer_id`, `network_id`, `profile`, `protocol_version`, `height`, `state_root`, `connected_peers`, and `validator_active`.
- `GET /readyz` — Readiness gate verifying storage health plus P2P mesh connectivity (and reports `503` in `vnetwork-api` standalone mode when no consensus node is attached).
- `GET /metrics` — Prometheus text exposition (`vnetwork_height`, `vnetwork_committed_events`, `vnetwork_connected_peers`, `vnetwork_proposals_committed`, `vnetwork_proposals_rejected`, `vnetwork_votes_cast`, `vnetwork_programs_submitted`).
- `GET /v1/consensus/status` — Active validator weights, validator epoch, `validator_set_hash`, quorum threshold bps (`6667`), and certificate count.
- `GET /v1/ledger/proofs` — Event hash-chain and deterministic replay equivalence verification (`chain_valid: true`).
