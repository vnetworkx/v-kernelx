# Node Participation & Validator Set

Nodes operate in one of four `NodeKind` modes configured cleanly via TOML, CLI, or `NETWORK_*` environment variables:
- `BOOTSTRAP_SEED`: Publicly reachable discovery and relay peer.
- `FULL_NODE`: Replicates all committed proposals, verifies Quorum Certificates, and serves `/v1/*` APIs.
- `VALIDATOR_NODE`: Active consensus participant holding `validator.key.json`, independently verifying `.vx` source bundles + re-executing state transitions prior to signing votes.
- `LIGHT_PARTICIPANT`: Lightweight participant endpoint.

Consensus finality requires `approving_weight * 10000 >= total_active_weight * 6667` (`>= 2/3` supermajority). Double-voting on conflicting proposals at the same `(height, round)` triggers `EquivocationDetector` evidence and rejection.
