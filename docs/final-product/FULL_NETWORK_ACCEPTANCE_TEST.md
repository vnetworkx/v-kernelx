# Full Network Acceptance Test (`scripts/test-network.sh`)

`scripts/test-network.sh` validates the complete production architecture end-to-end with zero mocks:
1. Executes all Cargo workspace unit & integration tests (`quorum_bft`, `language_conformance`, `wal_recovery`).
2. Verifies byte-for-byte 5-language BLAKE3 / Canonical JSON / Ed25519 parity (`tests/cross_language/run_parity.sh`).
3. Compiles all 16 `.vx`/`.vdx` examples via `vn language compile`.
4. Launches 4 persistent `vnetwork-node` validator processes connected over real `libp2p` TCP+Noise+Yamux+Gossipsub.
5. Submits `.vx` workflows via `vn` CLI and all 5 live SDKs (Rust, JavaScript, TypeScript, Python, Go) and verifies convergence across all 4 nodes.
6. Verifies atomic zero-partial-state rollback on a failing `.vx` program (`failed_operation_index = 3`).
7. Proves BFT fault tolerance: 3/4 validators (`300/400 >= 6667 bps`) still achieve finality; 2/4 (`200/400 < 6667 bps`) reject quorum cleanly with zero corruption.
8. Restarts stopped nodes and verifies WAL recovery + `libp2p` `GetMissingCommits` catch-up sync restores exact `height`, `state_root`, and `chain_valid: true` across all 4 nodes.
