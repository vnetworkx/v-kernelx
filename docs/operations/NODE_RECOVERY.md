# Node Crash Recovery & P2P Catch-Up

Upon restart, `StorageDatabase::open_and_recover` executes:
1. Validates stored `genesis.json` matches configured `network_id` and `profile` (aborts immediately on mismatch).
2. Verifies hash continuity across `events.wal` and replays any committed proposals from `consensus_commits.wal` strictly above the latest verified snapshot height.
3. Reconnects to configured `bootstrap_peers` over `libp2p`, receives peer height via Identify & Gossipsub Heartbeats, and requests missing `CommittedProposalRecord` batches via `/vnetwork/sync/1.0.0`.
4. Verifies every synced Quorum Certificate (`>= 6667` bps) and re-executes events deterministically before persisting and converging to the cluster `state_root`.
