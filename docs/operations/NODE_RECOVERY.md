# Node Crash Recovery & P2P Catch-Up

Upon restart, `StorageDatabase::open_and_recover` executes consensus-aware recovery:
1. Validates stored `genesis.json` and `genesis_hash` against configured `network_id`, `profile`, `protocol_version`, `genesis_timestamp_ms`, `initial_validators`, and `allow_bootstrap_atlas` (aborts immediately on mismatch).
2. Verifies `events.wal` hash continuity and checks `consensus_commits.wal` records (validating `QuorumCertificate`, validator-set commitment, epoch, and proposal linkage).
3. Verifies any loaded `state.snapshot.json` against `compute_replay_hash()`, `compute_state_root()`, and committed height; snapshots failing cryptographic verification are ignored and rebuilt from verified commits.
4. Never promotes uncertified `events.wal` tail records into authoritative committed state; incomplete staging records without durable `QuorumCertificate`s remain uncommitted.
5. Reconnects to configured `bootstrap_peers` over `libp2p`, observes peer heights via Identify & Gossipsub Heartbeats, requests missing `CommittedProposalRecord` batches via `/vnetwork/sync/1.0.0`, verifies every Quorum Certificate before committing atomically, and converges to identical `height` and `state_root`.
