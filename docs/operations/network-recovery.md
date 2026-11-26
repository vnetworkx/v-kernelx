# Network Recovery Runbook

If a node experiences process termination or storage interruption, restart `vnetwork-node` pointing at its persistent `storage_path` and `genesis.json`. WAL verification (`events.wal` + `consensus_commits.wal`) restores committed state and libp2p `/vnetwork/sync/1.0.0` automatically catches up missing certified heights from peers.
