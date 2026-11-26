-- Vector Network Durable Storage Schema (v1)
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS genesis_metadata (
    network_id TEXT PRIMARY KEY,
    profile TEXT NOT NULL,
    protocol_version TEXT NOT NULL,
    genesis_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ledger_events (
    sequence INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    entity_kind TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    event_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS consensus_certificates (
    certificate_id TEXT PRIMARY KEY,
    height INTEGER NOT NULL,
    proposal_id TEXT NOT NULL,
    post_state_root TEXT NOT NULL,
    certificate_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS state_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    height INTEGER NOT NULL,
    state_root TEXT NOT NULL,
    snapshot_json TEXT NOT NULL
);
