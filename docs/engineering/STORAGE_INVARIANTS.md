# Storage & Recovery Invariants — Vector Network

Tracks 1 and 5 establish fail-closed persistence, encrypted identity management, and certified crash recovery across `vnetwork-types`, `vnetwork-storage`, and `vnetwork-node`.

---

## 1. Encrypted Node & Validator Key Storage

1. Node and validator secret seeds live exclusively inside `Zeroizing<[u8; 32]>` inside `ProtectedSigningKey`. `Debug` outputs `"[REDACTED]"`, `EncryptedKeyEnvelope::Debug` outputs `"[ENCRYPTED]"`, and `NodeIdentityMetadata` omits secret material entirely.
2. Envelopes encrypt 32-byte seeds using Argon2id (`v0x13`, minimum `4096 KiB`, default `65536 KiB`, `t=3`, `p=1`) and AES-256-GCM authenticated with AAD binding `{envelope_version, cipher, kdf, kdf_params, key_role, derived_id, public_key_hex, pubkey_fingerprint, key_version}`.
3. File writes create temporary `.json.enc.tmp` files with POSIX mode `0600`, `sync_all()`, and atomic `rename` with parent directory sync (`0700` dir permissions).
4. Reading refuses group/world-accessible key files (`mode & 0o077 != 0`) and refuses legacy plaintext `private_key_hex` files unless explicit `allow_plaintext_key_fallback` override is enabled for migration.
5. `rotate_encrypted_key` records an append-only `KeyRotationRecord` chain (`version`, previous/new public keys and IDs, timestamp, reason).

---

## 2. Transactional Two-Phase Commit (`StorageDatabase::persist_commit`)

For every committed proposal at height `h`:

1. Verify `proposal.verify_digest_and_metadata()` and exact `state.height` + `state.compute_state_root() == proposal.post_state_root`.
2. Atomically write `wal_tx/tx_{h:012}_pending.json` (`prior_event_count`, target `proposal_id`, `proposal_digest`, `certificate_id`, `post_state_root`).
3. Append events to `events.wal` (`sync_all`).
4. Append `(proposal, certificate)` to `consensus_commits.wal` (`sync_all`).
5. Atomically write `wal_tx/tx_{h:012}_committed.marker`.
6. Persist certified checkpoint (`certified.checkpoint.json`) anchored to `qc`, `proposal_digest`, `parent_commitment`, `state_root`, and `event_history_root`.
7. Persist derived read projections (`transactions.json`, `programs.json`, `indexes.json`).
8. Clean up processed `pending` / `committed` WAL markers only after all durable writes succeed.

---

## 3. Fail-Closed Crash Recovery & Health Probes (`recover_state_from_disk` / `check_health`)

1. Validate `GenesisConfig` and verify full `genesis.commitment_hash()` against on-disk `genesis.json`. Any mismatch in `network_id`, `profile`, `protocol_version`, `drain_policy`, or `initial_validators` fails loudly.
2. Any `_pending.json` lacking `_committed.marker` triggers rollback of heights `>= min_uncommitted_height` and truncation of uncommitted `events.wal` entries above `prior_event_count`, moving pre-rollback/uncommitted artifacts into `forensic_quarantine/` rather than silent deletion.
3. Legacy uncertified `state.snapshot.json` files without `certified.checkpoint.json` are strictly refused (`load_certified_checkpoint` returns an error).
4. `verify_wal_exact_alignment` enforces:
   - Event hash chain continuity across `events.wal`.
   - Height continuity `1..=H` across `consensus_commits.wal`.
   - Certificate <-> proposal digest, IDs, hashes, and root match per height.
   - Exact 1-to-1 equality of `events.wal` and flattened certified proposal events (`event_id`, `event_hash`, `prev_event_hash`, `sequence`, `payload_hash`).
5. `CertifiedCheckpoint` is verified against `GenesisConfig` and `consensus_commits.wal`; any divergence fails closed. State reconstruction above checkpoint height verifies `verify_membership_chain_from_genesis` before committing each proposal.
6. `/healthz` fails with HTTP `503` whenever `StorageDatabase::check_health()` or `EquivocationStore::check_health()` fails, returning exact `storage_ok`, `wal_consistency_ok`, `equivocation_store_ok`, `equivocation_count`, `key_storage_mode`, and `verification_status` values without hardcoded `true` defaults.
