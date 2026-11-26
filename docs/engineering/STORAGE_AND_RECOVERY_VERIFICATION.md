# Storage and Recovery Verification — Vector Network

**Status**: `IMPLEMENTED` in Rust (`crates/vnetwork-storage/`, `crates/vnetwork-node/`); `cargo test` execution `BLOCKED BY ENVIRONMENT` (no `cargo`/`rustc` toolchain in container); Explorer replay & ledger conservation verification `TESTED` (`tests/explorer/integrity_and_crypto.test.mjs`, 17/17 passed).

---

## 1. Certified Checkpoint & Strict WAL Design (`crates/vnetwork-storage/`)

1. **Exclusive Certified Bootstrap**:
   - Node startup requires valid `CertifiedCheckpoint` (`certified.checkpoint.json`) anchored to a verified `QuorumCertificate`, `proposal_digest`, `state_root`, `history_root`, and `genesis.json` commitment (`crates/vnetwork-storage/src/snapshots.rs`, `recovery.rs`).
   - Legacy uncertified `state.snapshot.json` fallback paths are disabled; uncertified temporary files or uncommitted journals are quarantined rather than promoted into authoritative state.
2. **Two-Phase Commit WAL (`crates/vnetwork-storage/src/transactions.rs`, `database.rs`)**:
   - Writes record a prepare marker in `commit_journal.wal` with `sync_all()`, persist aligned entries to `events.wal` and `consensus_commits.wal`, write temp checkpoint + `fsync` + atomic rename, and commit the journal marker.
   - `QuorumCertificate` verification and `storage.persist_commit(...)` complete *before* promoting in-memory `shared_state` or broadcasting finality events (`crates/vnetwork-node/src/lifecycle.rs`).
   - Storage write errors propagate explicitly (`Result`) instead of being ignored (`let _ =`).
3. **Strict Recovery Validation (`crates/vnetwork-storage/src/recovery.rs`)**:
   - Rejects corrupted WAL records, missing historical certificates, extra uncertified events, missing certified events, event reordering, `state_root` mismatches, `history_root` mismatches, incomplete prepare markers without matching commit, and wrong membership history.

---

## 2. Storage & Recovery Test Coverage (`IMPLEMENTED` in Rust)

Implemented in:
- `crates/vnetwork-storage/tests/certified_recovery_and_wal.rs`
- `crates/vnetwork-storage/tests/wal_recovery.rs`
- `crates/vnetwork-core/tests/protocol_domain_invariants.rs`

Covers:
- Valid certified checkpoint + clean replay reconstruction.
- Rejection of tampered checkpoint QC, missing historical certificate, wrong membership history, corrupted WAL framing, extra uncertified tail event, missing certified event, altered event order, `state_root` mismatch, `history_root` mismatch, incomplete crash markers, and interrupted writes.
- Deterministic domain replay error propagation (`replay.rs`, `reconstruction.rs`, `ghost.rs` TTL expiration).

---

## 3. Explorer Conservation & Replay Verification (`TESTED`)

Verified directly via `node --test tests/explorer/integrity_and_crypto.test.mjs` (17/17 passed):
- `/api/replay` compares `/v1/ledger/replay` against `/v1/ledger/proofs`; missing reports remain `UNVERIFIED` and mismatched state roots or incorrect `network_id` mark `INVALID`.
- Conservation verification computes sums from actual returned balances rather than copying `totalSupply`; partial balance sets or unknown account categories prevent a false `VERIFIED` claim.
- Missing region creation events preserve honest `null` hashes/metadata without synthetic fabrication.
