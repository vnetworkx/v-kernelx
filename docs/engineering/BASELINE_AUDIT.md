# Vector Network (`v-kernelx`) Baseline Engineering Audit

**Audit Date**: 2026-11-26  
**Repository**: `vnetworkx/v-kernelx` (with vendored `vendor/vectorspace` / `v-langx` v1.2.0)  
**Environment Inspection Status**: Local workspace audited directly against source code. `node` v22.23.5, `npm` 10.9.9, `python3` 3.11.2, `gcc`, `make`, `curl`, and `openssl` are available in the container; `cargo`, `rustc`, `go`, `docker`, and `tsx` are NOT installed in this container. Baseline cross-language JS & Python parity scripts passed (`verify_parity.mjs`, `verify_parity.py`); `verify_parity.ts` failed due to ESM `.js` import specifiers requiring TypeScript compilation or `tsx`.

---

## 1. Critical Protocol & Security Defects Discovered

### 1.1 Protocol Version & SDK Desynchronization
- **Authoritative Constant**: `crates/vnetwork-types/src/protocol_version.rs` defines `PROTOCOL_VERSION = "vector-network/1.0.0"`.
- **Defect**:
  - `sdks/javascript/index.js`, `sdks/javascript/browser.js` hardcode `"vnetwork/1.0"`.
  - `sdks/typescript/src/client.ts`, `sdks/typescript/src/browser.ts` hardcode `"vnetwork/1.0"`.
  - `sdks/python/vnetwork_sdk/client.py` hardcodes `"vnetwork/1.0"`.
  - `sdks/go/client.go` hardcodes `"vnetwork/1.0"`.
  - `config/{bootstrap,node,network}.example.toml` use `"vnetwork/0.2.0"`, failing `NodeConfig::validate()`.
- **Impact**: No non-Rust SDK can connect to any `vnetwork-node`, and none of the example `.toml` configs can start a node without overrides.

### 1.2 Finality Before Persistence & Non-Atomic Storage
- **Defect in `crates/vnetwork-node/src/lifecycle.rs`**:
  - `finalize_proposal_everywhere` calls `finalize_and_commit(...)` (mutating committed engine state) **before** persisting to disk, then discards persistence errors (`let _ = storage.persist_commit(...)`), updates `shared_state`, and broadcasts `QuorumCertificate` + `CONSENSUS_FINALITY` WebSocket events.
  - `submit_program` and `submit_signed_operation` mutate `*shared_state.write().await = engine.state.clone()` when staging proposals prior to quorum finality.
  - `let _ = storage.persist_metadata_only(...)` discards metadata write errors.
- **Defect in `crates/vnetwork-storage/src/database.rs`**:
  - `persist_commit` performs 5 independent unbundled writes (`events.wal`, `consensus_commits.wal`, `state.snapshot.json`, `programs.json`/`transactions.json`, `indexes.json`), appending `events.wal` *before* `consensus_commits.wal`. A crash mid-commit leaves divergent WALs/snapshots.
  - `persist_metadata_only` uses `let _ = persist_entity_index(...)`.
- **Defect in `crates/vnetwork-storage/src/recovery.rs`**:
  - Line 89–90: If `committed_proposals` is empty, recovery replays **uncertified** `wal_events` into committed state!
  - Snapshots only check `compute_replay_hash()`, not `compute_state_root()` or certificate linkage, and blindly copy `programs`, `transactions`, `certificates`, `actor_nonces`, and `seen_request_ids`.
  - Genesis verification checks only `network_id` and `profile`, omitting `protocol_version`, `genesis_timestamp_ms`, `initial_validators`, and `allow_bootstrap_atlas`.

### 1.3 Incomplete Canonical State Root & Proposal Commitments
- **Defect in `crates/vnetwork-core/src/state.rs`**:
  - `NetworkLedgerState::compute_state_root()` hashes `balances, contracts, height, loans, logical_clock, network_id, participants, profile, regions, spaces, tokens, wallets` — omitting `nodes`, `actor_nonces`, `seen_request_ids`, `protocol_version`, validator membership/epoch, and genesis commitment.
- **Defect in `crates/vnetwork-types/src/consensus.rs`**:
  - `ConsensusProposal::canonical_signing_bytes()` omits `program_source_bundle` and `nonce_binding`.

### 1.4 Broken 3D Token Accounting, Economic Invention & Arithmetic Safety
- **Defect in `crates/vnetwork-core/src/token.rs`**:
  - Line 51: `let eff_max = max_supply.max(initial_vector.token);` silently increases an explicitly set `max_supply` instead of rejecting `initial_vector.token > max_supply`.
  - Line 170 (and `replay.rs:136`): initializes empty recipient wallet balance with `TokenVector::new(0, 1000, 0)` (hardcoded `1000` `auth_ratio_au`).
  - Line 219, 300: `saturating_sub` and raw `-=` used instead of checked arithmetic; `apply_drain_token` skips `verify_token_supply_conservation`.
- **Defect in `crates/vnetwork-core/src/replay.rs`**:
  - Line 113: `let _ = apply_transfer_token(...)?;` discards return values and uses `saturating_sub`, `-=`, `+=` fallback branch when `drain_fee > 0`.
- **Defect in `crates/vnetwork-core/src/drain.rs`**:
  - Line 18: uses `amount.saturating_sub(fee)`.
- **Defect in `vendor/vectorspace/src/compiler.rs`**:
  - Uses `f64` floating-point math (`0.35 * am + ...`, `parse::<f64>()`) in `compute_auth_ratio` and `Statement::Certify` compilation.

### 1.5 Broken Participant Scope Authorization & Multi-Key Wallet Security
- **Defect in `crates/vnetwork-core/src/identity.rs`**:
  - `verify_and_register_participant` automatically grants EVERY scope in `req.requested_scopes` with `target_id: None`, allowing any joining client to grant itself `SPACE`, `REGION`, `WALLET`, and `TOKEN` scopes at will.
  - `require_participant_scope` bypasses participant verification if an actor is present anywhere in `wallet.authorized_keys`, regardless of role/revocation.
  - Missing scope grant metadata (`grantor`, `authorization_basis`, `permissions`, `expires_at_ms`, `registration_event_id`, `revoked_at_ms`), key rotation, explicit scope grant/revocation operations.
- **Defect in `crates/vnetwork-core/src/wallet.rs` & `crates/vnetwork-types/src/entity.rs`**:
  - `apply_authorize_wallet_key` requires NO proof-of-possession signature from `new_pubkey` bound to `{network_id, wallet_id, participant_identity, public_key, purpose, nonce, expiry, protocol_version}`.
  - `WalletEntity::is_authorized_signer` checks map membership only and completely ignores `role` (`view`, `receive`, `send`, `drain`, `manage_keys`, `co-signer`, `contract_interact`), spend limits, token allocation restrictions, expiry, revocation, or multisig thresholds.

### 1.6 Incomplete Vector Language Signing & Implicit Program Defaults
- **Defect in `crates/vnetwork-core/src/language/submission.rs`**:
  - `SubmitProgramRequest::canonical_signing_bytes()` signs only `{actor_pubkey, file_name, network_id, nonce, request_id, source_hash}`, omitting `modules` (paths + content hashes), `execution_params`, `file_kind`, `protocol_version`, `language_version`, `compiler_version`.
  - All 5 SDKs + browser clients also omit these fields from signing payloads.
- **Defect in `crates/vnetwork-core/src/language/program.rs`**:
  - `TOKEN_CREATE` defaults to `(1_000_000, 1_000, 0)` when fields are absent, ignores parse failures via `.unwrap_or(...)`, and defaults `max_supply` silently to `initial_supply`.
  - `TOKEN_TRANSFER` selects `state.tokens.keys().next()` if token reference is omitted.

### 1.7 Consensus, Epoch, Contracts & Loans Gaps
- **Defect in `crates/vnetwork-core/src/consensus_gate.rs`**:
  - `verify_quorum_certificate` does not verify `vote.epoch == qc.epoch`, skips `approve == false` votes instead of validating them or rejecting malformed votes, and uses `saturating_add`.
  - `lifecycle.rs` mixes fixed `epoch: 1` proposals with `(state.height / 100) + 1` status reporting.
- **Defect in `crates/vnetwork-core/src/contracts.rs`**:
  - Any `Network`-scoped participant can execute any contract regardless of creator, authorized actors, `rules` (max_executions, expiry, allowed_actors, auth_ratio requirements).
- **Defect in `crates/vnetwork-core/src/loans.rs`**:
  - Collateral is recorded numerically (`collateral_locked: collateral`) without locking collateral tokens in escrow, releasing/seizing collateral on repay/liquidate, or checking authorization on `liquidate`. Interest calculation is ignored during `repay`, and `saturating_*` arithmetic is used.

### 1.8 API, Health Checks, Deployment, CI & Script Safety
- **Health**: `crates/vnetwork-api/src/routes/network.rs` `healthz` always returns `200 OK`; `lifecycle.rs` hardcodes `healthy: true` and `storage_ok: true`.
- **Middleware**: `crates/vnetwork-api/src/middleware.rs` blindly trusts spoofable `x-forwarded-for` headers without peer socket info or bounded limiter map eviction.
- **Stub Binary**: `crates/vnetwork-api/src/main.rs` prints a note and exits 0, breaking `deploy/Dockerfile.api`.
- **CI/Release**: `.github/workflows/{ci,release}.yml` run `cargo clippy` / `cargo test` / `cargo build --release` without `--workspace`.
- **Unsafe Cleanup Scripts**: `scripts/test-network.sh` and `scripts/devnet-up.sh` execute `rm -rf "$DEVNET_DIR"` without path validation or isolated `mktemp -d` defaults; `scripts/backup.sh` still references removed `npx tsx atlas.ts backup`.
- **Deployment Mismatches**: `deploy/reverse-proxy/{Caddyfile,nginx.conf}` proxy to `127.0.0.1:8080` instead of `bootstrap-seed:8080`; compose manifests use `NETWORK_GENESIS_PATH`, `NETWORK_ADVERTISED_ADDRS`, `NETWORK_NODE_ID`, and non-PeerId multiaddrs.
- **Next.js Explorer**: `lib/server/kernel.ts` imports nonexistent `@/ts/src/index.ts`.
- **Bootstrap Fixture**: `examples/vector-language/bootstrap-atlas.vx` uses `Atlas Genesis Region` / `ATLAS` prefix / `ATLAS` token name instead of `ATLAS` / `ATL` / `Atlas Vector Region` / `ATLAS TOKEN`.
