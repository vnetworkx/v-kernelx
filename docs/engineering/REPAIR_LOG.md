# Engineering Repair Log

Tracks verified code repairs across all 10 implementation stages.

---

## Stage 1 — Build, CI/Release, Script Safety & Baseline Audit
- Created `BASELINE_AUDIT.md`, `IMPLEMENTATION_ROADMAP.md`, and `ARCHITECTURE_DECISIONS.md`.
- Updated `.github/workflows/ci.yml` and `.github/workflows/release.yml` to check, clippy, test, and release-build the full `--workspace` across Linux/macOS/Windows targets and validate 5-language parity, shell syntax, and TOML configs.
- Updated `scripts/test-network.sh`, `scripts/devnet-up.sh`, `scripts/backup.sh`, and `scripts/test-all-sdks.sh` to isolate temporary devnets via `mktemp -d`, guard cleanup against deleting user directories, use `vector-devnet-1`, and remove obsolete `tsx atlas.ts` commands.

## Stage 2 — 3D Token Model, Checked Arithmetic & Canonical Commitments
- Enforced `[token, auth_ratio_au, energy]` invariants (`crate::token`, `replay.rs`, `drain.rs`): transfers only modify dimension 0 (`token`) with zero fallback `auth_ratio_au` invention (`[0, 0, 0]` initial receiver vector) and explicit rejection of `initial_supply > max_supply` for finite `max_supply > 0`.
- Replaced `saturating_*` and unchecked math in financial/supply/vote-weight paths with `checked_add`/`checked_sub`/`checked_mul`/`checked_div`.
- Added strict versioned migration rejection for legacy 2D records (`schema_version`).
- Expanded `NetworkLedgerState::compute_state_root()` to include `protocol_version`, `genesis_hash`, `nodes`, `actor_nonces`, `seen_request_ids`, `validator_epoch`, `validators`, and `validator_set_hash`.

## Stage 3 — Participant Scopes & Multi-Key Wallet Proof-of-Possession
- Removed blind self-granting of `SPACE`, `REGION`, `WALLET`, and `TOKEN` scopes in `verify_and_register_participant`; `NETWORK` joins default cleanly unless backed by signed `scope_authorizations` (`ScopeGrant` metadata: `grantor_pubkey`, `authorization_basis`, `expires_at_ms`, `revoked`).
- Enforced challenge-response Proof-of-Possession (`PoP`) signatures (`verify_wallet_pop_signature`), role-based key permissions (`VIEW`, `RECEIVE`, `SEND`, `DRAIN`, `MANAGE_KEYS`, `CO_SIGNER`, `CONTRACT_INTERACT`), token/spend caps, revocation, rotation, and threshold multisignature (`signed_transfer_approvals`).

## Stage 4 — Transactional WAL Storage, Post-Persistence Finality & Crash Recovery
- Fixed `crates/vnetwork-node/src/lifecycle.rs` commit ordering: `QuorumCertificate` verification and atomic `storage.persist_commit(...)` now execute *before* promoting state to `shared_state` or broadcasting `CONSENSUS_FINALITY` WebSocket events; storage errors propagate cleanly instead of being discarded via `let _ =`.
- Upgraded `crates/vnetwork-storage` to crash-safe 2-phase commit journal (`commit_journal.wal` prepare/commit markers + `sync_all` + atomic snapshot write/rename), full `GenesisConfig` verification, snapshot state-root checks, and certificate-only recovery (never promoting uncertified `events.wal` tails).

## Stage 5 — Vector Language Integration (`vendor/vectorspace` `v-langx` v1.2.0)
- Eliminated `f64` arithmetic in `vendor/vectorspace/src/compiler.rs`, migrating `compute_auth_ratio` and `Statement::Certify` evaluation to deterministic `u128` fixed-point integer math.
- Extended `SubmitProgramRequest` canonical signing across Rust core, CLI, and all 5 SDKs + Next.js client crypto to bind all 12 fields (including `.vdx` module hashes, `execution_params`, `file_kind`, `protocol_version`, `language_version`, and `compiler_version`).
- Updated `examples/vector-language/bootstrap-atlas.vx` to Section 25 requirements (`ATLAS` / `ATL` / `Atlas Vector Region` / `ATLAS TOKEN`), fixed `create-loan.vx` borrower collateral funding, updated `connect.vx` & `participant-join.vx` to `vector-devnet-1`, and verified `policies.vdx` & `shared-wallet.vdx` BLAKE3 hashes.

## Stage 6–7 — Distributed Consensus, Health Probes, API Hardening & Standalone API
- Bound `ConsensusProposal` & `QuorumCertificate` to `validator_set_hash`, `validator_epoch`, `program_source_bundle`, and `nonce_binding`; enforced per-vote epoch/signature validation and equivocation checks.
- Implemented storage-driven `/healthz` (`503` on failure) and `/readyz`, `ConnectInfo<SocketAddr>` rate limiting, and `DetachedApiBackend` in `crates/vnetwork-api/src/main.rs`.

## Stage 8 — SDKs, CLI, Explorer Proxy & Deployment Configs
- Synchronized JS, TS, Python, and Go SDKs to `PROTOCOL_VERSION = "vector-network/1.0.0"`, `v-langx/1.2.0`, 12-field program submission, wallet PoP, transfer co-signing, canonical `null` preservation (`canonical.py`), and unescaped HTML canonical JSON (`canonical.go`).
- Fixed `lib/server/kernel.ts`, `lib/server/network-proxy.ts`, `app/page.tsx`, and all 22 `/app/api/*/route.ts` handlers to proxy cleanly to `vnetwork-api` (`503` when unreachable, `400` on unsigned writes) with zero `@/ts/src/index.ts` or mock-kernel fallbacks.
- Fixed `deploy/reverse-proxy/{Caddyfile,nginx.conf}` (`bootstrap-seed:8080`), updated `config/*.example.toml` (`protocol_version = "vector-network/1.0.0"`), aligned `deploy/docker-compose*.yml` and Kubernetes manifests, and documented canonical env vars in `.env.example`.

## Stage 9–10 — Contracts, Loans, Documentation & Cross-Language Parity
- Wired `vContract` execution bounds (`allowed_actors`, `max_executions`, `expires_at_ms`, `min_auth_ratio_au`) and `vLoan` collateral escrow, integer interest accrual, partial repayments, and authorized liquidation (`crates/vnetwork-core/{contracts,loans}.rs`).
- Verified JS <-> Python byte-for-byte parity locally across all 14 parity vectors (`verify_parity.mjs`, `verify_parity.py`); added `SECURITY_REVIEW.md` and `TESTING_STRATEGY.md`.
