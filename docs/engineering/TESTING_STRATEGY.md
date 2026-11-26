# Testing & Verification Strategy — Vector Network

## 1. Rust Authoritative Engine Tests (`cargo` Required)
- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo check --workspace --all-targets --all-features`
- `cargo test --workspace --all-features` covering:
  - `crates/vnetwork-types`: 3D token invariants, canonical JSON, Ed25519 key separation.
  - `crates/vnetwork-core/tests/language_conformance.rs`: `.vx`/`.vdx` parsing, dependency hash checks, wallet PoP, RBAC roles, `vContract`, `vLoan` escrow/interest/liquidation, checked overflow/underflow.
  - `crates/vnetwork-consensus/tests/quorum_bft.rs`: BFT quorum (`6667` bps), `validator_set_hash`, equivocation detection, epoch enforcement.
  - `crates/vnetwork-storage/tests/wal_recovery.rs`: crash-point simulation, uncertified tail rejection, snapshot state-root verification, genesis commitment checks.
- `cargo build --workspace --release`

## 2. Cross-Language Cryptographic & Canonical Parity (`tests/cross_language/run_parity.sh`)
- Compares BLAKE3 digests, `canonicalJsonBytes` (including `null` retention and unescaped HTML `< > &`), ID derivation, Ed25519 signatures, 12-field `SubmitProgramRequest` canonical bytes, `wallet_pop`, and `transfer_approval` payloads across **Rust, JavaScript, TypeScript, Python, and Go**.
- In this container environment (`node` v22 + `python3` 3.11 available; `cargo`/`go`/`tsx` absent), JS and Python parity scripts executed directly and matched byte-for-byte.

## 3. End-to-End Multi-Node Acceptance (`./scripts/test-network.sh`)
- Launches 4 persistent `vnetwork-node` validator processes in an isolated `mktemp -d` directory over real `libp2p`.
- Compiles all 16 `.vx`/`.vdx` programs, executes `bootstrap-atlas.vx` and `complete-network-workflow.vx`, tests all 5 live SDKs (`scripts/test-all-sdks.sh`), verifies atomic rollback & tampered-signature rejection, validates 3/4 quorum commit vs 2/4 minority rejection, and restarts nodes to confirm WAL + P2P sync convergence.

## 4. Environment Limitations in Current Audit Container
- Available tools: `node` v22.23.5, `npm` 10.9.9, `python3` 3.11.2, `gcc`, `make`, `curl`, `openssl`.
- Unavailable tools (`BLOCKED BY ENVIRONMENT`): `cargo`, `rustc`, `go`, `docker`, `tsx`, root `node_modules`. All Rust, Go, Docker, and multi-node runtime suites require running on a host with those toolchains installed (or via `.github/workflows/ci.yml`).
