# Final Defect Register — Vector Network

Strict classification discipline:
- `PASS`: Verified directly in this container with observed exit code `0`.
- `IMPLEMENTED — NOT RUNTIME VERIFIED`: Remediated cleanly in source with regression tests written; Rust/Go compilation and live cluster runtime execution are `BLOCKED` in this container (no `cargo`, `rustc`, `go`, or `docker`).
- `BLOCKED`: Execution prevented by absent runtime toolchains in container.
- `NOT IMPLEMENTED`: See the dated follow-up addendum below; the original register is not a guarantee that subsequent review will discover no additional defects.

---

| ID | Area | Defect Discovered | Implemented Correction | Verification Evidence | Status |
|---|---|---|---|---|---|
| **DEF-01** | Consensus | Sub-supermajority quorum clamped/accepted (`< 6667` bps) | Enforced strict `quorum_threshold_bps >= 6667` across genesis, node config, certificate validation, and quorum checks | `crates/vnetwork-consensus/tests/strict_bft_security.rs`, `crates/vnetwork-node/tests/config_validation.rs` | `IMPLEMENTED — NOT RUNTIME VERIFIED` |
| **DEF-02** | Consensus | Weak/duplicate 32-byte Ed25519 keys & empty `validator_set_hash` | Canonical 32-byte pubkey decoding, torsion/identity key rejection, canonical key uniqueness, 22-check `verify_quorum_certificate` | `crates/vnetwork-consensus/tests/strict_bft_security.rs` | `IMPLEMENTED — NOT RUNTIME VERIFIED` |
| **DEF-03** | Consensus | Historical epoch transitions not rooted to genesis | Implemented `verify_membership_chain_from_genesis` anchoring every epoch certificate & state root to `genesis_commitment` | `crates/vnetwork-consensus/tests/strict_bft_security.rs` | `IMPLEMENTED — NOT RUNTIME VERIFIED` |
| **DEF-04** | Keys & Equivocation | Plaintext key defaults & RAM-only equivocation tracking | `ProtectedSigningKey` (Argon2id + AES-256-GCM) & fsynced 9-tuple `EquivocationStore` before signing | `crates/vnetwork-node/tests/security_keys_and_equivocation.rs` | `IMPLEMENTED — NOT RUNTIME VERIFIED` |
| **DEF-05** | Storage / Recovery | Uncertified checkpoint fallback & unaligned WAL recovery | Enforced `CertifiedCheckpoint` (`certified.checkpoint.json`) anchored to QC & quarantine of uncertified tails | `crates/vnetwork-storage/tests/certified_recovery_and_wal.rs` | `IMPLEMENTED — NOT RUNTIME VERIFIED` |
| **DEF-06** | Vector Language & Ghost Entities | Parentless Ghost entities blocked by hierarchy checks; `CERTIFY` missing; `vectorspace` symlink containment missing | Enabled parentless Ghost entities scoped to `NETWORK`, implemented `ghost_custody::{token_id}` custody accounting, real `vContract`/`vLoan` state execution, `CERTIFY`, and canonical path containment | `crates/vnetwork-core/tests/{language_conformance,protocol_domain_invariants}.rs` | `IMPLEMENTED — NOT RUNTIME VERIFIED` |
| **DEF-07** | HTTP API / Node Security | Permissive CORS, unauthenticated admin/dial routes, SSRF vectors on `/v1/nodes/connect` & peer dialing | Enforced `require_admin_token`, `build_cors_layer()`, `validate_peer_dial_multiaddr`, `allow_local_p2p` flag, and full explorer Ghost/hierarchy telemetry | `crates/vnetwork-api/src/`, `crates/vnetwork-node/tests/config_validation.rs`, `app/api/{admin/status,backup}/route.ts` | `PASS` (Next.js routes & guards) / `IMPLEMENTED — NOT RUNTIME VERIFIED` (Rust crates) |
| **DEF-08** | Explorer / API Mapping | Hardcoded `"UNKNOWN"`/`"PENDING"` states, `entity_kind` misread as `region_id`, missing `ghost_custody::` accounting, shallow JSON array sorting, legacy transport/sandbox UI stubs | Standardized `VerificationStatus` (`VERIFIED \| UNVERIFIED \| INVALID \| UNAVAILABLE`), fixed `region_id` mapping, added `ghost_custody::` + `ghost_assessment` + `hierarchy_commitments`, added recursive `sortJsonValueClient`, replaced legacy sandbox & `VectorsPanel` with real `.vx` workbench and `vContract`/`vLoan` console | `tests/explorer/integrity_and_crypto.test.mjs` (`21/21`), `tsc --noEmit`, `next lint`, `next build` | `PASS` |
| **DEF-09** | Multi-Language SDK Parity | Asymmetric endpoint coverage (`contracts`, `loans`, `explorer`, `nodes`), JS/TS/Py verification drift, Go client parity test absent | Synchronized all 5 SDKs (`rust`, `js`, `ts`, `python`, `go`), standardized `VerificationStatus`, hardened module loaders, added `sdks/go/client_test.go` | `tests/cross_language/sdk_parity.test.mjs` (`6/6`), `test_python_sdk.py` (`6/6`), `@vnetwork/ts-sdk` check | `PASS` (JS/TS/Py) / `IMPLEMENTED — NOT RUNTIME VERIFIED` (Rust/Go) |
| **DEF-10** | CI / Scripts | Unpinned CI actions, `|| true` step masking, destructive `DEVNET_DIR` / PID cleanup hazards | Pinned CI GitHub Actions to commit SHAs, removed all `|| true` bypasses, enforced `.vnetwork-devnet-owner` + PID cmdline + `sync-vectorspace.sh --check`, updated `.env.example` | `tests/e2e/script_safety.test.sh` (`6/6`), `bash -n` on all `.sh` files | `PASS` |


## Follow-up Audit Addendum — 2026-11-27

A subsequent source review found additional issues not captured by the original register. The following corrections have been committed to the upstream remediation branch, with runtime verification pending the current GitHub Actions run:

| Follow-up | Defect | Correction | Evidence / Status |
|---|---|---|---|
| AD-01 | Generic participation permission used for Space creation; post-bootstrap genesis-validator enrollment escape; participant/node identity overwrite | Explicit Network governance check, bootstrap-height/current-epoch restriction, reject identity overwrite | Regression tests added; kernel CI pending |
| AD-02 | Revoked participants could not be reinstated without key reuse/record overwrite | Explicit signed `ReinstateParticipant` operation, event replay, API/Vector Language/TypeScript support; restores Network only and leaves node unhealthy until resync | Regression tests added; kernel CI pending |
| AD-03 | Failed multi-ledger transition could leak partial state | Clone-and-commit operation execution | Regression test added; kernel CI pending |
| AD-04 | Loan fund/draw after maturity, liquidation without default, no cancellation path for unfunded collateral | Maturity gates, explicit default-before-liquidation, Cancelled state and collateral refund with conservation check | Regression scenarios added; kernel CI pending |
| AD-05 | Replay verification trusted live anti-replay index maps | Durable `REQUEST_NONCE_COMMIT` events; consensus binding and replay reconstruction | Regression tests added; kernel CI pending |
| AD-06 | Malformed ordinary hierarchy parents silently fell back to Network commitment; contract AuthRatio check could be bypassed by omitting Region | Reject missing hierarchy parents except explicit Ghosts; AuthRatio-gated contracts must be Region-bound | Regression tests added; kernel CI pending |
| AD-07 | Request nonce counters could reset after process restart or after an accepted request whose HTTP response was lost | Persist-before-send nonce reservations in CLI and Node/Browser JavaScript, TypeScript, Python, Go, Rust SDKs | Cross-language restart/concurrency tests added; kernel CI pending |
| AD-08 | Testnet nodes without shared genesis could independently derive divergent genesis commitments from their local validator identities | Require explicit genesis or configured shared genesis validator set for TESTNET and PRODUCTION; only DEVELOPMENT may derive local bootstrap genesis | Policy regression test added; kernel CI pending |
| AD-09 | Contract escrow close used unchecked `u128` summation | Checked accumulation returns a validation error on overflow; added extreme-value regression coverage | Regression test added; kernel CI pending |

The standalone `vnetworkx/vectorspace` runtime has a separate upstream PR with checked vector arithmetic, zero-vector/self-transfer validation, and transactional execution. Its Rust CI passed on commit `c182e775034370bd8910b669017d0e02e038ed93`. The kernel's current multi-platform Rust and cross-SDK checks are still pending; the status of an earlier run must not be substituted for the latest head.

The follow-up audit is ongoing. In particular, full multi-node P2P durability/upgrade acceptance, complete vContracts failure/refund semantics, and live testnet recovery remain deployment-blocking verification areas until exercised in an appropriate Rust/Go/Docker environment.
