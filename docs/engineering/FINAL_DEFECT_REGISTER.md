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


## Critical Consensus Revalidation Finding — 2026-11-27

A follow-up review of the validator pre-vote path found a release-blocking issue that was not covered by AD-01 through AD-09:

| Follow-up | Defect | Required correction | Verification / Status |
|---|---|---|---|
| AD-10 — P0 | The generic validator fallback accepted hash-valid proposer-supplied events for proposals with neither an actor-authenticated operation binding nor a verified program bundle. This allowed an event-only proposal to bypass operation authorization and semantic preconditions. | Reject proposals without `nonce_binding` and without a verified `ProgramSourceBundle`, except `PARTICIPANT_JOIN`, which has its own challenge-signature verification and deterministic re-execution path. The generic replay fallback now fails closed. Added an adversarial regression that constructs a hash-valid forged Network-governance participant grant. | `crates/vnetwork-consensus/tests/strict_bft_security.rs::unbound_proposal_cannot_inject_participant_scope`; source fix is committed on `fix/reject-unbound-consensus-proposals`. **IMPLEMENTED — NOT RUNTIME VERIFIED; Rust CI required.** |

The validator's ordinary signed-operation path now verifies the actor's signed envelope and payload hash, re-runs authorization and operation preconditions against the exact pre-state, compares the complete deterministic event sequence, and verifies the post-state root. `.vx` proposals are independently recompiled and executed, and participant enrollment uses its signed challenge. Proposals that provide neither an authenticated request binding nor a verified program bundle are now rejected before event replay, with a regression covering a forged participant grant. This correction is implemented in source; the new adversarial test and the Rust workspace still require a passing CI run before the P0 can be considered closed.

## CI Status Clarification — 2026-11-27

- The 2026-11-27 run 46048013247 had the cross-language/config job pass, including the browser nonce persistence test after the JS browser client helper was added.
- The same run failed the strict Rust formatting check across many Rust files; the previous workflow had been running cargo fmt --all, which mutates the CI checkout and is not a real formatting check.
- The workflow was changed to run formatting as a separate job so that formatting failure no longer prevents Rust cargo check, tests and release build jobs from executing. The new run must be inspected before claiming Rust compilation or test success.
- The earlier Clippy errors in token.rs and wallet.rs were addressed in source, but have not yet been re-verified by a completed CI run.
