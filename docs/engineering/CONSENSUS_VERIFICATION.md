# Consensus Verification — Vector Network

**Status**: `IMPLEMENTED` in Rust (`crates/vnetwork-consensus/`, `crates/vnetwork-node/`); `cargo test` execution `BLOCKED BY ENVIRONMENT` (no `cargo`/`rustc` toolchain in container); Explorer proof & certificate consumption `TESTED` (`tests/explorer/integrity_and_crypto.test.mjs`, 17/17 passed).

---

## 1. BFT Safety Invariants Implemented

| Invariant | Implementation Location | Verification Logic |
|---|---|---|
| Supermajority Quorum (`>= 6667` bps) | `crates/vnetwork-consensus/src/quorum.rs`, `crates/vnetwork-node/src/config.rs` | Rejects configured or certificate-embedded thresholds `< 6667` bps; never silently clamps down to `5001`. Computes `(signed_weight * 10000) >= (total_weight * threshold_bps)` using checked `u128` arithmetic. |
| Canonical Unique Validator Keys | `crates/vnetwork-consensus/src/eligibility.rs`, `membership.rs` | Decodes exact 32-byte canonical compressed Ed25519 keys; rejects identity point, all-zero keys, small-order torsion keys, and duplicate pubkeys across distinct `validator_id`s. |
| Full `ProposalDigest` Binding | `crates/vnetwork-consensus/src/proposal.rs` | Binds `network_id`, `protocol_version`, `genesis_commitment`, `epoch`, `height`, `round`, ordered `event_ids` & event hashes, `pre_state_root`, `post_state_root`, `validator_set_hash`, `program_source_bundle`, `execution_params`, and `nonce_binding` via BLAKE3 (`vnetwork/proposal-digest/v1`). |
| 22-Check `QuorumCertificate` | `crates/vnetwork-consensus/src/certificate.rs` | Verifies certificate ID derivation, non-empty `validator_set_hash`, `network_id`, `genesis_commitment`, `protocol_version`, matching `proposal_digest`, epoch bounds, unique voter IDs, unique canonical pubkeys, valid signatures over vote domain, `VotePhase` match, and threshold achievement. |
| Genesis-Rooted Membership History | `crates/vnetwork-consensus/src/membership.rs`, `epochs.rs` | `verify_membership_chain_from_genesis` verifies every validator set transition continuously from `genesis.initial_validators` through committed epoch certificates. |
| Durable Equivocation Fence | `crates/vnetwork-consensus/src/equivocation.rs` | 9-tuple slot lock with `IntentPending` -> `fsync` -> `sign()` -> `Signed` -> `fsync`; durable `EquivocationEvidence` generation on conflicting votes; fail-closed on store tampering/corruption. |

---

## 2. Consensus & Config Test Matrix Implemented (Rust `cargo test`)

All negative and positive cases are implemented in:
- `crates/vnetwork-consensus/tests/quorum_bft.rs`
- `crates/vnetwork-consensus/tests/strict_bft_security.rs`
- `crates/vnetwork-node/tests/security_keys_and_equivocation.rs`
- `crates/vnetwork-node/tests/config_validation.rs`

Coverage matrix includes:
1. Valid supermajority quorum & QC verification (`test` — `BLOCKED BY ENVIRONMENT` to run here).
2. Insufficient quorum rejection & modified certificate threshold rejection.
3. Sub-`6667` bps configured threshold rejection.
4. Wrong `network_id`, wrong `genesis_commitment`, wrong validator `epoch`, wrong validator set, empty `validator_set_hash`.
5. Duplicate canonical Ed25519 pubkey across validator IDs & small-order/identity key rejection.
6. Invalid vote signature, duplicate voter, conflicting double vote (`VotePhase`-scoped), and cross-height/network replay rejection.
7. Membership transition substitution rejection (`verify_membership_chain_from_genesis`).
8. Anti-equivocation persistence across simulated validator restarts & fail-closed recovery.

---

## 3. Explorer Proof & Consensus Truthfulness (`TESTED`)

Verified directly via `node --test tests/explorer/integrity_and_crypto.test.mjs` (17/17 passed):
- Missing certificate proofs stay `UNVERIFIED` (never fabricated `VERIFIED`).
- Invalid signatures in `certificate_verifications` or mismatched `network_id` mark node status `INVALID`.
- Insufficient quorum is rejected even when non-empty vote arrays are present.
- `app/api/consensus/route.ts` and `lib/server/snapshot-mapper.ts` surface real QC state without optimistic fallbacks.
