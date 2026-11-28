# Consensus Invariants — Vector Network

Tracks 2, 3, and 4 establish fail-closed BFT safety and equivocation invariants across `vnetwork-types`, `vnetwork-core`, `vnetwork-consensus`, and `vnetwork-node`.

---

## 1. Canonical Proposal & Vote Binding (`vnetwork/proposal-digest/v1`)

**Proposal version 2 is a coordinated consensus upgrade.** Validators reject version 1 proposals; older binaries reject version 2. Upgrade the validator set as a coordinated change before resuming consensus. Version 2 requires actor-authenticated `.vx` submission signatures in the program-source commitment.

1. Every `ConsensusProposal` MUST compute its 64-hex BLAKE3 `proposal_digest` over canonical JSON (`sort_json_value`) binding:
   - `domain` (`vnetwork/proposal-digest/v1`), `proposal_version`, `protocol_version`
   - `network_id`, `genesis_commitment`, `height`, `round`, `epoch`, `validator_set_hash`, `proposer_validator_id`
   - `parent_commitment`, `pre_state_root`, `post_state_root`, `operation_scope`
   - Ordered `event_ids` and `event_hashes` (exact permutation-sensitive array equality)
   - `program_id`, `tx_id`, `program_source_commitment` (source hash + sorted `.vdx` module hashes + language/compiler versions + submitter signature), `nonce_binding`, `execution_params`, and `timestamp_ms`.
2. `proposal_id` is deterministically derived as `prop_{height}_{proposal_digest}`.
3. Validators independently verify metadata, `genesis_commitment`, active epoch, `validator_set_hash`, proposer eligibility and signature, sequential height (`state.height + 1`), `parent_commitment`, `.vx` submitter-signature verification, source compilation/execution parity, and `post_state_root` before signing any `ConsensusVote`.

---

## 2. Strict Quorum Certificate (QC) Verification (22 Invariants)

`verify_quorum_certificate_strict` rejects any QC failing any of the following checks:

1. Valid non-empty validator set with positive active weight (`validate_validator_set`).
2. `qc.protocol_version == PROTOCOL_VERSION`.
3. Non-empty `qc.network_id` matching `expected_network_id` (when provided).
4. Non-empty `qc.genesis_commitment` matching `expected_genesis_commitment` (when provided).
5. `qc.epoch` matches `expected_epoch` (when provided).
6. Non-empty `qc.validator_set_hash` strictly equal to `validate_validator_set(validators)` (zero empty bypasses).
7. 64-hex `qc.proposal_digest` and matching `qc.proposal_id == prop_{height}_{proposal_digest}`.
8. Non-empty `parent_commitment`, `pre_state_root`, `post_state_root`, and `operation_scope`.
9. `qc.ordered_event_ids.len() == qc.event_hashes.len()`.
10. `qc.quorum_threshold_bps` within `[6667..=10000]` (no lowering/clamping below 2/3+ BFT supermajority).
11. `qc.total_weight` equals sum of active validator weights (checked integer addition).
12. All votes have `vote.approve == true`.
13. Every vote matches all QC fields (`proposal_id`, `proposal_digest`, `network_id`, `genesis_commitment`, `protocol_version`, `height`, `round`, `epoch`, `validator_set_hash`, `parent_commitment`, `pre_state_root`, `post_state_root`, `operation_scope`, `vote_phase`).
14. Every voter belongs to active validator set.
15. No duplicate `validator_id` within `qc.votes`.
16. Canonical 32-byte Ed25519 public key decoding via `canonical_ed25519_pubkey_bytes` (rejects all-zero `[0; 32]`, identity point `[1, 0..]`, and non-canonical points).
17. No duplicate canonical `[u8; 32]` Ed25519 public key across distinct validator IDs in validator set or `qc.votes`.
18. Valid domain-separated Ed25519 signature per vote (`DOM_VOTE_SIGN_V1`).
19. Checked integer accumulation guarantees `qc.approving_weight == verified_weight`.
20. Quorum inequality `(verified_weight as u128) * 10_000 >= (expected_total_weight as u128) * (quorum_threshold_bps as u128)`.
21. All epoch/membership updates form a continuous chain from `genesis.initial_validators` (`verify_membership_chain_from_genesis`) verified by prior-epoch QCs.
22. `EquivocationStore` cross-checks incoming/observed votes and persists cryptographic `EquivocationEvidence` upon slot conflicts.

---

## 3. Durable Fail-Closed Anti-Equivocation Sequence

`EquivocationStore` (`equivocation_votes.wal`, `equivocation_evidence.wal`) keys signing slots by canonical 9-tuple `VoteSlotKey`:
`(network_id, genesis_commitment, validator_id, pubkey_fingerprint, epoch, height, round, vote_phase, protocol_version)`.

1. Before calling any signer, reload and verify every `PersistedVoteRecord` checksum (`DOM_EQUIVOCATION_RECORD_V1`). Corrupt WAL lines fail closed on startup and health checks.
2. Check existing slot record: if any commitment (`proposal_id`, `proposal_digest`, `post_state_root`, `validator_set_hash`, `parent_commitment`, `approve`) differs, refuse signing immediately.
3. If `Signed` record matches the exact same proposal, return the persisted vote idempotently.
4. Otherwise persist and `sync_all()` an `IntentPending` record **before** calling `SigningProvider::sign`.
5. Sign the canonical vote and verify signature; persist and `sync_all()` the `Signed` record **before** broadcasting or returning the vote.
