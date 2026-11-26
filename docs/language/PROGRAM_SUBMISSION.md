# `.vx` Program Submission Lifecycle

## Signed Submission Request (`POST /v1/programs/submit`)
Clients construct a canonical `SubmitProgramRequest` containing:
- `file_name` (`.vx`), `source_bytes`, and `modules` (`map<path, source_text>` for all imported `.vdx` files)
- `actor_pubkey` (participant Ed25519 public key)
- `network_id`, `request_id` (unique replay-protected ID), and monotonic `nonce`
- `signature` (Ed25519 signature over canonical request bytes)

## Deterministic Lifecycle States
1. `RECEIVED` — Envelope verified and replay/nonce validated.
2. `COMPILED` — Real `v-langx` frontend compiled source and verified all `.vdx` hashes.
3. `STAGED` — Executed on cloned ledger state without mutating committed state.
4. `AWAITING_CONSENSUS` — Broadcast as `ConsensusProposal` with `ProgramSourceBundle` across libp2p validators.
5. `COMMITTED` — Quorum Certificate (`>= 6667 bps` / `2/3` supermajority) finalized and persisted to WAL.
6. `REJECTED` / `FAILED` — Zero partial state committed; `failed_operation_index` and `error_message` preserved for diagnostics.
