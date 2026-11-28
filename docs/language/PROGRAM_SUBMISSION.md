# `.vx` Program Submission Lifecycle

## Signed Submission Request (`POST /v1/programs/submit`)
Clients construct a canonical `SubmitProgramRequest` signing over ALL 12 fields:
- `actor_pubkey` (participant Ed25519 public key)
- `compiler_version` (`vectorspace-compiler/1.2.0`)
- `execution_params` (deterministic JSON map)
- `file_kind` (`"VX"` | `"VDX"`)
- `file_name` (`.vx` / `.vdx` filename)
- `language_version` (`v-langx/1.2.0`)
- `modules` (sorted `[path, blake3_hex(content)]` array bound to exact `.vdx` source contents)
- `network_id`
- `nonce` (strictly monotonic per-actor `u64`)
- `protocol_version` (`vector-network/1.0.0`)
- `request_id` (unique replay-protected ID)
- `source_hash` (`blake3_hex(source_bytes)`)

## Deterministic Lifecycle States
1. `RECEIVED` — Envelope, `protocol_version`, `language_version`, `compiler_version`, Ed25519 signature, and replay/nonce checks verified.
2. `COMPILED` — Real `v-langx` frontend compiled source and verified all `.vdx` dependency hashes.
3. `STAGED` — Executed on cloned ledger state without mutating externally visible committed state.
4. `AWAITING_CONSENSUS` — Broadcast as `ConsensusProposal` with the full `ProgramSourceBundle`, the actor's original Ed25519 submitter signature, and `nonce_binding`; the signature is bound into the proposal digest and each validator independently reconstructs/verifies the signed request before recompiling and re-executing.

**Upgrade note:** Proposal version 2 is not wire-compatible with version 1. Upgrade all validators as a coordinated consensus change; do not run a mixed-version validator quorum.
5. `COMMITTED` — Quorum Certificate (`>= 6667 bps` active validator weight with valid epoch & `validator_set_hash`) verified and persisted atomically to the storage WAL before committed state or finality events are published.
6. `REJECTED` / `FAILED` — Zero partial state committed; `failed_operation_index` and structured `error_message` preserved for diagnostics.
