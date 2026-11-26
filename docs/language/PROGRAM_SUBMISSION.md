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
4. `AWAITING_CONSENSUS` — Broadcast as `ConsensusProposal` with full `ProgramSourceBundle` and `nonce_binding` across validators; each validator independently recompiles and re-executes before voting.
5. `COMMITTED` — Quorum Certificate (`>= 6667 bps` active validator weight with valid epoch & `validator_set_hash`) verified and persisted atomically to the storage WAL before committed state or finality events are published.
6. `REJECTED` / `FAILED` — Zero partial state committed; `failed_operation_index` and structured `error_message` preserved for diagnostics.
