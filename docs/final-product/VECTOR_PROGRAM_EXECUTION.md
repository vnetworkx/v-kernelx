# Deterministic Vector Program Execution & Consensus Verification

1. Submitters sign canonical `SubmitProgramRequest` payloads containing `source_bytes` and inline `.vdx` module sources (`resolved_module_sources`).
2. The proposing validator verifies non-replay (`request_id` + monotonic `nonce`), compiles via `v_langx::compiler::compile_program`, and executes operations atomically against a **cloned** `NetworkLedgerState`.
3. If any operation fails (e.g., missing balance, dimension violation, unauthorized actor, or forbidden `ATLAS` bootstrap in `PRODUCTION`), zero entity mutations persist, committed `height` and `state_root` remain untouched, and `failed_operation_index` is recorded.
4. On staged success, `ConsensusProposal` carries `ProgramSourceBundle`. Peer validators independently verify `source_hash`, recompile via `v_langx`, match `compiled_program_hash`, re-execute all operations against their local state, and only cast a `ConsensusVote` if `post_state_root` matches bit-for-bit.
