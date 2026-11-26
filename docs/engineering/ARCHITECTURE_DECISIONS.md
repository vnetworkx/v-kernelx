# Architecture Decisions — Vector Network (`v-kernelx`)

## ADR-001: Single Authoritative Rust State Machine
All state transitions, token conservation checks, multi-key wallet authorizations, `.vx`/`.vdx` compilation, consensus proposal validation, and replay verification execute exclusively inside Rust (`crates/vnetwork-core`, `crates/vnetwork-consensus`, `vendor/vectorspace`). JavaScript, TypeScript, Python, Go SDKs, and the Next.js Explorer are strictly thin cryptographic clients or read-only API/HTTP proxies.

## ADR-002: Transactional Commit Journal Before Finality Emission
Nodes never mutate externally visible `shared_state`, emit `CONSENSUS_FINALITY` WebSocket events, return `COMMITTED` HTTP responses, or broadcast `QuorumCertificate`s before durable journal commit succeeds (`sync_all` across WALs and commit marker). Recovery reconstructs exclusively from verified `ConsensusProposal + QuorumCertificate` records matched against genesis commitment and validator sets; uncertified tail events are never promoted to committed state.

## ADR-003: Canonical 3-Dimensional Token Model & Fixed-Point Determinism
Tokens use `TokenVector { token: u128, auth_ratio_au: u128, energy: u128 }`. Transfers mutate only dimension 0 (`token`). Recipient wallets without an existing balance record start at `[0, 0, 0]`; `auth_ratio_au` and `energy` changes require dedicated authorized operations. No floating-point (`f32`/`f64`) types are permitted anywhere in canonical state, compiler ratio evaluation, transfers, drains, contracts, or loans. Explicit `max_supply == 0` denotes uncapped/unlimited supply when declared; any positive `max_supply > 0` rejects `initial_supply > max_supply` or mints exceeding `max_supply` without silent clamping.

## ADR-004: Complete Request & Proposal Canonical Signing Bindings
- `SubmitProgramRequest` canonical signing binds `{actor_pubkey, compiler_version, execution_params, file_kind, file_name, language_version, modules (path -> blake3 hash), network_id, nonce, protocol_version, request_id, source_hash}`.
- `ConsensusProposal` canonical signing binds `program_source_bundle` (hashes) and `nonce_binding` alongside block header fields and event hashes.
- Wallet key authorization supports challenge-response proof of possession signed by the newly added `authorized_pubkey` over `{network_id, wallet_id, participant_identity, authorized_pubkey, purpose, nonce, expires_at_ms, protocol_version}`.

## ADR-005: Protocol Version Consistency (`vector-network/1.0.0`)
All Rust crates, configuration schemas, Docker/Compose manifests, and all 5 SDKs standardize on `PROTOCOL_VERSION = "vector-network/1.0.0"`.
