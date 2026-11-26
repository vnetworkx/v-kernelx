# Final Vector Network Architecture

Vector Network (`v-kernelx` v0.2.0) is a multi-node, Byzantine Fault Tolerant (BFT), event-sourced distributed protocol engineered around a single authoritative Rust engine and native **Vector Language (`.vx` / `.vdx`)** integration via `vendor/vectorspace` (`v-langx` v1.2.0).

## Crate & Component Topology

1. **`vendor/vectorspace` (`v-langx` v1.2.0)**: Official Vector Language frontend (lexer, parser, AST, `.vdx` import hash verification, semantic invariant validator, deterministic `CompiledProgram` emitter).
2. **`crates/vnetwork-types`**: Canonical network identity, keypair separation (`NodeKey`, `ParticipantKey`, `WalletKey`, `ValidatorKey`), BLAKE3 helpers, canonical JSON serializer, 3D token vectors `[token, authratio(au), energy]`, and versioned API types.
3. **`crates/vnetwork-core`**: Authoritative protocol state machine, replay verification, challenge-response participant joining, staged atomic `.vx` program execution (`ProgramSourceBundle`), validator re-execution verifier, `vContract` & `vLoan` execution, and deterministic entity reconstruction.
4. **`crates/vnetwork-consensus`**: BFT supermajority quorum (`>= 2/3` weight / `6667` bps), proposer validation, equivocation detection, Quorum Certificate construction, and peer commit batch synchronization.
5. **`crates/vnetwork-storage`**: Append-only hash-verified Event WAL (`events.wal`), Consensus WAL (`consensus_commits.wal`), atomic JSON snapshots, indexed entities, and strict network/profile genesis locks on startup recovery.
6. **`crates/vnetwork-api`**: Versioned HTTP (`/v1/*`, `/healthz`, `/readyz`, `/metrics`) and real-time WebSocket (`/v1/ws`) server with body limits, CORS, rate limiting, and TLS support.
7. **`crates/vnetwork-node` (`vnetwork-node`)**: Full multi-node runtime combining `libp2p` (TCP + Noise + Yamux + Kademlia + Identify + Gossipsub + Request-Response sync + Relay), consensus orchestration, WAL persistence, and the API server.
8. **`crates/vnetwork-cli` (`vn`)**: Developer and operator CLI (`vn identity`, `vn connect`, `vn join`, `vn language`, `vn program submit`, `vn ledger verify`, `vn reconstruct`).
9. **5 Language SDKs (`sdks/{rust,javascript,typescript,python,go}`) + Bindings (`bindings/{node,python}`)**: Lightweight protocol-conformant client libraries with zero re-implemented ledger logic.
10. **Next.js Explorer (`app/`, `components/`, `lib/`)**: Preserved workspace explorer + live read-only network proxy (`/api/explorer`).
