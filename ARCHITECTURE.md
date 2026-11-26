# Vector Network Architecture Guide

See `docs/final-product/FINAL_ARCHITECTURE.md` for the complete system specification.

## Layer Responsibilities

1. **Language Frontend (`vendor/vectorspace`, `v-langx` v1.2.0)**: Parses `.vx` programs and `.vdx` declarative modules, enforces `.vdx` hash pinning and 3D scalar transfer rules, and produces deterministic `CompiledProgram` artifacts (`compiled_program_hash`).
2. **Protocol Authority (`crates/vnetwork-core`)**: Validates participant scopes, nonces, and replay resistance; executes `.vx` operations on cloned state for atomic zero-partial-state rollback; and provides deterministic event-sourced entity reconstruction and ledger proof checks.
3. **BFT Consensus (`crates/vnetwork-consensus`)**: Enforces validator eligibility, independent validator recompilation & re-execution of `ProgramSourceBundle`, equivocation checks, and `>= 2/3` (`6667` bps) Quorum Certificate finality.
4. **Durable Storage (`crates/vnetwork-storage`)**: Maintains append-only `events.wal`, `consensus_commits.wal`, atomic state snapshots, and startup profile/network identity verification.
5. **Multi-Node Networking (`crates/vnetwork-node`)**: Runs `libp2p` discovery/gossip/sync, consensus loops, and public/private API services.
6. **SDKs & Explorer (`sdks/*`, `crates/vnetwork-cli`, `app/*`)**: Thin cryptographic clients with distinct Node, Participant, Wallet, and Validator keys; zero authoritative ledger re-implementation outside Rust.
7. **Legacy Facade (`src/*`, `include/v_kernelx.h`)**: Preserved top-level compatibility crate (`vnetworkx`).
