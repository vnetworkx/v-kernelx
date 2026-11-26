# Vector Network (`v-kernelx`)

A complete, deployable, multi-node **Vector Network** powered by a single authoritative Rust execution engine, Byzantine Fault Tolerant (`>= 2/3` quorum) consensus, durable hash-verified WAL storage, `libp2p` P2P discovery & gossip/sync, unified HTTP + WebSocket APIs, `vn` CLI, native **Vector Language (`.vx` / `.vdx`)** via `vendor/vectorspace` (`v-langx` v1.2.0), 5 official language SDKs (**Rust, JavaScript, TypeScript, Python, Go**), and the Next.js Explorer UI.

## Workspace Architecture

- `vendor/vectorspace` (`v-langx` v1.2.0): Vector Language lexer, parser, AST, `.vdx` hash-verified import resolver, semantic invariant validator, and deterministic compiler.
- `crates/vnetwork-types`: Canonical IDs (`prt_*`, `nod_*`, `wlt_*`, `spc_*`, `reg_*`, `tkn_*`, `ctr_*`, `lon_*`), BLAKE3, canonical JSON, Ed25519 key separation, and 3D Token vector invariants `[token, authratio(au), energy]`.
- `crates/vnetwork-core`: Single authoritative state machine, staged atomic `.vx` execution, validator re-execution verifier, `vContract` & `vLoan` execution, and deterministic entity reconstruction.
- `crates/vnetwork-consensus`: BFT supermajority quorum (`6667` bps), equivocation detector, Quorum Certificates, and peer batch synchronization.
- `crates/vnetwork-storage`: Append-only hash-verified Event WAL, Consensus WAL, atomic JSON snapshots, and strict network/profile lock verification.
- `crates/vnetwork-api`: Versioned HTTP (`/v1/*`, `/healthz`, `/readyz`, `/metrics`) and real-time WebSocket (`/v1/ws`) server.
- `crates/vnetwork-node` (`vnetwork-node`): Full P2P (`libp2p` TCP + Noise + Yamux + Kademlia + Identify + Gossipsub + Sync + Relay), consensus, WAL, and API binary.
- `crates/vnetwork-cli` (`vn`): Operator & developer CLI.
- `sdks/{rust,javascript,typescript,python,go}` & `bindings/{node,python}`: Official client SDKs and native FFI/PyO3 bridges.
- `app/`, `components/`, `lib/`: Next.js Explorer + live `/api/explorer` network proxy, alongside preserved top-level `src/*.rs` compatibility facade.

## Quick Verification & Multi-Node Run

```bash
# Run full workspace tests, 5-language parity, 4-node libp2p cluster, BFT fault tolerance, WAL recovery, and all 5 live SDKs:
./scripts/test-network.sh

# Start / inspect / stop a 4-node local devnet:
DEVNET_CLEAN=1 ./scripts/devnet-up.sh
./scripts/health-check.sh
./scripts/test-all-sdks.sh
./scripts/devnet-down.sh
```

See `docs/final-product/FINAL_ARCHITECTURE.md`, `docs/language/`, `docs/sdk/`, and `docs/operations/` for complete reference guides.
