# Vector Network Rust SDK (`vnetwork-sdk`)

## Overview

`vnetwork-sdk` (`sdks/rust`) is the official Rust client for connecting to Vector Network nodes, verifying network profiles, performing challenge-response participant onboarding, compiling/submitting `.vx`/`.vdx` programs, signing transactions, subscribing to WebSocket events, and verifying entity reconstruction.

## Installation & Build

Add `vnetwork-sdk` to your workspace or `Cargo.toml`:

```toml
[dependencies]
vnetwork-sdk = { path = "../../sdks/rust" }
vnetwork-types = { path = "../../crates/vnetwork-types" }
```

## Key Separation

`ClientIdentity::generate("label")` creates two independent Ed25519 keypairs:
- `participant_key`: signs participant join handshakes, `.vx` submissions, and protocol envelopes (`prt_*`).
- `node_key`: identifies the local node identity (`nod_*`), never conflated with wallet or validator keys.

## Live Workflow (`examples/rust/src/main.rs`)

```bash
VNETWORK_ENDPOINT=http://127.0.0.1:18081 \
VNETWORK_NETWORK_ID=vector-devnet-1 \
cargo run --manifest-path examples/rust/Cargo.toml
```

### Core Methods
- `client.connect()` — fetches `/v1/network/info` and enforces expected `network_id` and `protocol_version`.
- `client.join(scopes)` — fetches `/v1/participation/challenge`, signs canonical join payload with both participant + node keys, and submits `/v1/participation/join`.
- `client.submit_vx_file(path)` / `client.submit_program(name, src, modules)` — resolves pinned `.vdx` imports, verifies local BLAKE3 hashes, signs, and submits `/v1/programs/submit`.
- `client.verify_reconstruction(kind, id)` — verifies `/v1/reconstruct/{kind}/{id}` proof equivalence.
- `client.subscribe_events()` — connects to `/v1/ws` WebSocket feed.

## Durable request nonces

The Rust client persists request nonce reservations per network and participant under `~/.vnetwork/nonces` before signing and sending writes. Use `reserve_nonce()` when constructing custom signed requests; it returns storage errors rather than silently reusing an in-memory value. A custom nonce file can be selected with `with_nonce_store(path)`. The legacy `next_nonce()` method remains for source compatibility and panics if durable reservation fails.
