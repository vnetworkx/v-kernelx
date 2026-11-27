# Vector Network TypeScript SDK (`@vnetwork/ts-sdk`)

## Overview

`@vnetwork/ts-sdk` (`sdks/typescript`) provides strictly typed interfaces mirroring Rust `vnetwork-types`, pure TypeScript BLAKE3, canonical JSON, Ed25519 key separation (`ClientIdentity`), Node/Browser transports, and `.vdx` hash-verified bundling. Protocol version is `vector-network/1.0.0`.

## Files
- `sdks/typescript/src/types.ts` — Strongly typed structs (`NetworkInfo`, `ProgramSubmission`, `QuorumCertificate`, `LedgerProofReport`, `ReconstructionReport`, `SignedRequestEnvelope`).
- `sdks/typescript/src/client.ts` — `VectorNetworkClient` (`connect`, `join`, `submitProgram`, `submitVxFile`, `submitOperation`, `verifyReconstruction`, `getLedgerProofs`, `subscribeEvents`).
- `sdks/typescript/src/browser.ts` — Browser client.

## Live Workflow (`examples/typescript/workflow.ts`)

```bash
VNETWORK_ENDPOINT=http://127.0.0.1:18083 \
VNETWORK_NETWORK_ID=vector-devnet-1 \
node --experimental-strip-types examples/typescript/workflow.ts
```

## Durable request nonces

The Node client persists per-network/per-participant nonce reservations under `~/.vnetwork/nonces` before sending a signed write. Supply an optional fourth constructor argument to select a custom nonce file. The browser client persists state in origin-local `localStorage` and uses Web Locks to serialize tabs; it refuses writes if persistent storage or Web Locks are unavailable.
