# Vector Network TypeScript SDK (`@vnetwork/sdk-ts`)

## Overview

`@vnetwork/sdk-ts` (`sdks/typescript`) provides strictly typed interfaces mirroring Rust `vnetwork-types`, pure TypeScript BLAKE3, canonical JSON, Ed25519 key separation (`ClientIdentity`), Node/Browser transports, and `.vdx` hash-verified bundling.

## Files
- `sdks/typescript/src/types.ts` — Strongly typed structs (`NetworkInfo`, `ProgramSubmission`, `QuorumCertificate`, `LedgerProofReport`, `ReconstructionReport`, `SignedRequestEnvelope`).
- `sdks/typescript/src/client.ts` — `VectorNetworkClient` (`connect`, `join`, `submitProgram`, `submitVxFile`, `submitOperation`, `verifyReconstruction`, `getLedgerProofs`, `subscribeEvents`).
- `sdks/typescript/src/browser.ts` — Browser client.

## Live Workflow (`examples/typescript/workflow.ts`)

```bash
VNETWORK_ENDPOINT=http://127.0.0.1:18083 \
VNETWORK_NETWORK_ID=vnetwork-devnet-1 \
tsx examples/typescript/workflow.ts
```
