# Vector Network JavaScript SDK (`@vnetwork/sdk`)

## Overview

`@vnetwork/sdk` (`sdks/javascript`) provides zero-dependency pure JS BLAKE3 hashing, canonical JSON serialization, RFC 8032 / Node `node:crypto` + browser WebCrypto Ed25519 signing, `.vdx` module bundling, HTTP client, and WebSocket event streaming.

## Modules
- `sdks/javascript/index.js` — Node.js entrypoint (`ClientIdentity`, `VectorNetworkClient`, `bundleVxImports`, `blake3Hex`, `canonicalJsonBytes`).
- `sdks/javascript/browser.js` — Browser ESM build using WebCrypto (`crypto.subtle`) and browser `WebSocket`.

## Quick Start (`examples/javascript/workflow.mjs`)

```bash
VNETWORK_ENDPOINT=http://127.0.0.1:18082 \
VNETWORK_NETWORK_ID=vnetwork-devnet-1 \
node examples/javascript/workflow.mjs
```

```js
import { ClientIdentity, VectorNetworkClient } from "./sdks/javascript/index.js";

const identity = ClientIdentity.generate("js-user");
const client = new VectorNetworkClient("http://127.0.0.1:18082", identity, "vnetwork-devnet-1");
await client.connect();
await client.join(["NETWORK", "SPACE", "REGION", "WALLET", "TOKEN"]);
const submission = await client.submitVxFile("examples/vector-language/complete-network-workflow.vx");
const proof = await client.verifyReconstruction("token", submission.created_entities.find(e => e.kind === "token").id);
```
