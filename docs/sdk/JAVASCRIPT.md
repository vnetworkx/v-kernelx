# Vector Network JavaScript SDK (`@vnetwork/sdk`)

## Overview

`@vnetwork/sdk` (`sdks/javascript`) provides zero-dependency pure JS BLAKE3 hashing, canonical JSON serialization, RFC 8032 / Node `node:crypto` + browser WebCrypto Ed25519 signing, `.vdx` module bundling, HTTP client, and WebSocket event streaming.

## Modules
- `sdks/javascript/index.js` — Node.js entrypoint (`ClientIdentity`, `VectorNetworkClient`, `bundleVxImports`, `blake3Hex`, `canonicalJsonBytes`).
- `sdks/javascript/browser.js` — Browser ESM build using WebCrypto (`crypto.subtle`) and browser `WebSocket`.

## Quick Start (`examples/javascript/workflow.mjs`)

```bash
VNETWORK_ENDPOINT=http://127.0.0.1:18082 \
VNETWORK_NETWORK_ID=vector-devnet-1 \
node examples/javascript/workflow.mjs
```

```js
import { ClientIdentity, VectorNetworkClient } from "./sdks/javascript/index.js";

const identity = ClientIdentity.generate("js-user");
const client = new VectorNetworkClient("http://127.0.0.1:18082", identity, "vector-devnet-1");
await client.connect();
await client.join(["NETWORK", "SPACE", "REGION", "WALLET", "TOKEN"]);
const submission = await client.submitVxFile("examples/vector-language/complete-network-workflow.vx");
const proof = await client.verifyReconstruction("token", submission.created_entities.find(e => e.kind === "token").id);
```

## Durable request nonces

The Node.js client reserves and writes its next request nonce to a per-network/per-participant file under `~/.vnetwork/nonces` before signing or sending writes. The state is atomically replaced and protected by a file lock, so a lost HTTP response does not cause a restart to reuse a committed nonce. A custom path can be supplied as the fourth constructor argument:

```js
const client = new VectorNetworkClient(endpoint, identity, networkId, "./private/nonces.json");
```

The browser client uses origin-local `localStorage` serialized by the Web Locks API. It fails closed when either facility is unavailable. Browser nonce state is origin-specific and is not shared between different browser profiles or devices.
