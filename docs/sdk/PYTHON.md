# Vector Network Python SDK (`vnetwork_sdk`)

## Overview

`vnetwork_sdk` (`sdks/python`) is a self-contained Python 3.11+ SDK implementing pure Python BLAKE3, RFC 8032 Ed25519 (with optional `vnetwork_native` PyO3 acceleration via `bindings/python`), canonical JSON serialization, `.vdx` import resolution, HTTP transport, and RFC 6455 WebSocket event streaming using Python standard library modules (`urllib`, `socket`, `hashlib`, `hmac`).

## Live Workflow (`examples/python/workflow.py`)

```bash
VNETWORK_ENDPOINT=http://127.0.0.1:18081 \
VNETWORK_NETWORK_ID=vnetwork-devnet-1 \
python3 examples/python/workflow.py
```

```python
from vnetwork_sdk import ClientIdentity, VectorNetworkClient

identity = ClientIdentity.generate("py-participant")
client = VectorNetworkClient("http://127.0.0.1:18081", identity, expected_network_id="vnetwork-devnet-1")
client.connect()
client.join(["NETWORK", "SPACE", "REGION", "WALLET", "TOKEN"])
sub = client.submit_vx_file("examples/vector-language/create-token.vx")
print(sub["status"], sub["final_state_root"])
```
