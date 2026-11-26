# Vector Network Go SDK (`github.com/vnetworkx/vnetwork-sdk-go`)

## Overview

The Go SDK (`sdks/go`) uses pure Go standard library (`crypto/ed25519`, `net/http`, RFC 6455 `net` WebSocket client) paired with a byte-exact BLAKE3 implementation (`blake3.go`) and deterministic canonical JSON serializer (`canonical.go`) verified via `tests/cross_language/run_parity.sh`.

## Live Workflow (`examples/go/main.go`)

```bash
VNETWORK_ENDPOINT=http://127.0.0.1:18082 \
VNETWORK_NETWORK_ID=vector-devnet-1 \
go -C examples/go run .
```

## Core Methods
- `vnetwork.GenerateIdentity(label)` — creates separate Ed25519 `ParticipantKey` and `NodeKey`.
- `client.Connect()` — checks `/v1/network/info` compatibility.
- `client.Join(scopes)` — dual-signed challenge-response network participation join.
- `client.SubmitProgram(fileName, source, modules)` / `client.SubmitVxFile(path)` — resolves `.vdx` imports, computes BLAKE3 hashes, signs, and submits `.vx` program to BFT consensus.
- `client.VerifyReconstruction(kind, id)` — validates deterministic event-sourced entity reconstruction.
