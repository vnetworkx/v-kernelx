# 5-Language SDK Conformance & Parity

All 5 SDKs (`sdks/rust`, `sdks/javascript`, `sdks/typescript`, `sdks/python`, `sdks/go`) guarantee deterministic cross-language parity with `vnetwork-types`:
- Single-chunk and multi-chunk BLAKE3 digests (tested on empty, short, and 3000-byte multi-chunk inputs)
- Canonical sorted-key JSON byte serialization without insignificant whitespace
- Ed25519 signing and verification matching `ed25519-dalek`
- Deterministic ID derivation (`prt_`, `nod_`, `wlt_`)

Verified continuously by `tests/cross_language/run_parity.sh` and live multi-node execution via `scripts/test-all-sdks.sh`.
