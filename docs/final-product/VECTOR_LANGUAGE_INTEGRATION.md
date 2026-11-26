# Vector Language Integration (`vendor/vectorspace`)

`vendor/vectorspace` (`v-langx` v1.2.0, pinned from upstream commit `1a080053679625c7979416ccecc6f1003c4b2262`) is compiled directly into `vnetwork-core` and `vn` CLI.

- Upstream provenance is documented in `vendor/vectorspace/VENDOR_ORIGIN.md` and inspectable via `scripts/sync-vectorspace.sh`.
- `v-langx` handles tokenization, AST construction, `.vdx` import hash enforcement, `.vdx` declarative purity enforcement, and `CompiledProgram` generation.
- `vnetwork-core` retains sole authority over protocol state, nonces/replay protection, participant permissions, 3D token vector accounting, and consensus proposal construction.
