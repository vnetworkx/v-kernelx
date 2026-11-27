# Vendored VectorSpace (`v-langx`) Origin & Synchronization

- **Upstream Repository**: `https://github.com/vnetworkx/vectorspace`
- **Pinned Upstream Commit**: `1a080053679625c7979416ccecc6f1003c4b2262`
- **Base Upstream Version**: `1.1.0` (`v-langx`)
- **Integrated Workspace Version**: `1.2.0` (extended with Network AST nodes, `.vdx` content-hashed imports, line/column spans, semantic/permission validation, and deterministic `CompiledProgram` output)

## Separation of Responsibilities

`vendor/vectorspace` (`v_langx`) is strictly the **language frontend**:

> **Security boundary:** the frontend's local event demo uses FNV-1a-128 and placeholder `signature` fields. They are deterministic checksums, not cryptographic signatures, actor authentication, or consensus proofs. The frontend is not an authoritative ledger or durable store. Production signatures, authorization, replay protection, persistence, and finality are provided only by the kernel / consensus / storage layers.
- Source loading, lexing, parsing, AST, semantic validation, type checking, `.vdx` import hash verification, and deterministic compilation into `CompiledProgram`.
- It is **never** an authoritative network or ledger. All compiled operations are revalidated, authorized, and committed through `vnetwork-core` + `vnetwork-consensus`.

## Upgrading from Upstream

Run `./scripts/sync-vectorspace.sh <commit-or-tag>` to inspect upstream diffs against `1a080053679625c7979416ccecc6f1003c4b2262` and merge updates cleanly.
