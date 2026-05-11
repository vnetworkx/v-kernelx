# v-kernelx

`v-kernelx` is a multi-runtime vector ledger prototype. The repo keeps one canonical state model and reuses it across:

- Rust core engine and rules
- TypeScript SDK/runtime
- Python simulation and developer tooling

The shared canonical schema is `v.kernelx/VectorStateV1`.

## What the system does

A wallet owns a vector, and every operation updates that vector through a state machine. The core lifecycle is:

1. **Origin creation**: a new vector is created only after proof-style work succeeds.
2. **Certification**: the vector is checked against the network’s auth rules.
3. **Transfer**: vector components move from one wallet to another.
4. **Drain**: a protocol fee is removed before or during movement.
5. **Projection**: part of the vector is locked into escrow/risk logic.
6. **Reconstruction**: projected value settles back into the wallet with gains or losses.
7. **Recordkeeping**: every state change creates an immutable vector record.
8. **Querying**: the current state and history can be read back through the SDKs and interpreter.

Zero vectors are guarded during normalization, so normalization is never attempted on an all-zero state.

## Canonical state model

Every runtime uses the same fields conceptually:

- `schema`
- `vector_id`
- `owner_pubkey`
- `space_id`
- `vector_type`
- `status`
- `components`
- `type_metadata`
- `certification`
- `projection`
- `origin`
- `version`
- `created_at_ms`
- `updated_at_ms`

The record format is also shared:

`R = (before, after, operation, parameters, certification, timestamp_ms, proof)`

## Runtime roles

### Rust
The Rust crate is the closest thing to the reference implementation. It defines the state structs, validation helpers, record hashes, consensus filter, execution engine, interpreter, and SDK wrapper.

### TypeScript
The TypeScript layer mirrors the same state model for client-side usage and scripted demos.

### Python
The Python package is a simulation harness and reference workflow runner. It is useful for fast iteration and smoke testing.

## How the flow works

### 1. Origin creation
The origin engine verifies a nonce against a seed and difficulty. In the current implementation, the proof is a SHA-256 hash of `seed:nonce`, and the runtime searches for a nonce when a test or demo needs a guaranteed valid origin.

### 2. Certification
Certification computes an auth ratio from the state and marks the vector certified when the ratio meets or exceeds the threshold. In the current code, a valid owner public key is the primary signal and the threshold defaults to `700`.

### 3. Transfer
Transfer requires matching dimensions. The sender loses exactly the transferred components and the receiver gains the same components.

### 4. Drain
Drain applies a basis-point fee. Certified vectors can receive a reduced effective drain rate.

### 5. Projection
Projection moves a chosen slice into escrow, stores the escrow metadata, and changes the vector type/status to projected.

### 6. Reconstruction
Reconstruction validates the projected slice, applies gains and losses, appends the settled value back into the vector, and marks the state as settled.

### 7. Records
Every mutation creates a record with before/after snapshots and a proof hash so the history can be audited.

### 8. Query and script execution
The kernel exposes direct query methods and a small opcode interpreter so scripts can drive the same operations.

## Formal test suite plan

The test strategy is split into five layers so the same behavior is checked at the state, operation, record, storage, and runtime levels.

### A. Canonical model tests
These verify the immutable shape of `VectorStateV1` and `VectorRecordV1`.

Coverage:
- schema constant is correct
- magnitude is the sum of components
- direction shares are computed correctly
- zero vectors reject normalization
- default certification fields are initialized correctly

### B. Validation tests
These verify the rule engine rejects invalid inputs before state changes happen.

Coverage:
- empty vectors are rejected
- missing IDs are rejected
- dimension mismatch is rejected
- insufficient balance is rejected
- zero normalization is rejected
- invalid origin proof is rejected

### C. Operation tests
These verify each state transition works and preserves accounting integrity.

Coverage:
- origin creation
- transfer out/in symmetry
- drain calculations
- projection escrow setup
- reconstruction settlement
- certification refresh after each mutation

Assertions:
- no component is created or destroyed except by the explicit operation
- transfer is value-preserving across sender and receiver
- drain reduces total magnitude by the expected basis-point amount
- reconstruction appends the settled value and stores settlement metadata

### D. Record and storage tests
These verify all mutations generate immutable records and can be queried back.

Coverage:
- record count increases after operations
- record proof hashes are stable for a given snapshot
- before/after snapshots serialize correctly
- query APIs return the current state and history
- in-memory store round-trips states and records

### E. Interpreter and SDK tests
These verify the script interface and public API behave the same as the direct engine calls.

Coverage:
- opcode parsing
- script dispatch
- query opcode output
- SDK wrapper methods
- simulation harness flow

### F. Cross-runtime parity tests
These verify Rust, TypeScript, and Python are doing the same logical work.

Coverage:
- canonical schema name matches in all runtimes
- same field names and enum values are used
- origin proof search behaves consistently
- end-to-end smoke flow produces the same operation sequence

## Test files in this repo

- `tests/smoke.rs` — Rust smoke test
- `python/tests/test_kernel.py` — Python smoke test
- `ts/tests/smoke.test.ts` — TypeScript smoke test

## How to run the tests

### Rust
From the repository root:

```bash
cargo test
```

### Python
From `python/`:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

### TypeScript
From `ts/` on Node 22.16+:

```bash
npm test
```

The TypeScript test script uses Node's native TypeScript stripping mode to run the `.ts` test file directly.

## File map

- `src/` — Rust core modules
- `ts/src/` — TypeScript SDK/runtime
- `python/v_kernelx/` — Python simulation package
- `tests/` — Rust smoke tests
- `python/tests/` — Python smoke tests
- `ts/tests/` — TypeScript smoke tests

## Notes

The repo currently uses in-memory storage. If you later add disk persistence or network consensus, the same canonical state format can stay unchanged and the test matrix can be extended with persistence and multi-node integration cases.
