# v-kernelx

`v-kernelx` is the Rust-first kernel for the Vector Network prototype. The repository keeps one canonical state model and mirrors it in TypeScript and Python so the same protocol flow can be exercised in three runtimes.

Canonical schema:

- `v.kernelx/VectorStateV1`
- `v.kernelx/VectorRecordV1`

## What the kernel does

The kernel is the source of truth for the protocol lifecycle:

1. **Create** a new origin vector after proof-of-work style origin validation.
2. **Certify** the state against the network’s validity rules.
3. **Transfer** value between wallets or spaces.
4. **Drain** a protocol fee or movement cost.
5. **Project** part of a vector into escrow or a contract-like environment.
6. **Reconstruct** the settled value back into the wallet.
7. **Record** every successful state mutation as an immutable ledger entry.
8. **Query** live state and history without mutating the ledger.

## Canonical state format

The repository uses one shared runtime model across Rust, TypeScript, and Python.

### Vector state

```text
V = (schema, vector_id, owner_pubkey, space_id, vector_type, status,
     components, type_metadata, certification, projection, origin,
     version, created_at_ms, updated_at_ms)
```

### Record state

```text
R = (schema, record_id, vector_id, before, after, operation,
     parameters, certification, timestamp_ms, proof)
```

### Blueprint mapping

The blueprint’s `tau` operational tag is represented in the implementation by `vector_type`, and additional protocol metadata lives in `type_metadata`.

## Mathematical rules

- `magnitude` is the sum of all components.
- `direction_shares` returns the normalized component ratios.
- Zero vectors are safe to store, but normalization is rejected.
- Drain uses a basis-point reduction.
- Projection subtracts the projected slice and stores it in escrow metadata.
- Reconstruction restores the settled result back into the remaining state.

## How the flow works

### Create
The origin engine checks a nonce against a seed and difficulty. If the proof hash satisfies the difficulty, the vector enters the network as an origin vector.

### Certify
Certification computes an auth ratio and marks the state certified when the threshold is met. The current prototype uses a fixed-point ratio in the `0..=1000` range so it can be shared cleanly between Rust, Python, and TypeScript.

### Transfer
Transfer requires matching dimensions. The sender loses the requested amount and the receiver gains the same amount.

### Drain
Drain applies a basis-point fee. Certified vectors receive a reduced effective drain rate in the current prototype.

### Projection
Projection removes the projected slice from the live balance and stores the escrow state in `projection`.

### Reconstruction
Reconstruction settles the projected slice and adds the settled result back into the remaining vector state without changing the component count.

### Records
Every successful mutation writes a record with before/after snapshots and a proof hash.

### Queries and scripts
The kernel exposes direct query methods plus a compact opcode interpreter so scripts can run the same state transitions.

## Repository layout

- `src/` — Rust kernel, validation, records, storage, SDK, interpreter
- `ts/src/` — TypeScript mirror of the canonical model and smoke runner
- `python/v_kernelx/` — Python simulation harness and smoke runner
- `tests/` — Rust smoke tests
- `ts/tests/` — TypeScript smoke tests
- `python/tests/` — Python smoke tests

## Formal test suite plan

The project is tested in layers so the same protocol rules are checked from the model outward.

### 1. Canonical model tests
These verify the shared state shape and math.

Checks:
- schema constant matches `v.kernelx/VectorStateV1`
- magnitude is a component sum
- direction shares are correct for non-zero vectors
- normalization rejects the zero vector
- record schema is stable

### 2. Validation tests
These verify invalid inputs fail before mutation.

Checks:
- missing IDs are rejected
- empty component vectors are rejected
- dimension mismatch is rejected
- over-transfer is rejected
- over-projection is rejected
- oversized drain values are rejected
- invalid origin proof is rejected

### 3. Operation tests
These verify each state transition preserves accounting.

Checks:
- origin creation produces a certified origin state
- transfer subtracts and adds matching amounts
- drain reduces balance by the expected basis-point amount
- projection stores escrow metadata and reduces the live balance
- reconstruction restores settled value without changing vector length

### 4. Record and storage tests
These verify history and persistence behavior.

Checks:
- every successful mutation appends a record
- record IDs are stable for the same logical payload
- proof hashes are content-derived
- query APIs can read current state and history
- in-memory storage round-trips states and records

### 5. Interpreter and SDK tests
These verify script-driven execution matches direct method calls.

Checks:
- opcode parsing
- origin, transfer, drain, project, reconstruct, certify, query dispatch
- SDK wrappers call the same engine logic
- smoke flow is reproducible across runtimes

### 6. Cross-runtime parity tests
These verify Rust, TypeScript, and Python stay aligned.

Checks:
- shared schema names match
- same canonical field names are present
- zero-vector guards behave the same way
- the smoke flow uses the same operation sequence

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

## Notes on the current prototype

- Storage is in-memory.
- Consensus is a simple acceptance filter, not a full distributed protocol.
- Timestamps are local execution timestamps.
- The canonical state model is stable, but the higher layers are still prototype-grade and meant for simulation, SDK work, and kernel validation.
