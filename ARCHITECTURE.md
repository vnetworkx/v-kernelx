# Architecture Guide

This document is the permanent editing guide for `v-kernelx/`.

It explains what each file owns, what should be edited there, and how changes should stay consistent across the Rust kernel, Python simulator, and TypeScript SDK.

---

## 1) Project purpose

`v-kernelx` is organized as a protocol kernel with three aligned layers:

- **Rust**: the canonical kernel, state machine, validation, storage, and test surface
- **Python**: the simulation and mathematical mirror used for experiments and tests
- **TypeScript**: the SDK/runtime-facing client layer and compatibility surface

The core editing rule is simple:

> When protocol behavior changes, update all affected layers so they stay aligned.

---

## 2) Repository layout

```text
v-kernelx/
├── Cargo.toml
├── README.md
├── tests/
│   └── smoke.rs
├── src/
│   ├── lib.rs
│   ├── error.rs
│   ├── state.rs
│   ├── wallet.rs
│   ├── validation.rs
│   ├── certification.rs
│   ├── record.rs
│   ├── storage.rs
│   ├── drain.rs
│   ├── projection.rs
│   ├── reconstruction.rs
│   ├── origin.rs
│   ├── consensus.rs
│   ├── query.rs
│   ├── transfer.rs
│   ├── engine.rs
│   ├── interpreter.rs
│   ├── sdk.rs
│   └── developer.rs
├── python/
│   ├── tests/
│   │   └── test_kernel.py
│   └── v_kernelx/
│       ├── __init__.py
│       ├── model.py
│       ├── engine.py
│       ├── simulation.py
│       └── tools.py
└── ts/
    ├── package.json
    ├── tsconfig.json
    ├── tests/
    │   └── smoke.test.ts
    └── src/
        ├── types.ts
        ├── client.ts
        ├── index.ts
        └── node-shims.d.ts
```

---

## 3) What each part owns

### Top-level files

#### `Cargo.toml`
Rust package definition and build configuration.

Owns:
- crate name
- dependencies
- edition
- test/build settings

Edit this when you add or change Rust dependencies, runtime support, or package settings.

#### `README.md`
Human-facing project overview and usage guide.

Owns:
- what the network is
- how to run tests
- how the state machine works
- how to use the repo

Update this whenever the architecture, setup, or public behavior changes.

---

### Rust tests

#### `tests/smoke.rs`
Rust end-to-end smoke test.

Owns:
- origin creation
- transfer
- drain
- projection
- reconstruction
- records

Edit this when operation behavior changes or new failure cases need coverage.

---

### Rust core: `src/`

The Rust source tree is the canonical kernel implementation.

#### `src/lib.rs`
Rust library entry point.

Owns:
- module exports
- public crate API
- top-level wiring

Edit this when adding modules or changing what external users import.

#### `src/error.rs`
Kernel error definitions.

Owns:
- error types
- error conversion
- protocol failure categories

Edit this when new failure modes need explicit representation.

#### `src/state.rs`
Canonical vector state model.

Owns:
- vector components
- magnitude
- direction/composition
- type tags
- zero-vector behavior
- canonical state struct

This is the source of truth for “what a vector is” in the network.

#### `src/wallet.rs`
Wallet identity and ownership logic.

Owns:
- wallet binding
- public key ownership
- wallet metadata
- owner verification flow

Edit this when wallet structure, ownership, or recovery rules change.

#### `src/validation.rs`
Validation and rejection rules.

Owns:
- structural validity
- type compatibility
- zero-vector safety
- bounds
- operation legality

Edit this when you add or tighten pre-execution checks.

#### `src/certification.rs`
Certification and AuthRatio gate.

Owns:
- certification threshold logic
- validity scoring
- restricted operation gating

Edit this when certification scoring, thresholds, or proof factors change.

#### `src/record.rs`
Immutable record engine.

Owns:
- before/after state records
- operation logs
- hash-linked record entries
- proof metadata

Edit this when record format, ledger schema, or audit fields change.

#### `src/storage.rs`
Persistence abstraction.

Owns:
- storing state
- loading records
- persistence interfaces

Edit this when introducing durable storage, schema changes, or sync methods.

#### `src/drain.rs`
Fee and cost logic.

Owns:
- drain calculation
- effective drain after credits
- value reduction before or during operations

Edit this when network cost rules change.

#### `src/projection.rs`
Projection, escrow, and risk-split logic.

Owns:
- splitting a vector into projected and remainder parts
- locking projected value
- policy-based projection behavior

Edit this when projection ratios, escrow rules, or pool behavior change.

#### `src/reconstruction.rs`
Settlement and reconstruction logic.

Owns:
- returning projected value
- applying gains or losses
- restoring final state after settlement

Edit this when settlement formulas or partial-loss behavior change.

#### `src/origin.rs`
Vector origin / minting engine.

Owns:
- origin creation
- proof/nonce validation
- minting flow
- initial certification path

Edit this when creation rules, anti-inflation constraints, or challenge logic change.

#### `src/consensus.rs`
Acceptance and agreement layer.

Owns:
- final state acceptance rules
- record acceptance
- deterministic convergence logic

Edit this when you add node agreement, conflict resolution, or record ordering rules.

#### `src/query.rs`
Read-only access layer.

Owns:
- wallet lookups
- record queries
- certification checks
- state inspection

This file should not mutate state.

#### `src/transfer.rs`
Transfer logic.

Owns:
- moving value from one vector to another
- source subtraction
- destination addition
- drain-aware movement

Edit this when transfer formulas or routing behavior change.

#### `src/engine.rs`
State machine coordinator.

Owns:
- receiving operations
- validating them
- calling the correct module
- updating state
- writing records

This is the central orchestration layer.

#### `src/interpreter.rs`
Opcode / runtime interface.

Owns:
- command interpretation
- runtime hooks
- execution entry points

Edit this when building a higher-level language or scripted execution flow.

#### `src/sdk.rs`
Rust SDK contract layer.

Owns:
- safe wrappers
- client-facing API behavior
- protocol-facing helpers

Edit this when public Rust client APIs change.

#### `src/developer.rs`
Developer tooling support.

Owns:
- simulation helpers
- debug helpers
- testing utilities
- CLI-adjacent support

Use this for internal tooling rather than protocol rules.

---

### Python simulation layer

The Python package mirrors the kernel for simulation, math checking, and testability.

#### `python/v_kernelx/model.py`
Canonical Python model.

Owns:
- vector and record structures
- canonical state mirror
- zero-vector handling

This should track `src/state.rs`.

#### `python/v_kernelx/engine.py`
Python simulation engine.

Owns:
- origin
- transfer
- drain
- project
- reconstruct
- record creation

Edit this when protocol behavior changes and the Python mirror must stay in sync.

#### `python/v_kernelx/simulation.py`
Demo and smoke-flow script.

Owns:
- full protocol scenario
- sample operations
- example outputs

Use this for demonstrations or manual verification of specific rules.

#### `python/v_kernelx/tools.py`
Helper utilities.

Owns:
- validation helpers
- proof helpers
- formatting helpers
- math helpers

Keep shared support logic here instead of duplicating it in tests or engine code.

#### `python/tests/test_kernel.py`
Python test suite.

Owns:
- simulation behavior
- vector rules
- edge-case rejection

Edit this when the protocol changes or new Python-visible behavior is added.

---

### TypeScript SDK layer

The TypeScript package mirrors the public contract and runtime-facing types.

#### `ts/src/types.ts`
Canonical TypeScript types.

Owns:
- vector types
- record types
- request/response shapes

This should mirror the Rust and Python models.

#### `ts/src/client.ts`
TypeScript client implementation.

Owns:
- engine calls
- operation helpers
- typed request flow

Edit this when SDK behavior or request shapes change.

#### `ts/src/index.ts`
TypeScript export surface.

Owns:
- public SDK exports
- simulation helpers
- client APIs

Edit this when you add or remove package exports.

#### `ts/src/node-shims.d.ts`
Node environment support.

Owns:
- compatibility typing for Node runtime use

Usually this file changes only for runtime compatibility work.

#### `ts/tests/smoke.test.ts`
TypeScript smoke test.

Owns:
- end-to-end flow
- zero-vector safety
- runtime compatibility

Edit this when SDK behavior or type rules change.

---

## 4) Change map: where to edit for common changes

Use this section as the primary navigation guide.

### Change the math or canonical state
Update:
- `src/state.rs`
- `python/v_kernelx/model.py`
- `ts/src/types.ts`

### Change legality or rejection rules
Update:
- `src/validation.rs`

### Change certification or AuthRatio
Update:
- `src/certification.rs`

### Change minting or origin behavior
Update:
- `src/origin.rs`

### Change transfer behavior
Update:
- `src/transfer.rs`

### Change fees or drain
Update:
- `src/drain.rs`

### Change projection or settlement
Update:
- `src/projection.rs`
- `src/reconstruction.rs`

### Change record format
Update:
- `src/record.rs`

### Change orchestration
Update:
- `src/engine.rs`

### Change public SDK behavior
Update:
- `src/sdk.rs`
- `ts/src/client.ts`

### Change simulator behavior
Update:
- `python/v_kernelx/engine.py`

### Change tests
Update:
- `tests/smoke.rs`
- `python/tests/test_kernel.py`
- `ts/tests/smoke.test.ts`

---

## 5) Safe editing rule

When one protocol rule changes, update all three layers that represent it:

- **Rust kernel**: canonical behavior
- **Python simulator**: mirrored behavior
- **TypeScript SDK/runtime**: public contract and client behavior

That is the fastest way to avoid drift between implementations.

---

## 6) Suggested editing order

When making a protocol change, edit in this order:

1. Canonical Rust module
2. Rust smoke test
3. Python mirror and tests
4. TypeScript types/client/tests
5. README and architecture notes if the public behavior changed

This keeps the source of truth aligned before changing downstream mirrors.

---

## 7) Guiding principles

- Keep canonical state and rules in Rust.
- Mirror behavior in Python and TypeScript.
- Put validation before execution.
- Keep read-only code side-effect free.
- Keep record generation deterministic.
- Update smoke tests whenever behavior changes.
- Prefer small, localized changes over cross-cutting edits.

---

## 8) Maintenance note

This file should be updated whenever:
- a new module is added
- a module changes responsibility
- a rule moves from one file to another
- the Rust, Python, or TypeScript models diverge in shape or behavior

Treat this file as the first stop before editing the codebase.
