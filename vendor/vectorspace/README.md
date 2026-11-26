# Vector Space / v-langx

Native Vector Language implementation for the Vector Network.

Vector Space is the user-facing language layer for a deterministic, replayable, vector-native protocol system. It is built to compile directly into kernel operations and to preserve every successful state transition as immutable event history.

This repository includes:

- a working Rust parser, compiler, and interpreter
- a deterministic kernel execution model
- immutable event recording
- a Tree-sitter grammar for editor tooling
- a canonical LALRPOP grammar for future parser generation
- a Python prototype compiler / parser test harness
- `.vx` and `.vdx` source examples

---

## What Vector Language is

Vector Language is the control language for the Vector Network.

It is designed for developers, contracts, explorers, wallets, tooling, and higher-level network applications that need to express vector state changes in a human-readable form while still compiling into deterministic kernel operations.

The language is not a separate source of truth. It is an interface to the kernel.

The kernel remains authoritative, and all live state is derived from immutable event history.

---

## File extensions

Vector Space uses two source extensions:

- `.vx` — executable Vector Language program
- `.vdx` — Vector Data / declaration module

Both extensions use the same language core. The difference is semantic:

- `.vx` is typically used for runnable workflows
- `.vdx` is typically used for reusable declarations, policy fragments, and contract payloads

---

## Design goals

Vector Language is intended to be:

- deterministic
- replayable
- human-readable
- strict about validation
- explicit about state mutation
- compatible with immutable event storage
- usable from both terminals and editor tooling
- simple enough to compile directly into network operations

A valid program should always mean the same thing on every honest node.

---

## Supported statements

The core implementation supports these statement families:

- `vector`
- `wallet`
- `certify`
- `transfer`
- `drain`
- `project`
- `reconstruct`
- `query`
- `record`
- `contract { action ...; }`

### Example

```vx
vector treasury: free = (100, 25, 0);
wallet treasury_owner = bind(pk_treasury);
certify treasury with ctx(space="global", op="transfer", risk="normal");
transfer treasury to reserve amount 10;
project treasury into staking_pool amount 20 policy staking_v1;
reconstruct treasury from proj_001;
query treasury.certification;
````

---

## Core semantics

The language follows a few non-negotiable rules:

* all vector components are nonnegative unless a separate debt model is explicitly introduced
* zero normalization is invalid unless handled by a dedicated rule
* every successful state-changing action produces a record
* mutable live state is derived, not authoritative
* queries do not mutate history
* contract actions compile to explicit kernel operations
* every valid operation must be deterministic and replayable

These rules are aligned with the Vector Network protocol design, where the event graph is the source of truth and snapshots or caches are only acceleration structures.

---

## Repository layout

```text
vectorspace/
├── Cargo.toml
├── README.md
├── grammar/
│   └── vector.lalrpop
├── examples/
│   ├── treasury.vx
│   ├── policy.vdx
│   └── contracts.vx
├── src/
│   ├── ast.rs
│   ├── compiler.rs
│   ├── error.rs
│   ├── event.rs
│   ├── kernel.rs
│   ├── lexer.rs
│   ├── lib.rs
│   ├── main.rs
│   ├── parser.rs
│   ├── runtime.rs
│   ├── state.rs
│   ├── token.rs
│   └── value.rs
├── tree-sitter-vx/
│   ├── grammar.js
│   ├── package.json
│   └── queries/
│       └── highlights.scm
└── python/
    ├── pyproject.toml
    ├── vlangx/
    │   ├── __init__.py
    │   ├── ast.py
    │   ├── compiler.py
    │   ├── lexer.py
    │   ├── parser.py
    │   ├── prototype.py
    │   └── runtime.py
    └── tests/
        ├── test_parser.py
        └── test_runtime.py
```

---

## Architecture overview

The repository is organized around a simple pipeline:

```text
parse -> validate -> compile -> execute -> record
```

### 1. Parse

Source text is tokenized and parsed into an AST.

### 2. Validate

The program is checked for structural correctness, type compatibility, policy compliance, and semantic validity.

### 3. Compile

The AST is lowered into kernel operations.

### 4. Execute

Kernel operations are run against deterministic state.

### 5. Record

Every successful state-changing operation emits an immutable event record.

---

## Rust runtime

The Rust implementation is the main runtime and protocol core.

It provides:

* tokenizer
* parser
* AST
* semantic validation
* compiler
* deterministic state machine
* kernel operations
* event generation
* query handling
* CLI entry point

Rust is used here because it gives:

* deterministic behavior
* memory safety
* strong type checking
* fast execution
* a good foundation for protocol code

### Rust entry points

Run a file:

```bash
cargo run -- examples/treasury.vx
```

Print the parsed AST:

```bash
cargo run -- --ast examples/treasury.vx
```

Show recorded events:

```bash
cargo run -- --events examples/treasury.vx
```

---

## Python prototype

The Python package is a lightweight experimentation layer.

It exists to support:

* language testing
* parser iteration
* prototype runtime checks
* fast experimentation before changing Rust code
* readable test harnesses

Run a prototype example:

```bash
cd python
python -m vlangx.prototype ../examples/treasury.vx
```

The Python side is useful when experimenting with syntax or verifying a parsing change before porting it into Rust.

---

## Tree-sitter support

The `tree-sitter-vx` folder contains the syntax grammar and highlight queries for editor tooling.

This layer is intended for:

* incremental parsing
* syntax highlighting
* editor integrations
* future language server support

Tree-sitter mirrors the runtime language forms so that editor feedback stays aligned with actual language behavior.

---

## LALRPOP grammar

The `grammar/vector.lalrpop` file is the canonical grammar path for future parser generation.

It exists so the language has a formal parser specification even if the current runtime parser is handwritten.

The repository intentionally keeps the runtime parser self-contained and usable without generated parser artifacts.

---

## Source file guide

### `src/ast.rs`

Defines the abstract syntax tree for the language.

This is where statements, expressions, arguments, declarations, and language structures are represented after parsing.

Edit this file when:

* adding a new statement type
* adding a new expression form
* changing the shape of parsed language objects

### `src/token.rs`

Defines token structures and token kinds used by the lexer and parser.

Edit this file when:

* adding new lexical categories
* changing token metadata
* adjusting keyword or punctuation handling

### `src/lexer.rs`

Converts raw source code into tokens.

This file is responsible for:

* keyword recognition
* identifiers
* literals
* punctuation
* comments
* spans and token positions

Edit this file when:

* adding keywords
* changing literal syntax
* changing comment syntax
* improving source position tracking

### `src/parser.rs`

Converts token streams into AST nodes.

This is where the grammar is enforced at runtime.

Edit this file when:

* adding new statements
* adjusting statement syntax
* changing expression parsing
* expanding named argument behavior
* changing how paths, calls, or contexts parse

### `src/value.rs`

Defines runtime values and supporting value/context structures.

This file is used to represent data that the language evaluates or passes through the kernel.

Edit this file when:

* changing runtime scalar/value types
* adding structured runtime data
* extending expression evaluation

### `src/error.rs`

Defines parser, runtime, validation, and kernel error types.

This is the central place for user-facing diagnostics.

Edit this file when:

* adding new validation failures
* improving error messages
* adding new error categories
* carrying more source span information

### `src/event.rs`

Defines immutable event records and event-related helpers.

This file matters because the protocol treats event history as authoritative.

Edit this file when:

* changing event schema
* adding fields to event records
* changing hashing/signature derivation
* changing event display format

### `src/state.rs`

Defines the derived network state used by execution.

This is the live, mutable cache layer, not the source of truth.

Edit this file when:

* adding new derived state stores
* changing snapshot or cache representations
* adding new runtime indexes or registries

### `src/kernel.rs`

Implements the deterministic kernel operation engine.

This is the heart of execution. It handles the actual protocol operations that the language compiles into.

It is responsible for:

* create
* certify
* transfer
* drain
* project
* reconstruct
* query
* record
* contract handling
* record generation

Edit this file when:

* changing operational semantics
* changing balance movement rules
* changing drain logic
* changing projection / settlement behavior
* changing certification gating
* changing event emission behavior

### `src/compiler.rs`

Lowers AST into kernel operations.

This is the compile stage between language structure and protocol execution.

Edit this file when:

* adding new language forms that must map to kernel ops
* changing lowering rules
* adding constant folding or validation passes
* changing contract lowering

### `src/runtime.rs`

Coordinates parsing, compilation, execution, and query resolution.

This file is the main orchestration layer for the Rust runtime.

Edit this file when:

* changing the execution pipeline
* adding new CLI modes
* changing how source files are executed
* changing query/record resolution behavior

### `src/lib.rs`

Exports the runtime modules for library use.

Edit this file when:

* adding new public modules
* changing crate-level API exposure

### `src/main.rs`

Command-line entry point for running Vector Language source files.

Edit this file when:

* changing CLI flags
* adding new commands
* changing default file loading behavior

---

## Python package guide

### `python/vlangx/__init__.py`

Package entry point.

Usually keeps exports clean and minimal.

### `python/vlangx/ast.py`

Python AST definitions.

This mirrors the Rust AST closely enough for testing and experimentation.

### `python/vlangx/lexer.py`

Python tokenizer.

Used by the Python parser and prototype runtime.

### `python/vlangx/parser.py`

Python parser for the language.

This is the most useful Python file when debugging grammar behavior.

Edit this file when:

* changing statement syntax
* changing named argument behavior
* changing expression parsing
* experimenting with new language features

### `python/vlangx/compiler.py`

Prototype compiler logic.

This is where Python AST nodes are lowered into runnable prototype operations.

### `python/vlangx/runtime.py`

Prototype runtime execution layer.

This coordinates parse, validate, compile, and execute for the Python harness.

### `python/vlangx/prototype.py`

Command-line prototype runner.

Useful for quick file-based testing without touching Rust.

### `python/tests/test_parser.py`

Parser tests for the Python prototype.

### `python/tests/test_runtime.py`

Runtime tests for the Python prototype.

These are the fastest regression checks when language syntax changes.

---

## Tree-sitter file guide

### `tree-sitter-vx/grammar.js`

Tree-sitter grammar definition for the language.

This is used for incremental parsing and syntax support in editors.

Edit this file when:

* adding statement syntax
* changing expression syntax
* changing keyword usage
* adjusting parser conflicts

### `tree-sitter-vx/queries/highlights.scm`

Highlight query rules for editor syntax coloring.

Edit this file when:

* adding new tokens that should be highlighted
* changing language categories
* improving editor readability

### `tree-sitter-vx/package.json`

Package metadata for the Tree-sitter grammar project.

Edit this file when:

* changing package name or version
* adding dev tooling
* adjusting generation scripts

---

## Example files

### `examples/treasury.vx`

A runnable example showing a standard state lifecycle:

* create vector state
* bind wallet
* certify
* transfer
* project
* reconstruct
* query

This is the best file to use as a first smoke test.

### `examples/contracts.vx`

Example focused on contract declarations and actions.

Useful for testing contract syntax and contract lowering.

### `examples/policy.vdx`

Example focused on reusable declarations or policy payloads.

Useful for testing `.vdx` parsing and policy-oriented constructs.

---

## How the parts fit together

The overall system is layered like this:

### Language layer

The user writes `.vx` and `.vdx` source.

### Parser layer

Rust and Python parsers transform source into AST.

### Compiler layer

The AST is lowered into kernel operations.

### Kernel layer

The runtime executes deterministic state transitions.

### Record layer

Every valid state transition produces an immutable event record.

### Storage layer

The network stores event history, not mutable truth.

### Tooling layer

Tree-sitter, editor support, and prototype tools sit on top of the same syntax and semantics.

This keeps the system consistent across runtime execution, debugging, tests, and future network integration.

---

## Determinism notes

Determinism is a core design constraint.

The implementation aims to keep behavior stable through:

* explicit validation
* ordered maps where stable ordering matters
* predictable serialization
* reproducible event construction
* strict handling of zero vectors
* explicit kernel operations instead of hidden side effects

This is essential because the language is intended to replay identically across peers.

---

## When to edit which file

Use this as the quick map.

### Edit parsing behavior

* `src/parser.rs`
* `python/vlangx/parser.py`
* `tree-sitter-vx/grammar.js`

### Edit tokenization / keywords

* `src/lexer.rs`
* `python/vlangx/lexer.py`
* `tree-sitter-vx/grammar.js`

### Edit runtime semantics

* `src/kernel.rs`
* `src/compiler.rs`
* `src/runtime.rs`
* `python/vlangx/compiler.py`
* `python/vlangx/runtime.py`

### Edit AST shape

* `src/ast.rs`
* `python/vlangx/ast.py`

### Edit event / history rules

* `src/event.rs`
* `src/state.rs`
* `src/kernel.rs`

### Edit CLI behavior

* `src/main.rs`
* `python/vlangx/prototype.py`

### Edit editor support

* `tree-sitter-vx/grammar.js`
* `tree-sitter-vx/queries/highlights.scm`

---

## Current status

This repository already contains a working base implementation with:

* Python prototype tests
* Rust compilation path
* deterministic runtime structure
* a language grammar
* example source files
* a clear runtime execution pipeline

The next growth steps are usually:

* expand the language grammar
* harden validation rules
* add richer contract semantics
* improve event replay and snapshotting
* add a CLI explorer
* add editor integration and language server support

---

## Usage

### Rust

```bash
cargo run -- examples/treasury.vx
cargo run -- --ast examples/treasury.vx
cargo run -- --events examples/treasury.vx
```

### Python

```bash
cd python
python -m unittest discover -s tests -v
python -m vlangx.prototype ../examples/treasury.vx
```

### Tree-sitter

```bash
cd tree-sitter-vx
tree-sitter generate
```

---

## Roadmap

A fuller next phase could include:

* richer contract runtime
* settlement and projection policy engine
* spatial movement forms
* region-aware causality rules
* snapshot recovery
* event replay tooling
* language server support
* IDE completion and diagnostics
* network sync and node APIs

---

## Summary

Vector Space is the language and tooling layer for the Vector Network.

It gives developers a human-readable way to express deterministic vector state changes while preserving the protocol’s core invariants:

* immutable records
* replayable history
* explicit validation
* derived live state
* kernel truth
* deterministic execution

The repository is structured to support language development, runtime execution, editor integration, and future network expansion from the same shared syntax and semantics.

