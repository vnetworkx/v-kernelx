# Vector Language (`v-langx` v1.2.0) Specification

Vector Language (`.vx` executable programs and `.vdx` reusable declarative definition modules) is parsed and compiled by `vendor/vectorspace` (`v-langx` v1.2.0).

## File Kinds
- **`.vx` (Executable Program)**: Declares optional `import` modules, network hierarchy creation (`space create`, `region create`, `wallet create`, `token create`), transfers (`transfer`), vContracts (`contract create`, `contract execute`), vLoans (`loan create`, `loan execute`), and proof/reconstruction checks (`verify proof network`, `reconstruct`).
- **`.vdx` (Declarative Definition Module)**: Reusable declarations (`space create`, `region create`, `wallet create`, `token create`, `contract create`, `loan create`, `certify`). **Runtime execution ops** (`transfer`, `drain`, `contract execute`, `loan execute`, `connect`, `join`) are rejected at compile time in `.vdx` files.

## Token Vector Dimension Invariants
Every token uses a 3-dimensional vector `[token, authratio(au), energy]`:
- `dimensions = 3;` is mandatory.
- **Dimension 0 (`token`)**: The sole transferable dimension.
- **Dimension 1 (`authratio(au)`)** & **Dimension 2 (`energy`)**: Protocol-governed dimensions; direct mutation or array-form transfers (e.g., `amount [10, 5, 1]`) are rejected at compile time and runtime.

## ATLAS Bootstrap Rule
Creating `ATLAS` / `Atlas Core Space` / `Atlas Genesis Region` is permitted in `DEVELOPMENT` and `TESTNET` profiles, and strictly rejected in `PRODUCTION` unless explicitly authorized in `GenesisConfig.allow_bootstrap_atlas`.
