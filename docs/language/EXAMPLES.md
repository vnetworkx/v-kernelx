# Vector Language Examples Reference

All 16 examples reside under `examples/vector-language/` and compile cleanly with `vn language compile`:

| File | Kind | Description |
| --- | --- | --- |
| `policies.vdx` | Module | Protocol compliance Space and Policy Token definitions |
| `shared-wallet.vdx` | Module | Treasury Space, Region, and co-signed Treasury Wallet definitions |
| `connect.vx` | Program | Network profile & health verification |
| `participant-join.vx` | Program | Network participation scope check |
| `create-space.vx` | Program | Creates a public Space |
| `create-region.vx` | Program | Creates Space + Region hierarchy |
| `create-wallet.vx` | Program | Creates Space, Region, Wallet + binds co-signer key |
| `create-token.vx` | Program | Creates 3D Token `[token, authratio(au), energy]` |
| `transfer-token.vx` | Program | Transfers Token dimension 0 with drain fee |
| `create-contract.vx` | Program | Creates declarative `vContract` with rules & actions |
| `execute-contract.vx` | Program | Creates and executes `vContract` |
| `create-loan.vx` | Program | Creates and executes `vLoan` lifecycle (fund, draw, repay) |
| `query-network.vx` | Program | Queries state root and entity counts |
| `reconstruct-entity.vx` | Program | Executes transactions and verifies event-sourced reconstruction |
| `bootstrap-atlas.vx` | Program | Non-production `ATLAS` `[1000000, 1000, 0]` bootstrap workflow |
| `complete-network-workflow.vx` | Program | Imports pinned `.vdx` modules and executes full end-to-end protocol lifecycle |
