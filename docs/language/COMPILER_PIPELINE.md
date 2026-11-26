# Vector Language Compiler Pipeline

1. **Lexer (`v_langx::lexer`)**: Tokenizes `.vx`/`.vdx` source with exact line/column source spans (`Span`).
2. **Parser (`v_langx::parser`)**: Constructs typed AST (`ProgramAst`, `Statement`, `ImportDecl`, `Expr`).
3. **Import Resolver (`crates/vnetwork-core/src/language/imports.rs` & `v_langx`)**: Reads referenced `.vdx` modules (from inline `modules` map or local directory), verifies `blake3` hash pins, and enforces `.vdx` purity rules.
4. **Semantic Validator (`v_langx::semantic`)**: Enforces 3D token invariance, single-dimension scalar transfers, alias scoping, and rejects arbitrary non-deterministic expressions.
5. **Compiler (`v_langx::compiler`)**: Emits deterministic `CompiledProgram` containing ordered `CompiledOp` records and canonical BLAKE3 `program_hash`.
6. **Staged Protocol Execution (`vnetwork-core::language::program`)**: Clones `NetworkLedgerState`, executes all compiled operations sequentially; any error aborts with zero partial state mutation and returns `failed_operation_index`.
7. **Validator Independent Verification (`vnetwork-core::language::verification`)**: Every BFT validator recompiles the submitted `source_bytes` + verified `resolved_module_sources`, verifies `compiled_program_hash`, re-executes staged state, and checks `post_state_root` equality before signing a `ConsensusVote`.
