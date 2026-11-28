# `.vdx` Module Imports & Pinning

Every `.vdx` import in a `.vx` program must pin the exact content digest:

```vx
import "policies.vdx" blake3 "7f9b854da3cf09f093932bc845a5cc08ed02589f77ceaf27317c20e97490c501";
import "shared-wallet.vdx" blake3 "b4320f1c14ff3c41c180e93e57e8cea2cb9ea7e6d30b8bf6044d0ecb08e3c5ab";
```

## Security Guarantees
- **Tamper Detection**: Both the SDK/CLI preprocessor and authoritative validator nodes compute `blake3_hex(module_source.as_bytes())` and reject mismatched imports prior to execution.
- **No Unbounded Network Fetches**: Validators never fetch arbitrary URLs during consensus; all referenced module sources are bundled deterministically in `ProgramSourceBundle.resolved_module_sources` and verified against the pinned BLAKE3 digest.
- **`.vdx` Purity**: `.vdx` files may only declare definitions/certifications, never execute transfers, drains, or contract mutations.
