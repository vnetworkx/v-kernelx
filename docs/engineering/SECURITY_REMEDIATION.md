# Security Remediation Report — Vector Network

Covers key storage, cryptography, consensus anti-equivocation, path containment, authorization invariants, API boundaries, and operational script safety.

---

## 1. Key Storage & Identity Security (`IMPLEMENTED` in Rust / `TESTED` in Python & JS/TS)

- **Encrypted Envelope (`ProtectedSigningKey`, `crates/vnetwork-types/src/identity.rs`, `crates/vnetwork-node/src/identity.rs`)**:
  - Argon2id key derivation (`m >= 4096` KiB enforced minimum, `65536` KiB / 64 MiB default, `t = 3`, `p = 1`) paired with AES-256-GCM authenticated encryption binding `network_id`, `key_role`, `public_key_hex`, and schema version in AEAD Associated Authenticated Data (AAD).
  - Atomic write-temp + `fsync` + parent-dir `sync_all` + rename, enforcing POSIX `0600` file permissions and `0700` directory permissions.
  - Plaintext private key loading is strictly rejected in `PRODUCTION` and `TESTNET` profiles and disabled by default in `crates/vnetwork-cli/src/config.rs` unless explicitly opted in during development.
  - Secret redaction via custom `Debug` and `Display` implementations in Rust and `__repr__` in `sdks/python/vnetwork_sdk/crypto.py` (tested via `tests/cross_language/test_python_sdk.py`).
  - Validator key rotation preserves prior public key lineage (`rotation_history`) without erasing identity bindings.

## 2. Cryptographic Integrity & Weak-Key Rejection (`TESTED` JS/TS/Py / `IMPLEMENTED` Rust/Go)

- **Strict Canonical Ed25519 Validation**:
  - Rejects non-64-hex keys, non-canonical compressed points, all-zero weak keys (`00..00`), identity point (`0100..00`), and small-order torsion elements before consensus set construction or signature verification.
  - Cross-language parity verified across Node JS (`sdks/javascript`), Node TS (`sdks/typescript`), Browser JS/TS WebCrypto (`browser.js`/`browser.ts`), and Python (`sdks/python`) via `tests/cross_language/sdk_parity.test.mjs` (5/5 passed) and `tests/cross_language/test_python_sdk.py` (5/5 passed).
- **Signature Domain Separation**:
  - Transfer approvals include `"domain": "vnetwork/transfer-approval/v1"` across Rust, JS, TS, Python, Go, and Next.js client helpers (`lib/client-crypto.ts`), verified in `tests/explorer/integrity_and_crypto.test.mjs` (17/17 passed).
  - CSPRNG (`OsRng`) used exclusively for PoP challenges (`crates/vnetwork-core/src/identity.rs`).

## 3. Anti-Equivocation Guarantees (`IMPLEMENTED`)

- **Persistent 9-Tuple Slot Lock (`crates/vnetwork-consensus/src/equivocation.rs`)**:
  - Slot key: `(network_id, genesis_commitment, validator_id, pubkey_fingerprint, epoch, height, round, vote_phase, protocol_version)`.
  - Two-phase signing write-ahead protocol:
    1. Acquire exclusive filesystem lock.
    2. Write and `fsync` `IntentPending` slot record *before* invoking `signer.sign(message)`.
    3. Write and `fsync` `Signed` slot record *before* returning signature or broadcasting vote.
  - Conflicting vote in an already locked/signed slot for a divergent `proposal_digest` deterministically halts signing and records durable `EquivocationEvidence`.
  - Corrupted equivocation store fails closed and refuses all validator signing rather than resetting state.

## 4. Authorization, Policy & Contract Boundaries (`IMPLEMENTED`)

- **No Silent Scope Escalation**: `crates/vnetwork-cli/src/commands/join.rs` and `crates/vnetwork-core/src/authorization.rs` fail closed on unrecognized scopes and require valid signed `ScopeGrant` metadata for elevated scopes.
- **Closed-by-Default Smart Contracts**: `vContract` execution enforces explicit `allowed_actors`, invocation caps (`max_executions`), expiration timestamps (`expires_at_ms`), and `min_auth_ratio_au`.
- **Dual-Side Wallet Policy**: Recipients enforce `WalletReceivePolicy` (`Open | Restricted | Frozen`) including `SameWallet` self-transfers; loan collateral movements route through internal protocol settlement helpers without user send-policy ambiguity.
- **Ghost Record TTL**: `crates/vnetwork-core/src/ghost.rs` enforces deterministic expiry pruning and access denial once `expires_at_ms <= timestamp_ms`.

## 5. Supply-Chain & Filesystem Safety (`TESTED` JS/TS/Py/Shell / `IMPLEMENTED` Rust/Go)

- **Module Import Path Containment**:
  - Rust (`vendor/vectorspace/src/compiler.rs`, `sdks/rust/src/lib.rs`), JS (`sdks/javascript/index.js`), TS (`sdks/typescript/src/client.ts`), Python (`sdks/python/vnetwork_sdk/client.py`), and Go (`sdks/go/client.go`) canonicalize real filesystem paths (`canonicalize` / `fs.realpath` / `Path.resolve` / `filepath.EvalSymlinks`) and verify containment within `base_dir` while capping module count (`<= 64`) and depth (`<= 16`).
- **Devnet Script Safety (`scripts/devnet-up.sh`, `scripts/devnet-down.sh`, `scripts/test-network.sh`)**:
  - Refuses symlinks, `..` traversal, `/`, `$HOME`, workspace root, `.git`, and unowned non-empty directories lacking `.vnetwork-devnet-owner`.
  - Refuses terminating reused PIDs unless OS process cmdline (`vnetwork-node` + `--config <node.toml>`) matches `node.meta`.
  - Verified by `tests/e2e/script_safety.test.sh` (4/4 passed).
