# Security Policy — Vector Network (`v-kernelx`)

## Security Architecture Summary

1. **Key Separation**:
   - **Node Identity Keys** (`Ed25519` + `libp2p` Noise identity): Authenticate P2P connections and node status advertisements.
   - **Participant Identity Keys** (`Ed25519`): Authenticate join challenges, `.vx` program submissions, and signed protocol requests.
   - **Wallet Authorization Keys** (`Ed25519`): Independently control Wallet and Token operations; multi-participant co-signing requires explicit `WALLET_KEY_AUTHORIZE` quorum/owner approval.
   - **Validator Consensus Keys** (`Ed25519`): Sign BFT proposals, votes, and Quorum Certificates. Network connections never auto-grant validator rights.

2. **Language-to-Kernel Isolation**:
   - The `v-langx` compiler frontend deterministically compiles `.vx` and `.vdx` sources with BLAKE3 content-pinned imports into `CompiledProgram` representations.
   - Validators never trust client claims of compilation: proposals carry `ProgramSourceBundle`, and every validator re-verifies source hash, module hashes, compiled program hash, and re-executes atomically before voting.
   - Only dimension 0 (`token`) of the 3-dimensional `[token, authratio(au), energy]` vector is transferable.

3. **Replay & Tampering Protection**:
   - All write operations require Ed25519 signature verification over canonical JSON payloads, `network_id` binding, unique `request_id`, and strictly monotonic per-actor `nonce`.
   - `QuorumCertificate`s require `>= 6667 bps` (`> 2/3`) active validator weight and include verified per-validator Ed25519 signatures.

4. **Network & Profile Isolation**:
   - `DEVELOPMENT`, `TESTNET`, and `PRODUCTION` profiles enforce distinct `network_id`s and genesis files persisted on disk.
   - Storage refuses to boot if disk genesis metadata mismatches runtime profile configuration.
   - Development fixtures (`ATLAS` bootstrap) are explicitly blocked in `PRODUCTION` unless authorized at genesis.

5. **Production Hardening Checklist**:
   - Terminate public HTTPS/WSS behind TLS 1.3 (via built-in `NETWORK_TLS_CONFIGURATION` or `deploy/reverse-proxy/`).
   - Never reuse development keys in `TESTNET` or `PRODUCTION`.
   - Restrict P2P and API ports via firewall rules and configure `NETWORK_ADVERTISED_ADDRESSES` to verifiable public DNS/IP multiaddrs.
