# Network Security Controls

- **Key Isolation**: Node, Participant, Wallet, and Validator private keys are never reused across roles.
- **Replay Prevention**: Every signed submission/operation carries a unique `request_id` and monotonic actor `nonce` committed atomically.
- **API Protections**: `vnetwork-api` enforces 2 MiB body size limits, per-minute rate limiting, strict profile/network header enforcement, and TLS/reverse-proxy WebSocket upgrades.
- **Consensus Guards**: Validators independently recompile `.vx` programs, check `.vdx` BLAKE3 pins, detect validator equivocation, and reject below-quorum (`< 6667 bps`) proposals.
