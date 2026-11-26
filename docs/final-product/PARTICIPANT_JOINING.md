# Participant Joining & Key Separation

Joining a Vector Network requires explicit cryptographic challenge-response verification and strict key role separation:

1. **Key Roles**:
   - **Node Key (`nod_*`)**: Identifies the P2P node daemon (`libp2p` PeerId + `node_pubkey`).
   - **Participant Key (`prt_*`)**: Authorizes participant identity (`participant_pubkey`) and signs `.vx` submissions.
   - **Wallet Keys (`wlt_*`)**: Co-signers authorized onto wallets; managed independently of participant identity.
   - **Validator Key (`val_*`)**: Genesis/governance-authorized consensus signing key; joining never auto-grants validator rights.
2. **Join Flow**:
   - Client fetches `GET /v1/network/info` and asserts `network_id` + `protocol_version`.
   - Client requests a single-use challenge via `POST /v1/participation/challenge`.
   - Client constructs canonical join payload `{ challenge_id, network_id, node_pubkey, nonce, participant_pubkey, requested_scopes }`.
   - Client signs with **both** `participant_key` and `node_key` (`participant_pubkey != node_pubkey` enforced by core).
   - Validators verify signatures, enforce `NodeKind` non-self-promotion (`ValidatorNode` requests downgrade to `FullNode`), and finalize registration under BFT quorum.
