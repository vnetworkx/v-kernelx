# ATLAS VECTOR NETWORK — Deployment & Operations Guide

## Architecture & Scope
- **Mode**: Standalone persistent single-node kernel (`v-kernelx` v0.1.4-atlas).
- **Storage**: ACID SQLite (`WAL`, `synchronous=FULL`) in `${ATLAS_DATA_DIR:-./data}/atlas-kernel.db`.
- **Keystore**: AES-256-GCM + scrypt encrypted Ed25519 seeds in `${ATLAS_DATA_DIR:-./data}/keystore/` (mode `0700`/`0600`).

## Firewall & Exposure
- Bind HTTP port `3000` behind TLS/VPN or localhost (`127.0.0.1:3000:3000` in `docker-compose.yml`).
- Never expose `/api/regions`, `/api/wallets`, `/api/tokens*`, `/api/snapshot`, or `/api/backup` publicly without setting a strong `ATLAS_ADMIN_TOKEN` and TLS termination.

## Backup & Recovery
1. Database hot backup: `./scripts/backup.sh` or `npx tsx atlas.ts backup --out ./data/backups/manual.db`.
2. Keystore backup: Copy `${ATLAS_DATA_DIR:-./data}/keystore/` and record `ATLAS_KEYSTORE_PASSPHRASE` securely offline.
3. Recovery: Stop node (`npx tsx atlas.ts stop`), restore `atlas-kernel.db` and `keystore/`, verify with `npx tsx atlas.ts history replay`, then start (`npx tsx atlas.ts start`).
