#!/usr/bin/env bash
set -euo pipefail

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DATA_DIR="${ATLAS_DATA_DIR:-./data}"
OUT_DIR="${DATA_DIR}/backups"
mkdir -p "${OUT_DIR}"

npx tsx atlas.ts backup --out "${OUT_DIR}/atlas-backup-${STAMP}.db"
echo "Backup written to ${OUT_DIR}/atlas-backup-${STAMP}.db (Note: encrypted keystores reside in ${DATA_DIR}/keystore/ and must be backed up separately)."
