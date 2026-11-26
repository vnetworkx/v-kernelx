#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
STORAGE_DIR="${NETWORK_STORAGE_PATH:-$ROOT/data/node1}"
OUT_DIR="${BACKUP_OUT_DIR:-$STORAGE_DIR/backups}"
mkdir -p "${OUT_DIR}"

if [[ ! -d "$STORAGE_DIR" ]]; then
  echo "Storage directory '$STORAGE_DIR' does not exist." >&2
  exit 1
fi

ARCHIVE="${OUT_DIR}/vnetwork-backup-${STAMP}.tar.gz"
INCLUDE_FILES=()
for f in genesis.json events.wal consensus_commits.wal certified.checkpoint.json equivocation_votes.wal equivocation_evidence.wal programs.json transactions.json indexes.json migrations.json; do
  if [[ -f "${STORAGE_DIR}/${f}" ]]; then
    INCLUDE_FILES+=("${f}")
  fi
done

if [[ "${#INCLUDE_FILES[@]}" -eq 0 ]]; then
  echo "No durable Vector Network ledger artifacts found in '${STORAGE_DIR}'." >&2
  exit 1
fi

tar -czf "${ARCHIVE}" -C "${STORAGE_DIR}" "${INCLUDE_FILES[@]}"
echo "Backup archive written to ${ARCHIVE}"
echo "Reminder: Node and Validator Ed25519 key files must be backed up separately using encrypted offline storage."
