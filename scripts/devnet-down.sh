#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_DIR="${DEVNET_DIR:-$ROOT/.devnet}"

if [[ ! -d "$DEVNET_DIR" ]]; then
  echo "No devnet directory at $DEVNET_DIR"
  exit 0
fi

for pidfile in "$DEVNET_DIR"/node*/node.pid; do
  [[ -f "$pidfile" ]] || continue
  pid="$(cat "$pidfile" || true)"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      if ! kill -0 "$pid" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  fi
  rm -f "$pidfile"
done

echo "Devnet nodes stopped cleanly."
