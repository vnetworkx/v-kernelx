#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RAW_DEVNET_DIR="${DEVNET_DIR:-$ROOT/.devnet}"

if [[ -z "$RAW_DEVNET_DIR" || "$RAW_DEVNET_DIR" == *".."* || -L "$RAW_DEVNET_DIR" ]]; then
  echo "Refusing unsafe devnet directory for shutdown: '$RAW_DEVNET_DIR'" >&2
  exit 1
fi

if [[ ! -d "$RAW_DEVNET_DIR" ]]; then
  echo "No devnet directory at $RAW_DEVNET_DIR"
  exit 0
fi

DEVNET_DIR="$(cd "$RAW_DEVNET_DIR" && pwd -P)"
if [[ ! -f "$DEVNET_DIR/.vnetwork-devnet-owner" && ! -f "$DEVNET_DIR/.vnetwork-devnet-marker" ]]; then
  echo "Refusing to inspect '$DEVNET_DIR' because devnet ownership marker is missing." >&2
  exit 1
fi

verify_pid_identity() {
  local pid="$1"
  local expected_cfg="$2"
  local cmdline=""
  if [[ -r "/proc/${pid}/cmdline" ]]; then
    cmdline="$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || true)"
  else
    cmdline="$(ps -p "$pid" -o args= 2>/dev/null || true)"
  fi
  [[ "$cmdline" == *"vnetwork-node"* && "$cmdline" == *"$expected_cfg"* ]]
}

for pidfile in "$DEVNET_DIR"/node*/node.pid; do
  [[ -f "$pidfile" ]] || continue
  node_dir="$(dirname "$pidfile")"
  metafile="$node_dir/node.meta"
  pid="$(tr -d '[:space:]' < "$pidfile" || true)"
  expected_cfg="$node_dir/node.toml"
  if [[ -f "$metafile" ]]; then
    meta_cfg="$(grep '^config=' "$metafile" | head -n1 | cut -d= -f2- || true)"
    [[ -n "$meta_cfg" ]] && expected_cfg="$meta_cfg"
  fi

  if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
    if ! verify_pid_identity "$pid" "$expected_cfg"; then
      echo "WARNING: PID $pid in $pidfile does not match expected vnetwork-node ($expected_cfg); skipping signal." >&2
      rm -f "$pidfile" "$metafile"
      continue
    fi
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 50); do
      if ! kill -0 "$pid" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null && verify_pid_identity "$pid" "$expected_cfg"; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  rm -f "$pidfile" "$metafile"
done

echo "Devnet nodes stopped cleanly."
