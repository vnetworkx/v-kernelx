#!/usr/bin/env bash
set -euo pipefail

export PATH="/root/.cargo/bin:/usr/local/go/bin:$PATH"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NETWORK_ID="${VNETWORK_NETWORK_ID:-vector-devnet-1}"
EP1="${VNETWORK_ENDPOINT:-http://127.0.0.1:18081}"
EP2="${VNETWORK_ENDPOINT_2:-http://127.0.0.1:18082}"
EP3="${VNETWORK_ENDPOINT_3:-http://127.0.0.1:18083}"

echo "[1/5] Running Rust SDK workflow against $EP1..."
VNETWORK_ENDPOINT="$EP1" VNETWORK_NETWORK_ID="$NETWORK_ID" \
  cargo run -q --manifest-path "$ROOT/examples/rust/Cargo.toml"

echo "[2/5] Running JavaScript SDK workflow against $EP2..."
VNETWORK_ENDPOINT="$EP2" VNETWORK_NETWORK_ID="$NETWORK_ID" \
  node "$ROOT/examples/javascript/workflow.mjs"

echo "[3/5] Running TypeScript SDK workflow against $EP3..."
"$ROOT/node_modules/.bin/tsc" -p "$ROOT/sdks/typescript/tsconfig.json" --noEmit
if command -v tsx >/dev/null 2>&1; then
  VNETWORK_ENDPOINT="$EP3" VNETWORK_NETWORK_ID="$NETWORK_ID" \
    tsx "$ROOT/examples/typescript/workflow.ts"
elif command -v bun >/dev/null 2>&1; then
  VNETWORK_ENDPOINT="$EP3" VNETWORK_NETWORK_ID="$NETWORK_ID" \
    bun "$ROOT/examples/typescript/workflow.ts"
else
  echo "ERROR: neither tsx nor bun available to execute TypeScript SDK workflow" >&2
  exit 1
fi

echo "[4/5] Running Python SDK workflow against $EP1..."
VNETWORK_ENDPOINT="$EP1" VNETWORK_NETWORK_ID="$NETWORK_ID" \
  python3 "$ROOT/examples/python/workflow.py"

echo "[5/5] Running Go SDK workflow against $EP2..."
VNETWORK_ENDPOINT="$EP2" VNETWORK_NETWORK_ID="$NETWORK_ID" \
  go -C "$ROOT/examples/go" run .

echo "ALL 5 SDK LIVE WORKFLOWS SUCCEEDED (Rust, JavaScript, TypeScript, Python, Go)."
