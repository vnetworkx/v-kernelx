#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_BASE="$(mktemp -d "${TMPDIR:-/tmp}/vnetwork-script-safety-XXXXXX")"
SLEEPER_PID=""

cleanup() {
  if [[ -n "$SLEEPER_PID" ]] && kill -0 "$SLEEPER_PID" 2>/dev/null; then
    kill "$SLEEPER_PID" 2>/dev/null || true
    wait "$SLEEPER_PID" 2>/dev/null || true
  fi
  rm -rf -- "$TMP_BASE"
}
trap cleanup EXIT

echo "[1/4] Verifying devnet-down.sh rejects missing ownership marker..."
UNOWNED="$TMP_BASE/unowned"
mkdir -p "$UNOWNED/node1"
touch "$UNOWNED/important-user-file.txt"
if DEVNET_DIR="$UNOWNED" bash "$ROOT/scripts/devnet-down.sh" 2>/dev/null; then
  echo "ERROR: devnet-down.sh should reject directory without ownership marker" >&2
  exit 1
fi
[[ -f "$UNOWNED/important-user-file.txt" ]]

echo "[2/4] Verifying devnet-down.sh refuses symlinked DEVNET_DIR and .. traversal..."
REAL_TGT="$TMP_BASE/real_tgt"
mkdir -p "$REAL_TGT"
ln -s "$REAL_TGT" "$TMP_BASE/sym_dir"
if DEVNET_DIR="$TMP_BASE/sym_dir" bash "$ROOT/scripts/devnet-down.sh" 2>/dev/null; then
  echo "ERROR: devnet-down.sh should reject symlink DEVNET_DIR" >&2
  exit 1
fi
if DEVNET_DIR="$TMP_BASE/../evil" bash "$ROOT/scripts/devnet-down.sh" 2>/dev/null; then
  echo "ERROR: devnet-down.sh should reject '..' path traversal" >&2
  exit 1
fi

echo "[3/4] Verifying devnet-down.sh never kills reused/unrelated PID..."
sleep 30 &
SLEEPER_PID=$!
OWNED="$TMP_BASE/owned_devnet"
mkdir -p "$OWNED/node1"
echo "owner=vnetwork-devnet" > "$OWNED/.vnetwork-devnet-owner"
echo "$SLEEPER_PID" > "$OWNED/node1/node.pid"
cat > "$OWNED/node1/node.meta" <<EOF
pid=${SLEEPER_PID}
binary=/nonexistent/vnetwork-node
config=${OWNED}/node1/node.toml
EOF

DEVNET_DIR="$OWNED" bash "$ROOT/scripts/devnet-down.sh" 2>/dev/null
if ! kill -0 "$SLEEPER_PID" 2>/dev/null; then
  echo "ERROR: devnet-down.sh signaled unrelated process PID $SLEEPER_PID!" >&2
  exit 1
fi
if [[ -f "$OWNED/node1/node.pid" ]]; then
  echo "ERROR: stale pidfile was not removed after mismatch check" >&2
  exit 1
fi
kill "$SLEEPER_PID" 2>/dev/null || true
wait "$SLEEPER_PID" 2>/dev/null || true
SLEEPER_PID=""

echo "[4/4] Verifying devnet-up.sh rejects symlink/dangerous/unmanaged dirs before build..."
for bad in "/" "$ROOT" "$TMP_BASE/sym_dir" "$TMP_BASE/.."; do
  if DEVNET_DIR="$bad" bash "$ROOT/scripts/devnet-up.sh" 2>/dev/null; then
    echo "ERROR: devnet-up.sh should have rejected DEVNET_DIR=$bad" >&2
    exit 1
  fi
done
if DEVNET_DIR="$UNOWNED" bash "$ROOT/scripts/devnet-up.sh" 2>/dev/null; then
  echo "ERROR: devnet-up.sh should reject unmanaged non-empty directory" >&2
  exit 1
fi
[[ -f "$UNOWNED/important-user-file.txt" ]]

echo "[5/6] Verifying vendored vectorspace compiler drift check..."
bash "$ROOT/scripts/sync-vectorspace.sh" --check

echo "[6/6] Verifying CI workflows have zero '|| true' bypasses and .env.example declares auth vars..."
if grep -rnE '\|\|\s*true' "$ROOT/.github/workflows"; then
  echo "ERROR: found '|| true' bypass in GitHub Actions workflows" >&2
  exit 1
fi
grep -q "ATLAS_ADMIN_TOKEN" "$ROOT/.env.example"
grep -q "NETWORK_ADMIN_TOKEN" "$ROOT/.env.example"

echo "Shell script safety verification PASSED."

