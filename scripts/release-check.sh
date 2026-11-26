#!/usr/bin/env bash
set -euo pipefail

export PATH="/root/.cargo/bin:/usr/local/go/bin:$PATH"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[1/5] Checking Cargo workspace formatting & tests..."
cargo fmt --all --check --manifest-path "$ROOT/Cargo.toml"
cargo test --workspace --all-features --manifest-path "$ROOT/Cargo.toml"

echo "[2/5] Verifying cross-language parity..."
bash "$ROOT/tests/cross_language/run_parity.sh"

echo "[3/5] Checking Go SDK and Go workflow example builds..."
go -C "$ROOT/sdks/go" build ./...
go -C "$ROOT/examples/go" build ./...

echo "[4/5] Validating shell scripts and TOML configs..."
for s in "$ROOT"/scripts/*.sh "$ROOT"/tests/cross_language/*.sh; do
  bash -n "$s"
done
python3 - "$ROOT" <<'PY'
import glob, os, sys, tomllib
root = sys.argv[1]
for p in glob.glob(os.path.join(root, "config", "*.toml")):
    with open(p, "rb") as f:
        tomllib.load(f)
print("Config TOML validation passed.")
PY

echo "[5/5] Building workspace release binaries..."
cargo build --workspace --release --manifest-path "$ROOT/Cargo.toml"
echo "Release check succeeded."
