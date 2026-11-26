#!/usr/bin/env bash
set -euo pipefail

export PATH="/root/.cargo/bin:/usr/local/go/bin:$PATH"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[1/6] Checking Cargo workspace formatting & tests..."
cargo fmt --all --check --manifest-path "$ROOT/Cargo.toml"
cargo test --workspace --all-features --manifest-path "$ROOT/Cargo.toml"

echo "[2/6] Verifying cross-language parity & SDK unit tests..."
bash "$ROOT/tests/cross_language/run_parity.sh"
node --test "$ROOT/tests/cross_language/sdk_parity.test.mjs" "$ROOT/tests/explorer/integrity_and_crypto.test.mjs"
python3 -m unittest discover -s "$ROOT/tests/cross_language" -p "test_*.py"
bash "$ROOT/tests/e2e/script_safety.test.sh"

echo "[3/6] Checking Go SDK and Go workflow example builds..."
go -C "$ROOT/sdks/go" build ./...
go -C "$ROOT/examples/go" build ./...

echo "[4/6] Validating shell scripts and TOML configs..."
for s in "$ROOT"/scripts/*.sh "$ROOT"/tests/cross_language/*.sh "$ROOT"/tests/e2e/*.sh "$ROOT"/tests/multi_node/*.sh; do
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

echo "[5/6] Validating Next.js Explorer (TypeScript, Lint, Production Build)..."
npm --prefix "$ROOT" exec -- tsc --noEmit
npm --prefix "$ROOT" run lint
npm --prefix "$ROOT" run build

echo "[6/6] Building workspace release binaries..."
cargo build --workspace --release --manifest-path "$ROOT/Cargo.toml"
echo "Release check succeeded."
