#!/usr/bin/env bash
set -euo pipefail

export PATH="/root/.cargo/bin:/usr/local/go/bin:$PATH"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[1/4] Checking Rust workspace tests..."
cargo test --workspace --manifest-path "$ROOT/Cargo.toml"

echo "[2/4] Verifying cross-language parity (Rust, JS, TS, Python, Go)..."
bash "$ROOT/tests/cross_language/run_parity.sh"

echo "[3/4] Checking Go SDK and Go workflow example builds..."
go -C "$ROOT/sdks/go" build ./...
go -C "$ROOT/examples/go" build ./...

echo "[4/4] Building release binaries (vnetwork-node, vn)..."
cargo build --release -p vnetwork-node -p vnetwork-cli --manifest-path "$ROOT/Cargo.toml"
echo "Release check succeeded."
