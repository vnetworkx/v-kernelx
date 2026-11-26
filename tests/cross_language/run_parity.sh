#!/usr/bin/env bash
set -euo pipefail

export PATH="/root/.cargo/bin:/usr/local/go/bin:$PATH"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "[1/5] Generating Rust canonical parity reference..."
RUST_JSON="$(cargo run -q -p vnetwork-types --example parity_ref --manifest-path "$ROOT/Cargo.toml")"

echo "[2/5] Running JavaScript parity check..."
JS_JSON="$(node "$ROOT/tests/cross_language/verify_parity.mjs")"

echo "[3/5] Running TypeScript parity check..."
TS_JSON="$(tsx "$ROOT/tests/cross_language/verify_parity.ts")"

echo "[4/5] Running Python parity check..."
PY_JSON="$(python3 "$ROOT/tests/cross_language/verify_parity.py")"

echo "[5/5] Running Go parity check..."
GO_JSON="$(go -C "$ROOT/tests/cross_language" run .)"

python3 - "$RUST_JSON" "$JS_JSON" "$TS_JSON" "$PY_JSON" "$GO_JSON" <<'PY'
import json, sys

records = [json.loads(arg) for arg in sys.argv[1:]]
fields = ["empty_b3", "hello_b3", "multi_b3", "canon_str", "participant_pubkey", "participant_id", "node_id", "sig"]
ref = records[0]
for rec in records[1:]:
    for f in fields:
        if rec[f] != ref[f]:
            raise SystemExit(f"PARITY MISMATCH in {rec['lang']} field {f}:\n  expected: {ref[f]}\n  actual:   {rec[f]}")
print("CROSS-LANGUAGE PARITY VERIFIED ACROSS ALL 5 LANGUAGES (Rust, JS, TS, Python, Go):")
print("  empty_b3:", ref["empty_b3"])
print("  multi_b3:", ref["multi_b3"])
print("  participant_id:", ref["participant_id"])
print("  sig:", ref["sig"][:32] + "...")
PY
