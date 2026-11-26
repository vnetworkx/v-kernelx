#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPSTREAM_REPO="https://github.com/vnetworkx/vectorspace.git"
PINNED_COMMIT="1a080053679625c7979416ccecc6f1003c4b2262"

MODE="check"
TARGET_REF="$PINNED_COMMIT"

for arg in "$@"; do
  case "$arg" in
    --check)
      MODE="check"
      ;;
    --fetch)
      MODE="fetch"
      ;;
    -h|--help)
      echo "Usage: $0 [--check | <ref> --fetch]"
      exit 0
      ;;
    *)
      TARGET_REF="$arg"
      ;;
  esac
done

if [[ "${FETCH_UPSTREAM:-0}" == "1" ]]; then
  MODE="fetch"
fi

echo "VectorSpace vendor directory: $ROOT/vendor/vectorspace"
echo "Upstream repository: $UPSTREAM_REPO"
echo "Pinned commit: $PINNED_COMMIT"
echo "Requested target ref: $TARGET_REF"

if [[ ! -d "$ROOT/vendor/vectorspace/src" || ! -f "$ROOT/vendor/vectorspace/Cargo.toml" ]]; then
  echo "ERROR: vendored VectorSpace directory missing or incomplete at $ROOT/vendor/vectorspace" >&2
  exit 1
fi

python3 - "$ROOT" <<'PY'
import pathlib, re, sys, tomllib

root = pathlib.Path(sys.argv[1])
root_cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
members = root_cargo.get("workspace", {}).get("members", [])
if "vendor/vectorspace" not in members:
    raise SystemExit("ERROR: Cargo.toml workspace missing vendor/vectorspace member")

vendor_cargo = tomllib.loads((root / "vendor" / "vectorspace" / "Cargo.toml").read_text(encoding="utf-8"))
vendor_version = vendor_cargo["package"]["version"]
expected_lang_version = f"v-langx/{vendor_version}"

sdk_checks = [
    root / "sdks" / "javascript" / "crypto.js",
    root / "sdks" / "javascript" / "browser.js",
    root / "sdks" / "typescript" / "src" / "crypto.ts",
    root / "sdks" / "typescript" / "src" / "browser.ts",
    root / "sdks" / "python" / "vnetwork_sdk" / "crypto.py",
    root / "sdks" / "go" / "crypto.go",
]
for path in sdk_checks:
    txt = path.read_text(encoding="utf-8")
    if expected_lang_version not in txt:
        raise SystemExit(f"ERROR: {path} does not match expected language version {expected_lang_version}")

adapter_txt = (root / "crates" / "vnetwork-core" / "src" / "language" / "adapter.rs").read_text(encoding="utf-8")
if "v_langx" not in adapter_txt:
    raise SystemExit("ERROR: vnetwork-core language adapter does not reference v_langx")

print(f"Offline VectorSpace parity verified (version={vendor_version}, lang={expected_lang_version}).")
PY

if [[ "$MODE" == "fetch" ]]; then
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT
  git clone --depth 1 "$UPSTREAM_REPO" "$TMP_DIR/vectorspace"
  if [[ "$TARGET_REF" != "HEAD" ]]; then
    git -C "$TMP_DIR/vectorspace" fetch --depth 1 origin "$TARGET_REF"
    git -C "$TMP_DIR/vectorspace" checkout "$TARGET_REF"
  fi
  echo "Upstream HEAD: $(git -C "$TMP_DIR/vectorspace" rev-parse HEAD)"
  diff -ruN --exclude=target --exclude=.git "$TMP_DIR/vectorspace" "$ROOT/vendor/vectorspace"
fi
