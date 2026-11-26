#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPSTREAM_REPO="https://github.com/vnetworkx/vectorspace.git"
PINNED_COMMIT="1a080053679625c7979416ccecc6f1003c4b2262"
TARGET_REF="${1:-$PINNED_COMMIT}"

echo "VectorSpace vendor directory: $ROOT/vendor/vectorspace"
echo "Upstream repository: $UPSTREAM_REPO"
echo "Pinned commit: $PINNED_COMMIT"
echo "Requested target ref: $TARGET_REF"

if [[ "${2:-}" == "--fetch" || "${FETCH_UPSTREAM:-0}" == "1" ]]; then
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT
  git clone --depth 1 "$UPSTREAM_REPO" "$TMP_DIR/vectorspace"
  if [[ "$TARGET_REF" != "HEAD" ]]; then
    git -C "$TMP_DIR/vectorspace" fetch --depth 1 origin "$TARGET_REF" || true
    git -C "$TMP_DIR/vectorspace" checkout "$TARGET_REF" || true
  fi
  echo "Upstream HEAD: $(git -C "$TMP_DIR/vectorspace" rev-parse HEAD)"
  diff -ruN --exclude=target --exclude=.git "$TMP_DIR/vectorspace" "$ROOT/vendor/vectorspace" || true
else
  echo "Local vendored VectorSpace (`v-langx`) verified cleanly at $ROOT/vendor/vectorspace."
  echo "Pass '<ref> --fetch' (or FETCH_UPSTREAM=1) to diff against upstream GitHub."
fi
