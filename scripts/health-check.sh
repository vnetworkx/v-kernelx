#!/usr/bin/env bash
set -euo pipefail

ENDPOINTS=("$@")
if [[ "${#ENDPOINTS[@]}" -eq 0 ]]; then
  ENDPOINTS=("http://127.0.0.1:18081" "http://127.0.0.1:18082" "http://127.0.0.1:18083" "http://127.0.0.1:18084")
fi

for ep in "${ENDPOINTS[@]}"; do
  echo "=== Checking $ep ==="
  curl -fsS "$ep/healthz" | python3 -m json.tool
  curl -fsS "$ep/readyz" | python3 -m json.tool
  curl -fsS "$ep/v1/consensus/status" | python3 -c 'import sys,json; d=json.load(sys.stdin); print("consensus:", json.dumps({"height": d["height"], "quorum_bps": d["quorum_threshold_bps"], "required_weight": d["required_weight"], "total_active_weight": d["total_active_weight"], "certificates": d["certificate_count"]}))'
done
