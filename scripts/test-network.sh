#!/usr/bin/env bash
set -euo pipefail

export PATH="/root/.cargo/bin:/usr/local/go/bin:$PATH"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

AUTO_TEMP_DIR=""
if [[ -z "${DEVNET_DIR:-}" ]]; then
  AUTO_TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vnetwork-acceptance-XXXXXX")"
  DEVNET_DIR="$AUTO_TEMP_DIR"
else
  if [[ -d "$DEVNET_DIR" && ! -f "$DEVNET_DIR/.vnetwork-devnet-marker" ]]; then
    echo "Refusing to reuse existing non-devnet directory '$DEVNET_DIR' without .vnetwork-devnet-marker." >&2
    exit 1
  fi
fi
export DEVNET_DIR
export NETWORK_ID="${NETWORK_ID:-vector-devnet-1}"
CLI_HOME="$(mktemp -d "${TMPDIR:-/tmp}/vnetwork-cli-XXXXXX")"

cleanup() {
  echo "Stopping devnet nodes..."
  bash "$ROOT/scripts/devnet-down.sh" || true
  if [[ -n "$CLI_HOME" && "$CLI_HOME" == "${TMPDIR:-/tmp}/vnetwork-cli-"* && -d "$CLI_HOME" ]]; then
    rm -rf -- "$CLI_HOME"
  fi
  if [[ -n "$AUTO_TEMP_DIR" && "$AUTO_TEMP_DIR" == "${TMPDIR:-/tmp}/vnetwork-acceptance-"* && -d "$AUTO_TEMP_DIR" ]]; then
    rm -rf -- "$AUTO_TEMP_DIR"
  fi
}
trap cleanup EXIT

echo "=================================================================="
echo "STEP 1: Cargo workspace unit & integration tests"
echo "=================================================================="
cargo test --workspace --all-features --manifest-path "$ROOT/Cargo.toml"

echo "=================================================================="
echo "STEP 2: Cross-language cryptographic & canonical parity (5 SDKs)"
echo "=================================================================="
bash "$ROOT/tests/cross_language/run_parity.sh"

echo "=================================================================="
echo "STEP 3: Compile check all 16 .vx / .vdx language examples"
echo "=================================================================="
cargo build -q -p vnetwork-cli -p vnetwork-node --manifest-path "$ROOT/Cargo.toml"
VN_BIN="$ROOT/target/debug/vn"
NODE_BIN="$ROOT/target/debug/vnetwork-node"
for f in "$ROOT"/examples/vector-language/*.vx "$ROOT"/examples/vector-language/*.vdx; do
  "$VN_BIN" language compile "$f" >/dev/null
  echo "  OK compiled $(basename "$f")"
done

echo "=================================================================="
echo "STEP 4: Boot 4 real persistent libp2p validator nodes"
echo "=================================================================="
DEVNET_CLEAN=0 NETWORK_CONSENSUS_TIMEOUT_MS=3500 bash "$ROOT/scripts/devnet-up.sh"

N1_PEERS="$(curl -fsS http://127.0.0.1:18081/healthz | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d["healthy"] and d["storage_ok"]; print(d["connected_peers"])')"
echo "Node 1 connected libp2p peers: $N1_PEERS"
if [[ "$N1_PEERS" -lt 3 ]]; then
  echo "Expected >= 3 connected peers on Node 1, got $N1_PEERS" >&2
  exit 1
fi

echo "=================================================================="
echo "STEP 5: CLI join + ATLAS bootstrap + complete .vx/.vdx workflow"
echo "=================================================================="
HOME="$CLI_HOME" "$VN_BIN" identity create --name "cli-acceptance-user" >/dev/null
HOME="$CLI_HOME" "$VN_BIN" connect --network "$NETWORK_ID" --endpoint http://127.0.0.1:18081 >/dev/null
HOME="$CLI_HOME" "$VN_BIN" join --scope NETWORK >/dev/null
HOME="$CLI_HOME" "$VN_BIN" program submit "$ROOT/examples/vector-language/bootstrap-atlas.vx" >/dev/null
HOME="$CLI_HOME" "$VN_BIN" program submit "$ROOT/examples/vector-language/complete-network-workflow.vx" >/dev/null
HOME="$CLI_HOME" "$VN_BIN" ledger verify | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d["chain_valid"] is True; print("CLI ledger proof verified:", d["event_count"], "events, state_root=", d["state_root"])'

echo "=================================================================="
echo "STEP 6: Run ALL 5 live SDKs (Rust, JS, TS, Python, Go)"
echo "=================================================================="
VNETWORK_ENDPOINT=http://127.0.0.1:18081 \
VNETWORK_ENDPOINT_2=http://127.0.0.1:18082 \
VNETWORK_ENDPOINT_3=http://127.0.0.1:18083 \
VNETWORK_NETWORK_ID="$NETWORK_ID" \
bash "$ROOT/scripts/test-all-sdks.sh"

echo "Checking cross-node state convergence across all 4 nodes..."
python3 - <<'PY'
import json, urllib.request

roots = {}
heights = {}
for i in range(1, 5):
    url = f"http://127.0.0.1:{18080+i}/v1/network/status"
    data = json.loads(urllib.request.urlopen(url).read().decode())
    roots[i] = data["state_root"]
    heights[i] = data["height"]
    proofs = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{18080+i}/v1/ledger/proofs").read().decode())
    assert proofs["chain_valid"] is True, f"node {i} invalid proof chain"
print("Node heights:", heights)
print("Node state_roots:", set(roots.values()))
assert len(set(heights.values())) == 1, f"Height mismatch across nodes: {heights}"
assert len(set(roots.values())) == 1, f"State root mismatch across nodes: {roots}"
print("All 4 nodes converged at height", heights[1], "with identical state_root", roots[1])
PY

echo "=================================================================="
echo "STEP 7: Atomic rollback + hostile security rejection checks"
echo "=================================================================="
VNETWORK_ENDPOINT=http://127.0.0.1:18081 VNETWORK_NETWORK_ID="$NETWORK_ID" python3 - <<'PY'
import json, os, sys, urllib.request, urllib.error
sys.path.insert(0, "sdks/python")
from vnetwork_sdk import ClientIdentity, VectorNetworkClient, PROTOCOL_VERSION

ep = os.environ["VNETWORK_ENDPOINT"]
net_id = os.environ["VNETWORK_NETWORK_ID"]

ident = ClientIdentity.generate("security-verifier")
c = VectorNetworkClient(ep, ident, expected_network_id=net_id)
c.connect()
c.join(["NETWORK"])

before = json.loads(urllib.request.urlopen(f"{ep}/v1/network/status").read().decode())

# 1. Invalid .vx transfer causes atomic rollback (zero partial Space/Region/Wallet created)
failing_vx = '''
space create ShouldRollbackSpace { visibility = "public" }
region create ShouldRollbackRegion in "ShouldRollbackSpace" { prefix = "RBK"; visibility = "public"; section = 1; }
wallet create ShouldRollbackWallet in "ShouldRollbackRegion" { name = "Rollback Wallet"; }
transfer "NONEXISTENT_TOK" from "ShouldRollbackWallet" to "MissingDst" amount 500;
'''
sub = c.submit_program("should_rollback.vx", failing_vx)
assert sub["status"] in ("FAILED", "REJECTED"), f"Expected FAILED/REJECTED, got {sub}"
after = json.loads(urllib.request.urlopen(f"{ep}/v1/network/status").read().decode())
assert after["height"] == before["height"]
assert after["spaces"] == before["spaces"]
assert after["state_root"] == before["state_root"]
print("Verified atomic rollback: status=", sub["status"], "state_root unchanged.")

# 2. Tampered program signature MUST be rejected
try:
    req_data = urllib.request.Request(
        f"{ep}/v1/programs/submit",
        data=json.dumps({
            "file_name": "tamper.vx",
            "source_bytes": "space create TamperSpace { visibility = \"public\" }",
            "modules": {},
            "actor_pubkey": ident.participant_key.public_key_hex,
            "network_id": net_id,
            "request_id": "req_tamper_001",
            "nonce": 999,
            "signature": "00" * 64,
            "execution_params": {},
        }).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(req_data)
    raise AssertionError("Tampered signature should have been rejected!")
except urllib.error.HTTPError as e:
    assert e.code in (400, 401, 403), f"Unexpected HTTP status {e.code}"
    print("Verified tampered signature rejected with HTTP", e.code)
PY

echo "=================================================================="
echo "STEP 8: BFT Fault Tolerance (3/4 succeeds, 2/4 rejects quorum)"
echo "=================================================================="
kill "$(cat "$DEVNET_DIR/node4/node.pid")"
sleep 1

VNETWORK_ENDPOINT=http://127.0.0.1:18081 VNETWORK_NETWORK_ID="$NETWORK_ID" \
  node - <<'JS'
import { ClientIdentity, VectorNetworkClient } from "./sdks/javascript/index.js";
const id = ClientIdentity.generate("bft-3of4-tester");
const client = new VectorNetworkClient(process.env.VNETWORK_ENDPOINT, id, process.env.VNETWORK_NETWORK_ID);
await client.connect();
await client.join(["NETWORK"]);
const sub = await client.submitProgram("bft_3of4.vx", `
space create BftSurvivesSpace { visibility = "public" }
region create BftSurvivesRegion in "BftSurvivesSpace" { prefix = "BFT"; visibility = "public"; section = 1; }
wallet create BftWallet in "BftSurvivesRegion" { name = "BFT Wallet"; }
`);
if (sub.status !== "COMMITTED") throw new Error("3/4 quorum should have committed!");
console.log("3/4 BFT quorum succeeded cleanly: program_id=", sub.program_id);
JS

kill "$(cat "$DEVNET_DIR/node3/node.pid")"
sleep 1

PRE_FAULT_STATE="$(curl -fsS http://127.0.0.1:18081/v1/network/status)"
VNETWORK_ENDPOINT=http://127.0.0.1:18081 VNETWORK_NETWORK_ID="$NETWORK_ID" \
  node - <<'JS'
import { ClientIdentity, VectorNetworkClient } from "./sdks/javascript/index.js";
const id = ClientIdentity.generate("bft-2of4-tester");
const client = new VectorNetworkClient(process.env.VNETWORK_ENDPOINT, id, process.env.VNETWORK_NETWORK_ID);
await client.connect();
let failed = false;
try {
  await client.join(["NETWORK"]);
} catch (err) {
  failed = true;
  console.log("2/4 minority correctly rejected:", err.message);
}
if (!failed) throw new Error("2/4 minority should NOT reach finality!");
JS

POST_FAULT_STATE="$(curl -fsS http://127.0.0.1:18081/v1/network/status)"
python3 - "$PRE_FAULT_STATE" "$POST_FAULT_STATE" <<'PY'
import json, sys
pre = json.loads(sys.argv[1])
post = json.loads(sys.argv[2])
assert pre["height"] == post["height"], f"Height changed under minority fault: {pre['height']} vs {post['height']}"
assert pre["state_root"] == post["state_root"], "State root mutated under minority fault!"
print("Verified 2/4 minority preserved exact height & state_root:", post["height"], post["state_root"])
PY

echo "=================================================================="
echo "STEP 9: Restart Node 3 & Node 4 -> WAL Recovery + P2P Sync Catch-up"
echo "=================================================================="
for i in 3 4; do
  NETWORK_CONSENSUS_TIMEOUT_MS=3500 \
    "$NODE_BIN" \
    --config "$DEVNET_DIR/node$i/node.toml" \
    --genesis-file "$DEVNET_DIR/genesis.json" \
    run >> "$DEVNET_DIR/node$i/node.log" 2>&1 &
  echo $! > "$DEVNET_DIR/node$i/node.pid"
done

for i in 3 4; do
  api_port=$((18080 + i))
  for _ in $(seq 1 40); do
    if curl -fsS "http://127.0.0.1:$api_port/healthz" >/dev/null 2>&1; then
      break
    fi
    sleep 0.25
  done
done

python3 - <<'PY'
import json, time, urllib.request

for attempt in range(60):
    statuses = {}
    for i in range(1, 5):
        statuses[i] = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{18080+i}/v1/network/status").read().decode())
    heights = {i: statuses[i]["height"] for i in range(1, 5)}
    roots = {i: statuses[i]["state_root"] for i in range(1, 5)}
    if len(set(heights.values())) == 1 and len(set(roots.values())) == 1:
        print("Full cluster recovered & synchronized over P2P:", heights, roots[1])
        break
    time.sleep(0.25)
else:
    raise SystemExit(f"Nodes failed to converge after restart: heights={heights}, roots={roots}")

for i in range(1, 5):
    proofs = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{18080+i}/v1/ledger/proofs").read().decode())
    assert proofs["chain_valid"] is True, f"node {i} invalid proof chain after recovery"
PY

echo "=================================================================="
echo "ALL ACCEPTANCE CHECKS PASSED CLEANLY!"
echo "=================================================================="
