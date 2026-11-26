#!/usr/bin/env bash
set -euo pipefail

export PATH="/root/.cargo/bin:/usr/local/go/bin:$PATH"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_DIR="${DEVNET_DIR:-$ROOT/.devnet}"
export DEVNET_DIR

cleanup() {
  echo "Cleaning up devnet nodes..."
  bash "$ROOT/scripts/devnet-down.sh" || true
  rm -rf "$DEVNET_DIR"
}
trap cleanup EXIT

echo "=================================================================="
echo "STEP 1: Cargo workspace unit & integration tests"
echo "=================================================================="
cargo test --workspace --manifest-path "$ROOT/Cargo.toml"

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
DEVNET_CLEAN=1 NETWORK_CONSENSUS_TIMEOUT_MS=3500 bash "$ROOT/scripts/devnet-up.sh"

# Verify libp2p peer connections >= 3 on node 1
N1_PEERS="$(curl -fsS http://127.0.0.1:18081/healthz | python3 -c 'import sys,json; print(json.load(sys.stdin)["connected_peers"])')"
echo "Node 1 connected libp2p peers: $N1_PEERS"
if [[ "$N1_PEERS" -lt 3 ]]; then
  echo "Expected >= 3 connected peers on Node 1, got $N1_PEERS" >&2
  exit 1
fi

echo "=================================================================="
echo "STEP 5: CLI join + ATLAS bootstrap + complete .vx/.vdx workflow"
echo "=================================================================="
CLI_HOME="$(mktemp -d)"
trap 'rm -rf "$CLI_HOME"; cleanup' EXIT
HOME="$CLI_HOME" "$VN_BIN" identity create --name "cli-acceptance-user" >/dev/null
HOME="$CLI_HOME" "$VN_BIN" connect --network vnetwork-devnet-1 --endpoint http://127.0.0.1:18081 >/dev/null
HOME="$CLI_HOME" "$VN_BIN" join --scope NETWORK --scope SPACE --scope REGION --scope WALLET --scope TOKEN >/dev/null
HOME="$CLI_HOME" "$VN_BIN" program submit "$ROOT/examples/vector-language/bootstrap-atlas.vx" >/dev/null
HOME="$CLI_HOME" "$VN_BIN" program submit "$ROOT/examples/vector-language/complete-network-workflow.vx" >/dev/null
HOME="$CLI_HOME" "$VN_BIN" ledger verify | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d["chain_valid"] is True; print("CLI ledger proof verified:", d["event_count"], "events, state_root=", d["state_root"])'

echo "=================================================================="
echo "STEP 6: Run ALL 5 live SDKs (Rust, JS, TS, Python, Go)"
echo "=================================================================="
VNETWORK_ENDPOINT=http://127.0.0.1:18081 \
VNETWORK_ENDPOINT_2=http://127.0.0.1:18082 \
VNETWORK_ENDPOINT_3=http://127.0.0.1:18083 \
VNETWORK_NETWORK_ID=vnetwork-devnet-1 \
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
echo "STEP 7: Verify atomic zero-partial-state rollback on failing .vx"
echo "=================================================================="
python3 - <<'PY'
import json, sys, urllib.request
sys.path.insert(0, "sdks/python")
from vnetwork_sdk import ClientIdentity, VectorNetworkClient

ep = "http://127.0.0.1:18081"
before = json.loads(urllib.request.urlopen(f"{ep}/v1/network/status").read().decode())

ident = ClientIdentity.generate("rollback-verifier")
c = VectorNetworkClient(ep, ident, expected_network_id="vnetwork-devnet-1")
c.connect()
c.join(["NETWORK", "SPACE", "REGION", "WALLET", "TOKEN"])

before_after_join = json.loads(urllib.request.urlopen(f"{ep}/v1/network/status").read().decode())
failing_vx = '''
space create ShouldRollbackSpace { visibility = "public" }
region create ShouldRollbackRegion in "ShouldRollbackSpace" { prefix = "RBK"; visibility = "public"; section = 1; }
wallet create ShouldRollbackWallet in "ShouldRollbackRegion" { name = "Rollback Wallet"; }
transfer "NONEXISTENT_TOK" from "ShouldRollbackWallet" to "MissingDst" amount 500;
'''
sub = c.submit_program("should_rollback.vx", failing_vx)
assert sub["status"] in ("FAILED", "REJECTED"), f"Expected FAILED/REJECTED, got {sub}"
assert sub["failed_operation_index"] == 3, f"Expected failed_operation_index=3, got {sub}"
after = json.loads(urllib.request.urlopen(f"{ep}/v1/network/status").read().decode())
assert after["height"] == before_after_join["height"], "Height changed on failed program!"
assert after["spaces"] == before_after_join["spaces"], "Partial space leaked on failed program!"
assert after["state_root"] == before_after_join["state_root"], "State root mutated on failed program!"
print("Verified atomic rollback: status=", sub["status"], "failed_op=", sub["failed_operation_index"], "state_root unchanged.")
PY

echo "=================================================================="
echo "STEP 8: BFT Fault Tolerance (3/4 succeeds, 2/4 rejects quorum)"
echo "=================================================================="
echo "Stopping Node 4 (remaining 3/4 = 300/400 >= 6667 bps -> MUST SUCCEED)..."
kill "$(cat "$DEVNET_DIR/node4/node.pid")"
sleep 1

VNETWORK_ENDPOINT=http://127.0.0.1:18081 VNETWORK_NETWORK_ID=vnetwork-devnet-1 \
  node - <<'JS'
import { ClientIdentity, VectorNetworkClient } from "./sdks/javascript/index.js";
const id = ClientIdentity.generate("bft-3of4-tester");
const client = new VectorNetworkClient(process.env.VNETWORK_ENDPOINT, id, process.env.VNETWORK_NETWORK_ID);
await client.connect();
await client.join(["NETWORK", "SPACE", "REGION", "WALLET", "TOKEN"]);
const sub = await client.submitProgram("bft_3of4.vx", `
space create BftSurvivesSpace { visibility = "public" }
region create BftSurvivesRegion in "BftSurvivesSpace" { prefix = "BFT"; visibility = "public"; section = 1; }
wallet create BftWallet in "BftSurvivesRegion" { name = "BFT Wallet"; }
`);
if (sub.status !== "COMMITTED") throw new Error("3/4 quorum should have committed!");
console.log("3/4 BFT quorum succeeded cleanly: height committed, program_id=", sub.program_id);
JS

echo "Stopping Node 3 (remaining 2/4 = 200/400 < 6667 bps -> MUST FAIL QUORUM)..."
kill "$(cat "$DEVNET_DIR/node3/node.pid")"
sleep 1

PRE_FAULT_STATE="$(curl -fsS http://127.0.0.1:18081/v1/network/status)"
VNETWORK_ENDPOINT=http://127.0.0.1:18081 VNETWORK_NETWORK_ID=vnetwork-devnet-1 \
  node - <<'JS'
import { ClientIdentity, VectorNetworkClient } from "./sdks/javascript/index.js";
const id = ClientIdentity.generate("bft-2of4-tester");
const client = new VectorNetworkClient(process.env.VNETWORK_ENDPOINT, id, process.env.VNETWORK_NETWORK_ID);
await client.connect();
let failed = false;
try {
  await client.join(["NETWORK", "SPACE"]);
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

echo "Waiting for restarted Node 3 & Node 4 to sync missing heights over libp2p..."
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

echo "Submitting post-recovery .vx transaction to verify resumed 4-node quorum..."
python3 - <<'PY'
import sys
sys.path.insert(0, "sdks/python")
from vnetwork_sdk import ClientIdentity, VectorNetworkClient

ep = "http://127.0.0.1:18084"
ident = ClientIdentity.generate("post-recovery-verifier")
c = VectorNetworkClient(ep, ident, expected_network_id="vnetwork-devnet-1")
c.connect()
c.join(["NETWORK", "SPACE", "REGION", "WALLET", "TOKEN"])
sub = c.submit_program("post_recovery.vx", '''
space create PostRecoverySpace { visibility = "public" }
region create PostRecoveryRegion in "PostRecoverySpace" { prefix = "PRC"; visibility = "public"; section = 1; }
wallet create PostRecoveryWallet in "PostRecoveryRegion" { name = "Recovery Wallet"; }
verify proof network;
''')
assert sub["status"] == "COMMITTED", f"Post-recovery program did not commit: {sub}"
print("Post-recovery 4-node quorum committed:", sub["program_id"], "state_root=", sub["final_state_root"])
PY

echo "=================================================================="
echo "ALL ACCEPTANCE CHECKS PASSED CLEANLY!"
echo "=================================================================="
