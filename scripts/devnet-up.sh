#!/usr/bin/env bash
set -euo pipefail

export PATH="/root/.cargo/bin:/usr/local/go/bin:$PATH"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_DIR="${DEVNET_DIR:-$ROOT/.devnet}"
NETWORK_ID="${NETWORK_ID:-vnetwork-devnet-1}"
CONSENSUS_TIMEOUT_MS="${NETWORK_CONSENSUS_TIMEOUT_MS:-5000}"

if [[ "${DEVNET_CLEAN:-0}" == "1" ]]; then
  rm -rf "$DEVNET_DIR"
fi
mkdir -p "$DEVNET_DIR"

echo "Building vnetwork-node and vn binaries..."
cargo build -q -p vnetwork-node -p vnetwork-cli --manifest-path "$ROOT/Cargo.toml"
NODE_BIN="$ROOT/target/debug/vnetwork-node"

for i in 1 2 3 4; do
  mkdir -p "$DEVNET_DIR/node$i/data"
  if [[ ! -f "$DEVNET_DIR/node$i/init.json" ]]; then
    "$NODE_BIN" init-key \
      --node-key "$DEVNET_DIR/node$i/node.key.json" \
      --validator-key "$DEVNET_DIR/node$i/validator.key.json" \
      --validator-id "val_$i" \
      --validator > "$DEVNET_DIR/node$i/init.json"
  fi
done

python3 - "$DEVNET_DIR" "$NETWORK_ID" <<'PY'
import json, pathlib, sys

devnet_dir = pathlib.Path(sys.argv[1])
network_id = sys.argv[2]
validators = []
peers = []
for i in range(1, 5):
    init = json.loads((devnet_dir / f"node{i}" / "init.json").read_text())
    validators.append({
        "validator_id": f"val_{i}",
        "node_id": init["node_id"],
        "validator_pubkey_hex": init["validator_pubkey_hex"],
        "weight": 100,
        "active": True,
        "joined_epoch": 1,
    })
    p2p_port = 17100 + i
    peers.append(f"/ip4/127.0.0.1/tcp/{p2p_port}/p2p/{init['peer_id']}")

genesis = {
    "network_id": network_id,
    "network_name": "Vector Local Devnet",
    "profile": "DEVELOPMENT",
    "protocol_version": "vector-network/1.0.0",
    "genesis_timestamp_ms": 1764150000000,
    "initial_validators": validators,
    "allow_bootstrap_atlas": True,
}
(devnet_dir / "genesis.json").write_text(json.dumps(genesis, indent=2))

for i in range(1, 5):
    p2p_port = 17100 + i
    api_port = 18080 + i
    boot = [p for j, p in enumerate(peers, 1) if j != i]
    toml_cfg = f'''network_id = "{network_id}"
network_name = "Vector Local Devnet"
profile = "DEVELOPMENT"
protocol_version = "vector-network/1.0.0"
node_name = "vn-dev-node-{i}"
node_kind = "VALIDATOR_NODE"
enable_p2p = true
enable_public_api = true
enable_validator = true
enable_relay_server = true
p2p_listen_addresses = ["/ip4/127.0.0.1/tcp/{p2p_port}"]
advertised_addresses = ["/ip4/127.0.0.1/tcp/{p2p_port}"]
bootstrap_peers = {json.dumps(boot)}
discovery_mode = "hybrid"
public_api_bind = "127.0.0.1:{api_port}"
public_api_url = "http://127.0.0.1:{api_port}"
storage_path = "{(devnet_dir / f'node{i}' / 'data').as_posix()}"
node_identity_path = "{(devnet_dir / f'node{i}' / 'node.key.json').as_posix()}"
validator_key_path = "{(devnet_dir / f'node{i}' / 'validator.key.json').as_posix()}"
validator_id = "val_{i}"
quorum_threshold_bps = 6667
allow_bootstrap_atlas = true
'''
    (devnet_dir / f"node{i}" / "node.toml").write_text(toml_cfg)
PY

for i in 1 2 3 4; do
  if [[ -f "$DEVNET_DIR/node$i/node.pid" ]] && kill -0 "$(cat "$DEVNET_DIR/node$i/node.pid")" 2>/dev/null; then
    echo "Node $i already running (pid $(cat "$DEVNET_DIR/node$i/node.pid"))"
  else
    NETWORK_CONSENSUS_TIMEOUT_MS="$CONSENSUS_TIMEOUT_MS" \
      "$NODE_BIN" \
      --config "$DEVNET_DIR/node$i/node.toml" \
      --genesis-file "$DEVNET_DIR/genesis.json" \
      run > "$DEVNET_DIR/node$i/node.log" 2>&1 &
    echo $! > "$DEVNET_DIR/node$i/node.pid"
  fi
done

echo "Waiting for 4 validator nodes to become healthy & peer-connected..."
for i in 1 2 3 4; do
  api_port=$((18080 + i))
  ok=0
  for _ in $(seq 1 40); do
    if curl -fsS "http://127.0.0.1:$api_port/healthz" >/dev/null 2>&1; then
      ok=1
      break
    fi
    sleep 0.25
  done
  if [[ "$ok" -ne 1 ]]; then
    echo "Node $i failed to start on port $api_port. Logs:" >&2
    cat "$DEVNET_DIR/node$i/node.log" >&2 || true
    exit 1
  fi
done

# Give libp2p mesh a moment to complete identify + gossipsub peering
for _ in $(seq 1 30); do
  peers_n1="$(curl -fsS "http://127.0.0.1:18081/healthz" | python3 -c 'import sys,json; print(json.load(sys.stdin)["connected_peers"])')"
  if [[ "$peers_n1" -ge 3 ]]; then
    break
  fi
  sleep 0.25
done

echo "4-node Vector Network devnet is UP:"
for i in 1 2 3 4; do
  api_port=$((18080 + i))
  summary="$(curl -fsS "http://127.0.0.1:$api_port/healthz" | python3 -c "import sys,json; d=json.load(sys.stdin); print('node_id=' + str(d['node_id']) + ' height=' + str(d['height']) + ' peers=' + str(d['connected_peers']))")"
  echo "  Node $i: http://127.0.0.1:$api_port ($summary)"
done
