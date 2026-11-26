#!/usr/bin/env bash
set -euo pipefail

export PATH="/root/.cargo/bin:/usr/local/go/bin:$PATH"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RAW_DEVNET_DIR="${DEVNET_DIR:-$ROOT/.devnet}"
NETWORK_ID="${NETWORK_ID:-vector-devnet-1}"
CONSENSUS_TIMEOUT_MS="${NETWORK_CONSENSUS_TIMEOUT_MS:-5000}"

resolve_safe_devnet_dir() {
  local raw="$1"
  if [[ -z "$raw" || "$raw" == *".."* ]]; then
    echo "Refusing unsafe devnet directory path: '$raw'" >&2
    exit 1
  fi
  if [[ -L "$raw" ]]; then
    echo "Refusing symlinked devnet directory: '$raw'" >&2
    exit 1
  fi
  python3 - "$raw" "$ROOT" "${HOME:-}" <<'PY'
import os, pathlib, sys
raw, root, home = sys.argv[1:4]
p = pathlib.Path(raw)
if ".." in p.parts:
    raise SystemExit(f"Refusing '..' path segment in devnet dir: {raw}")
parent = p.parent.resolve() if not p.exists() else p.resolve()
resolved = (parent / p.name) if not p.exists() else parent
root_res = pathlib.Path(root).resolve()
forbidden = {pathlib.Path("/"), root_res, root_res / ".git"}
if home:
    forbidden.add(pathlib.Path(home).resolve())
if resolved in forbidden or resolved in root_res.parents:
    raise SystemExit(f"Refusing dangerous devnet directory target: {resolved}")
print(str(resolved))
PY
}

DEVNET_DIR="$(resolve_safe_devnet_dir "$RAW_DEVNET_DIR")"

has_valid_owner_marker() {
  local dir="$1"
  [[ -f "$dir/.vnetwork-devnet-owner" ]] && grep -q '^owner=vnetwork-devnet$' "$dir/.vnetwork-devnet-owner"
}

safe_clean_devnet_dir() {
  local target="$1"
  if [[ -L "$target" ]]; then
    echo "Refusing to delete symlinked directory: '$target'" >&2
    exit 1
  fi
  if [[ ! -d "$target" ]]; then
    return 0
  fi
  if ! has_valid_owner_marker "$target" && [[ ! -f "$target/.vnetwork-devnet-marker" ]]; then
    echo "Refusing to delete '$target' because .vnetwork-devnet-owner marker is missing (user data preserved)." >&2
    exit 1
  fi
  rm -rf -- "$target"
}

if [[ -d "$DEVNET_DIR" ]]; then
  if ! has_valid_owner_marker "$DEVNET_DIR" && [[ ! -f "$DEVNET_DIR/.vnetwork-devnet-marker" ]]; then
    if [[ -n "$(ls -A "$DEVNET_DIR" 2>/dev/null || true)" ]]; then
      echo "Refusing to use non-empty unmanaged directory '$DEVNET_DIR' without .vnetwork-devnet-owner marker." >&2
      exit 1
    fi
  fi
fi

if [[ "${DEVNET_CLEAN:-0}" == "1" ]]; then
  safe_clean_devnet_dir "$DEVNET_DIR"
fi

mkdir -p "$DEVNET_DIR"
cat > "$DEVNET_DIR/.vnetwork-devnet-owner" <<EOF
owner=vnetwork-devnet
network_id=${NETWORK_ID}
canonical_dir=${DEVNET_DIR}
EOF
chmod 0600 "$DEVNET_DIR/.vnetwork-devnet-owner"
echo "vnetwork-devnet" > "$DEVNET_DIR/.vnetwork-devnet-marker"

PASSPHRASE_FILE="$DEVNET_DIR/.devnet_passphrase"
if [[ -z "${NETWORK_KEY_PASSPHRASE:-}" ]]; then
  if [[ ! -f "$PASSPHRASE_FILE" ]]; then
    (
      umask 077
      python3 - "$PASSPHRASE_FILE" <<'PY'
import pathlib, secrets, sys
p = pathlib.Path(sys.argv[1])
p.write_text(secrets.token_urlsafe(24))
p.chmod(0o600)
PY
    )
  fi
  NETWORK_KEY_PASSPHRASE="$(cat "$PASSPHRASE_FILE")"
fi
export NETWORK_KEY_PASSPHRASE

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
      --profile development \
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
    val_pk = init["validator_metadata"]["public_key_hex"]
    validators.append({
        "validator_id": f"val_{i}",
        "node_id": init["node_id"],
        "validator_pubkey_hex": val_pk,
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
    "drain_policy": {
        "policy_version": 1,
        "same_wallet": {"status": "CONFIGURED_BPS", "bps": 0},
        "different_wallets_same_region": {"status": "CONFIGURED_BPS", "bps": 0},
        "different_regions_same_space": {"status": "CONFIGURED_BPS", "bps": 50},
        "different_spaces": {"status": "CONFIGURED_BPS", "bps": 150},
    },
}

genesis_path = devnet_dir / "genesis.json"
if genesis_path.exists():
    existing = json.loads(genesis_path.read_text())
    if existing.get("network_id") != network_id or existing.get("initial_validators") != validators:
        raise SystemExit(
            f"Incompatible existing genesis.json in {devnet_dir} "
            f"(existing network_id={existing.get('network_id')}, expected={network_id}). "
            "Pass DEVNET_CLEAN=1 to perform a verified clean reset."
        )
else:
    genesis_path.write_text(json.dumps(genesis, indent=2))

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
    cfg_path="$DEVNET_DIR/node$i/node.toml"
    NETWORK_CONSENSUS_TIMEOUT_MS="$CONSENSUS_TIMEOUT_MS" \
    NETWORK_KEY_PASSPHRASE="$NETWORK_KEY_PASSPHRASE" \
      "$NODE_BIN" \
      --config "$cfg_path" \
      --genesis-file "$DEVNET_DIR/genesis.json" \
      run > "$DEVNET_DIR/node$i/node.log" 2>&1 &
    pid=$!
    echo "$pid" > "$DEVNET_DIR/node$i/node.pid"
    cat > "$DEVNET_DIR/node$i/node.meta" <<EOF
pid=${pid}
binary=${NODE_BIN}
config=${cfg_path}
devnet_dir=${DEVNET_DIR}
EOF
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

for _ in $(seq 1 30); do
  peers_n1="$(curl -fsS "http://127.0.0.1:18081/healthz" | python3 -c 'import sys,json; print(json.load(sys.stdin)["connected_peers"])')"
  if [[ "$peers_n1" -ge 3 ]]; then
    break
  fi
  sleep 0.25
done

echo "4-node Vector Network devnet is UP (dir=$DEVNET_DIR):"
for i in 1 2 3 4; do
  api_port=$((18080 + i))
  summary="$(curl -fsS "http://127.0.0.1:$api_port/healthz" | python3 -c "import sys,json; d=json.load(sys.stdin); print('node_id=' + str(d['node_id']) + ' height=' + str(d['height']) + ' peers=' + str(d['connected_peers']))")"
  echo "  Node $i: http://127.0.0.1:$api_port ($summary)"
done
