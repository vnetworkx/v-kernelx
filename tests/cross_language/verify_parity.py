import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sdks" / "python"))

from vnetwork_sdk import (  # noqa: E402
    ClientIdentity,
    blake3_hex,
    canonical_json_bytes,
    canonical_program_submit_object,
    canonical_transfer_approval_object,
    canonical_wallet_pop_object,
)

SEED_HEX = "1111111111111111111111111111111111111111111111111111111111111111"
NODE_SEED_HEX = "2222222222222222222222222222222222222222222222222222222222222222"
identity = ClientIdentity.from_keys("parity", SEED_HEX, NODE_SEED_HEX)
multi_chunk = "vector-network-" * 200
canon = canonical_json_bytes({"b": 2, "nil": None, "html": "<a>&", "a": {"z": True, "m": [3, 1, 2]}})
sig = identity.participant_key.sign(canon)

submit_canon = canonical_json_bytes(canonical_program_submit_object(
    actor_pubkey=identity.participant_key.public_key_hex,
    file_name="bootstrap-atlas.vx",
    source_bytes="Wallet Main;",
    modules={"policies.vdx": "Space ATLAS;"},
    network_id="vector-devnet-1",
    request_id="req_0001",
    nonce=7,
    execution_params={"dry": False},
))
submit_sig = identity.participant_key.sign(submit_canon)

pop_canon = canonical_json_bytes(canonical_wallet_pop_object(
    network_id="vector-devnet-1",
    wallet_id="wal_demo",
    participant_identity=identity.participant_id,
    authorized_pubkey=identity.node_key.public_key_hex,
    purpose="wallet_key_authorization",
    nonce="pop_1",
    expires_at_ms=None,
))
pop_sig = identity.node_key.sign(pop_canon)

xfer_canon = canonical_json_bytes(canonical_transfer_approval_object(
    network_id="vector-devnet-1",
    token_id="tok_atlas",
    from_wallet_id="wal_a",
    to_wallet_id="wal_b",
    amount=250,
))
xfer_sig = identity.participant_key.sign(xfer_canon)

print(json.dumps({
    "lang": "python",
    "empty_b3": blake3_hex(""),
    "hello_b3": blake3_hex("hello world"),
    "multi_b3": blake3_hex(multi_chunk),
    "canon_str": canon.decode("utf-8"),
    "participant_pubkey": identity.participant_key.public_key_hex,
    "participant_id": identity.participant_id,
    "node_id": identity.node_id,
    "sig": sig,
    "submit_str": submit_canon.decode("utf-8"),
    "submit_sig": submit_sig,
    "pop_str": pop_canon.decode("utf-8"),
    "pop_sig": pop_sig,
    "xfer_str": xfer_canon.decode("utf-8"),
    "xfer_sig": xfer_sig,
}))
