import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sdks" / "python"))

from vnetwork_sdk import ClientIdentity, blake3_hex, canonical_json_bytes  # noqa: E402

SEED_HEX = "1111111111111111111111111111111111111111111111111111111111111111"
NODE_SEED_HEX = "2222222222222222222222222222222222222222222222222222222222222222"
identity = ClientIdentity.from_keys("parity", SEED_HEX, NODE_SEED_HEX)
multi_chunk = "vector-network-" * 200
canon = canonical_json_bytes({"b": 2, "a": {"z": True, "m": [3, 1, 2]}})
sig = identity.participant_key.sign(canon)

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
}))
