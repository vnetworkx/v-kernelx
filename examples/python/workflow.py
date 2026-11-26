import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sdks" / "python"))

from vnetwork_sdk import ClientIdentity, VectorNetworkClient  # noqa: E402


def main() -> None:
    endpoint = os.environ.get("VNETWORK_ENDPOINT", "http://127.0.0.1:8080")
    network_id = os.environ.get("VNETWORK_NETWORK_ID", "vector-devnet-1")
    vx_file = sys.argv[1] if len(sys.argv) > 1 else None

    identity = ClientIdentity.generate("python-sdk-participant")
    assert identity.participant_key.public_key_hex != identity.node_key.public_key_hex

    client = VectorNetworkClient(endpoint, identity, expected_network_id=network_id)
    info = client.connect()
    print(f"Connected via Python SDK to {info['network_id']} (height={info['height']})")

    join_res = client.join(["NETWORK", "SPACE", "REGION", "WALLET", "TOKEN"])
    print("Joined participant:", join_res["participant"]["participant_id"])

    if vx_file:
        submission = client.submit_vx_file(vx_file)
    else:
        source = """
space create PySdkSpace {
    name = "Python SDK Space";
    visibility = "public";
}
region create PySdkRegion in "PySdkSpace" {
    prefix = "PYS";
    visibility = "public";
    section = 1;
}
wallet create PyWalletA in "PySdkRegion" {
    name = "Py Wallet A";
}
wallet create PyWalletB in "PySdkRegion" {
    name = "Py Wallet B";
}
token create PYTOK in "PyWalletA" {
    name = "Python Token";
    symbol = "PYTOK";
    dimensions = 3;
    vector = [15000, 1000, 0];
    max_supply = 15000;
    drain_bps = 100;
    purpose = "Python SDK integration";
    external_monetary_value = "None";
}
transfer "PYTOK" from "PyWalletA" to "PyWalletB" amount 250;
verify proof network;
"""
        submission = client.submit_program("py_workflow.vx", source)

    assert submission["status"] == "COMMITTED", f"Unexpected status: {submission}"
    print(f"Committed Python program {submission['program_id']} root={submission['final_state_root']}")

    token_ent = next((e for e in submission["created_entities"] if e["kind"] == "token"), None)
    if token_ent:
        rec = client.verify_reconstruction("token", token_ent["id"])
        assert rec["verified"] is True
        print(f"Verified Python reconstruction for {token_ent['id']}: {rec['reconstructed_hash']}")


if __name__ == "__main__":
    main()
