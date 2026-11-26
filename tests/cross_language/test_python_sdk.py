import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sdks" / "python"))

from vnetwork_sdk import (  # noqa: E402
    ClientIdentity,
    KeypairMaterial,
    blake3_hex,
    canonical_json_bytes,
    canonical_transfer_approval_object,
)
from vnetwork_sdk.ed25519 import verify as ed25519_verify  # noqa: E402


class PythonSdkSecurityTests(unittest.TestCase):
    def test_keypair_repr_redacts_private_key(self):
        kp = KeypairMaterial.from_private_hex("participant", "11" * 32)
        rendered = repr(kp)
        self.assertIn("[REDACTED]", rendered)
        self.assertNotIn("11" * 32, rendered)

    def test_transfer_approval_domain_and_no_drain_bps(self):
        obj = canonical_transfer_approval_object(
            network_id="vector-devnet-1",
            token_id="tok_demo",
            from_wallet_id="wal_a",
            to_wallet_id="wal_b",
            amount=500,
        )
        self.assertEqual(obj["domain"], "vnetwork/transfer-approval/v1")
        self.assertNotIn("drain_bps", obj)
        self.assertEqual(obj["amount"], "500")

    def test_rejects_weak_identity_pubkey(self):
        with self.assertRaises(Exception):
            ed25519_verify(bytes(32), b"message", bytes(64))

    def test_sign_and_verify_roundtrip(self):
        ident = ClientIdentity.generate("unit-test")
        payload = canonical_json_bytes({"b": 2, "a": 1})
        sig_hex = ident.participant_key.sign(payload)
        ed25519_verify(
            bytes.fromhex(ident.participant_key.public_key_hex),
            payload,
            bytes.fromhex(sig_hex),
        )
        self.assertEqual(len(blake3_hex(payload)), 64)


if __name__ == "__main__":
    unittest.main()
