import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sdks" / "python"))

from vnetwork_sdk import (  # noqa: E402
    ClientIdentity,
    KeypairMaterial,
    VectorNetworkClient,
    VectorNetworkError,
    blake3_hex,
    canonical_json_bytes,
    canonical_transfer_approval_object,
    derive_node_id,
    derive_participant_id,
    verify_ed25519,
)
from vnetwork_sdk.ed25519 import verify as ed25519_verify  # noqa: E402


class PythonSdkSecurityTests(unittest.TestCase):
    def test_keypair_repr_redacts_private_key(self):
        kp = KeypairMaterial.from_private_hex("participant", "11" * 32)
        rendered = repr(kp)
        self.assertIn("[REDACTED]", rendered)
        self.assertNotIn("11" * 32, rendered)

    def test_participant_and_node_id_domain_separation(self):
        kp = KeypairMaterial.from_private_hex("participant", "11" * 32)
        pid = derive_participant_id(kp.public_key_hex)
        nid = derive_node_id(kp.public_key_hex)
        self.assertTrue(pid.startswith("prt_"))
        self.assertTrue(nid.startswith("nod_"))
        self.assertNotEqual(pid, nid)

    def test_transfer_approval_domain_u128_and_no_drain_bps(self):
        huge = "123456789012345678901234567890"
        obj = canonical_transfer_approval_object(
            network_id="vector-devnet-1",
            token_id="tok_demo",
            from_wallet_id="wal_a",
            to_wallet_id="wal_b",
            amount=int(huge),
        )
        self.assertEqual(obj["domain"], "vnetwork/transfer-approval/v1")
        self.assertNotIn("drain_bps", obj)
        self.assertEqual(obj["amount"], huge)
        with self.assertRaises(ValueError):
            canonical_transfer_approval_object("net", "tok", "a", "b", -1)
        with self.assertRaises(ValueError):
            canonical_transfer_approval_object("net", "tok", "a", "b", "12.5")

    def test_rejects_weak_identity_pubkey_and_tampered_payload(self):
        with self.assertRaises(Exception):
            ed25519_verify(bytes(32), b"message", bytes(64))
        self.assertFalse(verify_ed25519("0" * 64, b"message", "00" * 64))
        self.assertFalse(verify_ed25519("01" + "0" * 62, b"message", "00" * 64))
        self.assertFalse(verify_ed25519("not-hex", b"message", "00" * 64))

        ident = ClientIdentity.generate("unit-test")
        payload = canonical_json_bytes({"b": 2, "a": 1})
        sig_hex = ident.participant_key.sign(payload)
        self.assertTrue(verify_ed25519(ident.participant_key.public_key_hex, payload, sig_hex))
        self.assertFalse(
            verify_ed25519(
                ident.participant_key.public_key_hex,
                canonical_json_bytes({"b": 3, "a": 1}),
                sig_hex,
            )
        )
        self.assertEqual(len(blake3_hex(payload)), 64)

    def test_module_loader_rejects_traversal_and_symlink_escape(self):
        ident = ClientIdentity.generate("mod-test")
        client = VectorNetworkClient("http://127.0.0.1:8080", ident)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proj = root / "proj"
            proj.mkdir()
            (proj / "ok.vdx").write_text('space create Ok { visibility = "public" }\n', encoding="utf-8")
            outside = root / "secret.vdx"
            outside.write_text('space create Secret { visibility = "public" }\n', encoding="utf-8")
            (proj / "escape.vdx").symlink_to(outside)

            mods = client.load_modules_for_source('import "ok.vdx";\nquery network;\n', proj)
            self.assertIn("ok.vdx", mods)

            with self.assertRaises(VectorNetworkError):
                client.load_modules_for_source('import "../secret.vdx";\n', proj)
            with self.assertRaises(VectorNetworkError):
                client.load_modules_for_source(f'import "{outside}";\n', proj)
            with self.assertRaises(VectorNetworkError):
                client.load_modules_for_source('import "escape.vdx";\n', proj)

    def test_contracts_loans_and_explorer_methods_exposed(self):
        ident = ClientIdentity.from_keys("py-parity", "11" * 32, "22" * 32)
        client = VectorNetworkClient("http://127.0.0.1:8080", ident, "vector-devnet-1")
        for method in (
            "list_spaces",
            "list_nodes",
            "get_node_details",
            "get_explorer_network",
            "list_contracts",
            "get_contract",
            "list_loans",
            "get_loan",
            "create_contract",
            "execute_contract",
            "create_loan",
            "execute_loan",
            "submit_operation",
        ):
            self.assertTrue(callable(getattr(client, method)), f"Missing {method}")


if __name__ == "__main__":
    unittest.main()

