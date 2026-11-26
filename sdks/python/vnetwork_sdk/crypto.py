"""Identity derivation and Ed25519 key management matching Vector Network Rust ids.rs."""

from dataclasses import dataclass
import secrets
from .blake3 import blake3_hex
from .ed25519 import public_key_from_seed, sign as ed25519_sign


def derive_prefixed_id(prefix: str, domain: str, material: bytes) -> str:
    digest = blake3_hex(domain.encode("utf-8") + b":" + material)
    return f"{prefix}_{digest[:24]}"


def derive_participant_id(pubkey_hex: str) -> str:
    return derive_prefixed_id("prt", "vnetwork/participant-id-v1", pubkey_hex.encode("utf-8"))


def derive_node_id(pubkey_hex: str) -> str:
    return derive_prefixed_id("nod", "vnetwork/node-id-v1", pubkey_hex.encode("utf-8"))


@dataclass
class KeypairMaterial:
    key_role: str
    derived_id: str
    public_key_hex: str
    private_key_hex: str

    @classmethod
    def generate(cls, role: str = "participant") -> "KeypairMaterial":
        seed = secrets.token_bytes(32)
        return cls.from_private_hex(role, seed.hex())

    @classmethod
    def from_private_hex(cls, role: str, private_hex: str) -> "KeypairMaterial":
        seed = bytes.fromhex(private_hex.strip())
        pub_hex = public_key_from_seed(seed).hex()
        did = derive_node_id(pub_hex) if role == "node" else derive_participant_id(pub_hex)
        return cls(
            key_role=role,
            derived_id=did,
            public_key_hex=pub_hex,
            private_key_hex=seed.hex(),
        )

    def sign(self, message: bytes) -> str:
        seed = bytes.fromhex(self.private_key_hex)
        return ed25519_sign(seed, message).hex()


@dataclass
class ClientIdentity:
    display_name: str
    participant_key: KeypairMaterial
    node_key: KeypairMaterial
    participant_id: str
    node_id: str

    @classmethod
    def generate(cls, display_name: str) -> "ClientIdentity":
        pk = KeypairMaterial.generate("participant")
        nk = KeypairMaterial.generate("node")
        return cls(
            display_name=display_name,
            participant_key=pk,
            node_key=nk,
            participant_id=pk.derived_id,
            node_id=nk.derived_id,
        )

    @classmethod
    def from_keys(
        cls, display_name: str, participant_priv_hex: str, node_priv_hex: str
    ) -> "ClientIdentity":
        pk = KeypairMaterial.from_private_hex("participant", participant_priv_hex)
        nk = KeypairMaterial.from_private_hex("node", node_priv_hex)
        return cls(
            display_name=display_name,
            participant_key=pk,
            node_key=nk,
            participant_id=pk.derived_id,
            node_id=nk.derived_id,
        )
