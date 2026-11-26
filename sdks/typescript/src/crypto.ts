import crypto from "node:crypto";
import { blake3Hex } from "./blake3.js";
import type { KeypairMaterial } from "./types.js";

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function derivePrefixedId(prefix: string, domain: string, materialBytes: Uint8Array): string {
  const prefixBytes = Buffer.from(`${domain}:`, "utf8");
  const combined = Buffer.concat([prefixBytes, Buffer.from(materialBytes)]);
  return `${prefix}_${blake3Hex(combined).slice(0, 24)}`;
}

export function deriveParticipantId(pubkeyHex: string): string {
  return derivePrefixedId("prt", "vnetwork/participant-id-v1", Buffer.from(pubkeyHex, "utf8"));
}

export function deriveNodeId(pubkeyHex: string): string {
  return derivePrefixedId("nod", "vnetwork/node-id-v1", Buffer.from(pubkeyHex, "utf8"));
}

export function generateKeypair(role: string = "participant"): KeypairMaterial {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" });
  const publicKeyHex = spki.subarray(spki.length - 32).toString("hex");
  const privateKeyHex = pkcs8.subarray(pkcs8.length - 32).toString("hex");
  const derived_id = role === "node" ? deriveNodeId(publicKeyHex) : deriveParticipantId(publicKeyHex);
  return {
    key_role: role,
    derived_id,
    public_key_hex: publicKeyHex,
    private_key_hex: privateKeyHex,
  };
}

export function keypairFromPrivateHex(role: string, privateKeyHex: string): KeypairMaterial {
  const privRaw = Buffer.from(privateKeyHex.trim(), "hex");
  if (privRaw.length !== 32) {
    throw new Error("Ed25519 private key must be 32 bytes hex");
  }
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, privRaw]);
  const privObj = crypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const pubObj = crypto.createPublicKey(privObj);
  const spki = pubObj.export({ format: "der", type: "spki" });
  const publicKeyHex = spki.subarray(spki.length - 32).toString("hex");
  const derived_id = role === "node" ? deriveNodeId(publicKeyHex) : deriveParticipantId(publicKeyHex);
  return {
    key_role: role,
    derived_id,
    public_key_hex: publicKeyHex,
    private_key_hex: privRaw.toString("hex"),
  };
}

export function signEd25519(privateKeyHex: string, messageBytes: Uint8Array): string {
  const privRaw = Buffer.from(privateKeyHex.trim(), "hex");
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, privRaw]);
  const key = crypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  return crypto.sign(null, Buffer.from(messageBytes), key).toString("hex");
}

export class ClientIdentity {
  readonly display_name: string;
  readonly participant_key: KeypairMaterial;
  readonly node_key: KeypairMaterial;
  readonly participant_id: string;
  readonly node_id: string;

  constructor(displayName: string, participantKey: KeypairMaterial, nodeKey: KeypairMaterial) {
    this.display_name = displayName;
    this.participant_key = participantKey;
    this.node_key = nodeKey;
    this.participant_id = deriveParticipantId(participantKey.public_key_hex);
    this.node_id = deriveNodeId(nodeKey.public_key_hex);
  }

  static generate(displayName: string): ClientIdentity {
    return new ClientIdentity(
      displayName,
      generateKeypair("participant"),
      generateKeypair("node"),
    );
  }

  static fromKeys(displayName: string, participantPrivHex: string, nodePrivHex: string): ClientIdentity {
    return new ClientIdentity(
      displayName,
      keypairFromPrivateHex("participant", participantPrivHex),
      keypairFromPrivateHex("node", nodePrivHex),
    );
  }
}
