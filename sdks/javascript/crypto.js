import crypto from "node:crypto";
import { blake3Hex } from "./blake3.js";

// PKCS#8 DER prefix for 32-byte Ed25519 private key seed:
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
// SPKI DER prefix for 32-byte Ed25519 public key:
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function derivePrefixedId(prefix, domain, materialBytes) {
  const buf = Buffer.concat([
    Buffer.from(`${domain}:`, "utf8"),
    Buffer.isBuffer(materialBytes) ? materialBytes : Buffer.from(materialBytes),
  ]);
  const digest = blake3Hex(buf);
  return `${prefix}_${digest.slice(0, 24)}`;
}

export function deriveParticipantId(pubkeyHex) {
  return derivePrefixedId("prt", "vnetwork/participant-id-v1", Buffer.from(pubkeyHex, "utf8"));
}

export function deriveNodeId(pubkeyHex) {
  return derivePrefixedId("nod", "vnetwork/node-id-v1", Buffer.from(pubkeyHex, "utf8"));
}

export function generateKeypair(role = "participant") {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" });
  const pubRaw = spki.subarray(spki.length - 32);
  const privRaw = pkcs8.subarray(pkcs8.length - 32);
  const publicKeyHex = pubRaw.toString("hex");
  const privateKeyHex = privRaw.toString("hex");
  const derivedId = role === "node" ? deriveNodeId(publicKeyHex) : deriveParticipantId(publicKeyHex);
  return {
    key_role: role,
    derived_id: derivedId,
    public_key_hex: publicKeyHex,
    private_key_hex: privateKeyHex,
  };
}

export function keypairFromPrivateHex(role, privateKeyHex) {
  const privRaw = Buffer.from(privateKeyHex.trim(), "hex");
  if (privRaw.length !== 32) {
    throw new Error("Ed25519 private key must be 32 bytes hex");
  }
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, privRaw]);
  const privObj = crypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const pubObj = crypto.createPublicKey(privObj);
  const spki = pubObj.export({ format: "der", type: "spki" });
  const publicKeyHex = spki.subarray(spki.length - 32).toString("hex");
  const derivedId = role === "node" ? deriveNodeId(publicKeyHex) : deriveParticipantId(publicKeyHex);
  return {
    key_role: role,
    derived_id: derivedId,
    public_key_hex: publicKeyHex,
    private_key_hex: privRaw.toString("hex"),
  };
}

export function signEd25519(privateKeyHex, messageBytes) {
  const privRaw = Buffer.from(privateKeyHex.trim(), "hex");
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, privRaw]);
  const key = crypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const sig = crypto.sign(null, Buffer.from(messageBytes), key);
  return sig.toString("hex");
}

export function verifyEd25519(publicKeyHex, messageBytes, signatureHex) {
  const pubRaw = Buffer.from(publicKeyHex.trim(), "hex");
  const spki = Buffer.concat([ED25519_SPKI_PREFIX, pubRaw]);
  const key = crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
  return crypto.verify(null, Buffer.from(messageBytes), key, Buffer.from(signatureHex.trim(), "hex"));
}

export class ClientIdentity {
  constructor(displayName, participantKey, nodeKey) {
    this.display_name = displayName;
    this.participant_key = participantKey;
    this.node_key = nodeKey;
    this.participant_id = deriveParticipantId(participantKey.public_key_hex);
    this.node_id = deriveNodeId(nodeKey.public_key_hex);
  }

  static generate(displayName) {
    return new ClientIdentity(
      displayName,
      generateKeypair("participant"),
      generateKeypair("node"),
    );
  }

  static fromKeys(displayName, participantPrivHex, nodePrivHex) {
    return new ClientIdentity(
      displayName,
      keypairFromPrivateHex("participant", participantPrivHex),
      keypairFromPrivateHex("node", nodePrivHex),
    );
  }
}

export const PROTOCOL_VERSION = "vector-network/1.0.0";
export const LANGUAGE_VERSION = "v-langx/1.2.0";
export const COMPILER_VERSION = "vectorspace-compiler/1.2.0";

export function canonicalProgramSubmitObject({
  actorPubkey,
  fileName,
  sourceBytes,
  modules = {},
  networkId,
  requestId,
  nonce,
  executionParams = {},
}) {
  const sourceHash = blake3Hex(sourceBytes);
  const fileKind = fileName.endsWith(".vdx") ? "vdx" : "vx";
  const moduleHashes = {};
  for (const k of Object.keys(modules).sort()) {
    moduleHashes[k] = blake3Hex(modules[k]);
  }
  return {
    actor_pubkey: actorPubkey,
    compiler_version: COMPILER_VERSION,
    execution_params: executionParams,
    file_kind: fileKind,
    file_name: fileName,
    language_version: LANGUAGE_VERSION,
    module_hashes: moduleHashes,
    network_id: networkId,
    nonce,
    protocol_version: PROTOCOL_VERSION,
    request_id: requestId,
    source_hash: sourceHash,
  };
}

export function canonicalWalletPopObject({
  networkId,
  walletId,
  participantIdentity,
  authorizedPubkey,
  purpose,
  nonce,
  expiresAtMs = null,
}) {
  return {
    authorized_pubkey: authorizedPubkey,
    expires_at_ms: expiresAtMs,
    network_id: networkId,
    nonce,
    participant_identity: participantIdentity,
    protocol_version: PROTOCOL_VERSION,
    purpose,
    wallet_id: walletId,
  };
}

export function canonicalTransferApprovalObject({
  networkId,
  tokenId,
  fromWalletId,
  toWalletId,
  amount,
  drainBps = null,
}) {
  return {
    amount: String(amount),
    drain_bps: drainBps,
    from_wallet_id: fromWalletId,
    network_id: networkId,
    protocol_version: PROTOCOL_VERSION,
    to_wallet_id: toWalletId,
    token_id: tokenId,
  };
}

