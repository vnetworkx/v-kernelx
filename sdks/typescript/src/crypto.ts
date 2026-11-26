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

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export const PROTOCOL_VERSION = "vector-network/1.0.0";
export const LANGUAGE_VERSION = "v-langx/1.2.0";
export const COMPILER_VERSION = "vectorspace-compiler/1.2.0";
export const DOM_TRANSFER_APPROVAL_V1 = "vnetwork/transfer-approval/v1";

const WEAK_PUBKEY_HEXES = new Set([
  "0".repeat(64),
  "01" + "0".repeat(62),
]);

export function verifyEd25519(
  publicKeyHex: string,
  messageBytes: Uint8Array,
  signatureHex: string,
): boolean {
  const pkClean = publicKeyHex.trim().toLowerCase();
  const sigClean = signatureHex.trim().toLowerCase();
  if (
    !/^[0-9a-f]{64}$/.test(pkClean) ||
    WEAK_PUBKEY_HEXES.has(pkClean) ||
    !/^[0-9a-f]{128}$/.test(sigClean)
  ) {
    return false;
  }
  const pubRaw = Buffer.from(pkClean, "hex");
  const sigRaw = Buffer.from(sigClean, "hex");
  if (pubRaw.length !== 32 || sigRaw.length !== 64) {
    return false;
  }
  try {
    const spki = Buffer.concat([ED25519_SPKI_PREFIX, pubRaw]);
    const key = crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
    return crypto.verify(
      null,
      Buffer.from(messageBytes),
      key,
      sigRaw,
    );
  } catch {
    return false;
  }
}

export function canonicalProgramSubmitObject(params: {
  actorPubkey: string;
  fileName: string;
  sourceBytes: string;
  modules?: Record<string, string>;
  networkId: string;
  requestId: string;
  nonce: number;
  executionParams?: Record<string, unknown>;
}): Record<string, unknown> {
  const modules = params.modules ?? {};
  const sourceHash = blake3Hex(params.sourceBytes);
  const fileKind = params.fileName.endsWith(".vdx") ? "vdx" : "vx";
  const moduleHashes: Record<string, string> = {};
  for (const k of Object.keys(modules).sort()) {
    moduleHashes[k] = blake3Hex(modules[k]);
  }
  return {
    actor_pubkey: params.actorPubkey,
    compiler_version: COMPILER_VERSION,
    execution_params: params.executionParams ?? {},
    file_kind: fileKind,
    file_name: params.fileName,
    language_version: LANGUAGE_VERSION,
    module_hashes: moduleHashes,
    network_id: params.networkId,
    nonce: params.nonce,
    protocol_version: PROTOCOL_VERSION,
    request_id: params.requestId,
    source_hash: sourceHash,
  };
}

export function canonicalWalletPopObject(params: {
  networkId: string;
  walletId: string;
  participantIdentity: string;
  authorizedPubkey: string;
  purpose: string;
  nonce: string;
  expiresAtMs?: number | null;
}): Record<string, unknown> {
  return {
    authorized_pubkey: params.authorizedPubkey,
    expires_at_ms: params.expiresAtMs ?? null,
    network_id: params.networkId,
    nonce: params.nonce,
    participant_identity: params.participantIdentity,
    protocol_version: PROTOCOL_VERSION,
    purpose: params.purpose,
    wallet_id: params.walletId,
  };
}

export function formatDecimalAmount(amount: number | bigint | string): string {
  if (typeof amount === "bigint") {
    if (amount < 0n) throw new Error("Amount must be non-negative");
    return amount.toString(10);
  }
  if (typeof amount === "number") {
    if (!Number.isFinite(amount) || !Number.isInteger(amount) || amount < 0) {
      throw new Error("Numeric amount must be a finite non-negative integer; use string/bigint for u128");
    }
    return String(amount);
  }
  const clean = amount.trim();
  if (!/^\d+$/.test(clean)) {
    throw new Error(`Invalid unsigned integer amount string: ${amount}`);
  }
  return BigInt(clean).toString(10);
}

export function canonicalTransferApprovalObject(params: {
  networkId: string;
  tokenId: string;
  fromWalletId: string;
  toWalletId: string;
  amount: number | bigint | string;
}): Record<string, unknown> {
  return {
    amount: formatDecimalAmount(params.amount),
    domain: DOM_TRANSFER_APPROVAL_V1,
    from_wallet_id: params.fromWalletId,
    network_id: params.networkId,
    protocol_version: PROTOCOL_VERSION,
    to_wallet_id: params.toWalletId,
    token_id: params.tokenId,
  };
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
