import { blake3Hex } from "./blake3.js";
import { canonicalJsonBytes } from "./canonical.js";
import type {
  KeypairMaterial,
  NetworkInfo,
  NetworkOperation,
  ParticipationLevel,
  ProgramSubmission,
} from "./types.js";

const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

export const PROTOCOL_VERSION = "vector-network/1.0.0";
export const LANGUAGE_VERSION = "v-langx/1.2.0";
export const COMPILER_VERSION = "vectorspace-compiler/1.2.0";
export const DOM_TRANSFER_APPROVAL_V1 = "vnetwork/transfer-approval/v1";

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  const clean = hex.trim();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export async function generateBrowserKeypair(role = "participant"): Promise<KeypairMaterial> {
  const kp = (await globalThis.crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array(await globalThis.crypto.subtle.exportKey("spki", kp.publicKey));
  const pkcs8 = new Uint8Array(await globalThis.crypto.subtle.exportKey("pkcs8", kp.privateKey));
  const publicKeyHex = toHex(spki.slice(spki.length - 32));
  const privateKeyHex = toHex(pkcs8.slice(pkcs8.length - 32));
  const prefix = role === "node" ? "nod" : "prt";
  const domain = role === "node" ? "vnetwork/node-id-v1" : "vnetwork/participant-id-v1";
  const derived_id = `${prefix}_${blake3Hex(new TextEncoder().encode(`${domain}:${publicKeyHex}`)).slice(0, 24)}`;
  return { key_role: role, derived_id, public_key_hex: publicKeyHex, private_key_hex: privateKeyHex };
}

export async function signBrowserEd25519(privateKeyHex: string, messageBytes: Uint8Array): Promise<string> {
  const raw = fromHex(privateKeyHex);
  const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + raw.length);
  pkcs8.set(ED25519_PKCS8_PREFIX, 0);
  pkcs8.set(raw, ED25519_PKCS8_PREFIX.length);
  const key = await globalThis.crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
  const sig = await globalThis.crypto.subtle.sign("Ed25519", key, new Uint8Array(messageBytes));
  return toHex(new Uint8Array(sig));
}

export class BrowserVectorNetworkClient {
  connectedNetworkId: string | null = null;
  private nonce = 1;

  constructor(
    readonly baseUrl: string,
    readonly identity: { display_name: string; participant_key: KeypairMaterial; node_key: KeypairMaterial },
    readonly expectedNetworkId: string | null = null,
  ) {}

  async connect(): Promise<NetworkInfo> {
    const res = await fetch(`${this.baseUrl.replace(/\/+$/, "")}/v1/network/info`);
    const info = (await res.json()) as NetworkInfo;
    if (info.protocol_version !== PROTOCOL_VERSION) {
      throw new Error(`Protocol mismatch: ${info.protocol_version} != ${PROTOCOL_VERSION}`);
    }
    if (this.expectedNetworkId && info.network_id !== this.expectedNetworkId) {
      throw new Error(`Expected network ${this.expectedNetworkId}, got ${info.network_id}`);
    }
    this.connectedNetworkId = info.network_id;
    return info;
  }

  async join(
    scopes: ParticipationLevel[] = ["NETWORK", "SPACE", "REGION", "WALLET", "TOKEN"],
    scopeAuthorizations: Array<Record<string, unknown>> = [],
  ): Promise<unknown> {
    if (!this.connectedNetworkId) await this.connect();
    const base = this.baseUrl.replace(/\/+$/, "");
    const ch = await (await fetch(`${base}/v1/participants/challenge`, { method: "POST" })).json();
    const msg = canonicalJsonBytes({
      challenge_id: ch.challenge_id,
      network_id: ch.network_id,
      node_pubkey: this.identity.node_key.public_key_hex,
      nonce: ch.nonce,
      participant_pubkey: this.identity.participant_key.public_key_hex,
      requested_scopes: scopes,
    });
    const participantSig = await signBrowserEd25519(this.identity.participant_key.private_key_hex, msg);
    const nodeSig = await signBrowserEd25519(this.identity.node_key.private_key_hex, msg);
    const res = await fetch(`${base}/v1/participants/join`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        challenge_id: ch.challenge_id,
        participant_pubkey: this.identity.participant_key.public_key_hex,
        node_pubkey: this.identity.node_key.public_key_hex,
        display_name: this.identity.display_name,
        node_kind: "FULL_NODE",
        requested_scopes: scopes,
        advertised_addresses: [],
        participant_signature: participantSig,
        node_signature: nodeSig,
        scope_authorizations: scopeAuthorizations,
      }),
    });
    return res.json();
  }

  async submitProgram(
    fileName: string,
    sourceBytes: string,
    modules: Record<string, string> = {},
    executionParams: Record<string, unknown> = {},
  ): Promise<ProgramSubmission> {
    if (!this.connectedNetworkId) await this.connect();
    const networkId = this.connectedNetworkId!;
    const requestId = `req_${globalThis.crypto.randomUUID().replace(/-/g, "")}`;
    const nonce = this.nonce++;
    const sourceHash = blake3Hex(sourceBytes);
    const fileKind = fileName.endsWith(".vdx") ? "vdx" : "vx";
    const moduleHashes: Record<string, string> = {};
    for (const k of Object.keys(modules).sort()) {
      moduleHashes[k] = blake3Hex(modules[k]);
    }
    const msg = canonicalJsonBytes({
      actor_pubkey: this.identity.participant_key.public_key_hex,
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
    });
    const signature = await signBrowserEd25519(this.identity.participant_key.private_key_hex, msg);
    const res = await fetch(`${this.baseUrl.replace(/\/+$/, "")}/v1/programs/submit`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        file_name: fileName,
        source_bytes: sourceBytes,
        modules,
        actor_pubkey: this.identity.participant_key.public_key_hex,
        network_id: networkId,
        request_id: requestId,
        nonce,
        signature,
        execution_params: executionParams,
      }),
    });
    return (await res.json()) as ProgramSubmission;
  }

  async signWalletPop(
    walletId: string,
    participantIdentity: string,
    purpose: string,
    popNonce: string,
    authorizedKey: KeypairMaterial,
    expiresAtMs: number | null = null,
  ): Promise<string> {
    if (!this.connectedNetworkId) await this.connect();
    const msg = canonicalJsonBytes({
      authorized_pubkey: authorizedKey.public_key_hex,
      expires_at_ms: expiresAtMs,
      network_id: this.connectedNetworkId!,
      nonce: popNonce,
      participant_identity: participantIdentity,
      protocol_version: PROTOCOL_VERSION,
      purpose,
      wallet_id: walletId,
    });
    return signBrowserEd25519(authorizedKey.private_key_hex, msg);
  }

  async signTransferApproval(
    tokenId: string,
    fromWalletId: string,
    toWalletId: string,
    amount: number | bigint | string,
    cosignerKey: KeypairMaterial,
  ): Promise<string> {
    if (!this.connectedNetworkId) await this.connect();
    const msg = canonicalJsonBytes({
      amount: String(amount),
      domain: DOM_TRANSFER_APPROVAL_V1,
      from_wallet_id: fromWalletId,
      network_id: this.connectedNetworkId!,
      protocol_version: PROTOCOL_VERSION,
      to_wallet_id: toWalletId,
      token_id: tokenId,
    });
    return signBrowserEd25519(cosignerKey.private_key_hex, msg);
  }

  async submitOperation(operation: NetworkOperation): Promise<Record<string, unknown>> {
    if (!this.connectedNetworkId) await this.connect();
    const networkId = this.connectedNetworkId!;
    const requestId = `req_${globalThis.crypto.randomUUID().replace(/-/g, "")}`;
    const nonce = this.nonce++;
    const timestampMs = Date.now();
    const payloadHash = blake3Hex(canonicalJsonBytes(operation));
    const signingBytes = canonicalJsonBytes({
      actor_pubkey: this.identity.participant_key.public_key_hex,
      network_id: networkId,
      nonce,
      payload_hash: payloadHash,
      request_id: requestId,
      timestamp_ms: timestampMs,
    });
    const signature = await signBrowserEd25519(this.identity.participant_key.private_key_hex, signingBytes);
    const res = await fetch(`${this.baseUrl.replace(/\/+$/, "")}/v1/transactions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        request_id: requestId,
        network_id: networkId,
        actor_pubkey: this.identity.participant_key.public_key_hex,
        nonce,
        timestamp_ms: timestampMs,
        signature,
        operation,
      }),
    });
    return (await res.json()) as Record<string, unknown>;
  }
}
