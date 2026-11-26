import { blake3Hex } from "./blake3.js";
import { canonicalJsonBytes } from "./canonical.js";

export { blake3Hex } from "./blake3.js";
export { canonicalJsonBytes, canonicalJsonString, sortJsonValue } from "./canonical.js";

const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const clean = hex.trim();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export async function generateBrowserKeypair(role = "participant") {
  const kp = await globalThis.crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const spki = new Uint8Array(await globalThis.crypto.subtle.exportKey("spki", kp.publicKey));
  const pkcs8 = new Uint8Array(await globalThis.crypto.subtle.exportKey("pkcs8", kp.privateKey));
  const publicKeyHex = bytesToHex(spki.slice(spki.length - 32));
  const privateKeyHex = bytesToHex(pkcs8.slice(pkcs8.length - 32));
  const prefix = role === "node" ? "nod" : "prt";
  const domain = role === "node" ? "vnetwork/node-id-v1" : "vnetwork/participant-id-v1";
  const derivedId = `${prefix}_${blake3Hex(new TextEncoder().encode(`${domain}:${publicKeyHex}`)).slice(0, 24)}`;
  return { key_role: role, derived_id: derivedId, public_key_hex: publicKeyHex, private_key_hex: privateKeyHex };
}

export async function signBrowserEd25519(privateKeyHex, messageBytes) {
  const raw = hexToBytes(privateKeyHex);
  const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + raw.length);
  pkcs8.set(ED25519_PKCS8_PREFIX, 0);
  pkcs8.set(raw, ED25519_PKCS8_PREFIX.length);
  const key = await globalThis.crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
  const sig = await globalThis.crypto.subtle.sign("Ed25519", key, messageBytes);
  return bytesToHex(new Uint8Array(sig));
}

export class BrowserVectorNetworkClient {
  constructor(baseUrl, identity, expectedNetworkId = null) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.identity = identity;
    this.expectedNetworkId = expectedNetworkId;
    this.connectedNetworkId = null;
    this.nonce = 1;
  }

  async connect() {
    const info = await this.getJson("/v1/network/info");
    if (info.protocol_version !== "vnetwork/1.0") {
      throw new Error(`Protocol mismatch: ${info.protocol_version}`);
    }
    if (this.expectedNetworkId && info.network_id !== this.expectedNetworkId) {
      throw new Error(`Expected network ${this.expectedNetworkId}, got ${info.network_id}`);
    }
    this.connectedNetworkId = info.network_id;
    return info;
  }

  async join(scopes = ["NETWORK", "SPACE", "REGION", "WALLET", "TOKEN"]) {
    if (!this.connectedNetworkId) await this.connect();
    const challenge = await this.postJson("/v1/participants/challenge", {});
    const msg = canonicalJsonBytes({
      challenge_id: challenge.challenge_id,
      network_id: challenge.network_id,
      node_pubkey: this.identity.node_key.public_key_hex,
      nonce: challenge.nonce,
      participant_pubkey: this.identity.participant_key.public_key_hex,
      requested_scopes: scopes,
    });
    const participantSig = await signBrowserEd25519(this.identity.participant_key.private_key_hex, msg);
    const nodeSig = await signBrowserEd25519(this.identity.node_key.private_key_hex, msg);
    return this.postJson("/v1/participants/join", {
      challenge_id: challenge.challenge_id,
      participant_pubkey: this.identity.participant_key.public_key_hex,
      node_pubkey: this.identity.node_key.public_key_hex,
      display_name: this.identity.display_name,
      node_kind: "FULL_NODE",
      requested_scopes: scopes,
      advertised_addresses: [],
      participant_signature: participantSig,
      node_signature: nodeSig,
    });
  }

  async submitProgram(fileName, sourceBytes, modules = {}) {
    if (!this.connectedNetworkId) await this.connect();
    const networkId = this.connectedNetworkId;
    const requestId = `req_${globalThis.crypto.randomUUID().replace(/-/g, "")}`;
    const nonce = this.nonce++;
    const sourceHash = blake3Hex(sourceBytes);
    const msg = canonicalJsonBytes({
      actor_pubkey: this.identity.participant_key.public_key_hex,
      file_name: fileName,
      network_id: networkId,
      nonce,
      request_id: requestId,
      source_hash: sourceHash,
    });
    const signature = await signBrowserEd25519(this.identity.participant_key.private_key_hex, msg);
    return this.postJson("/v1/programs/submit", {
      file_name: fileName,
      source_bytes: sourceBytes,
      modules,
      actor_pubkey: this.identity.participant_key.public_key_hex,
      network_id: networkId,
      request_id: requestId,
      nonce,
      signature,
      execution_params: {},
    });
  }

  async getJson(path) {
    const res = await fetch(`${this.baseUrl}${path}`);
    const body = await res.json();
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${body.error ?? JSON.stringify(body)}`);
    return body;
  }

  async postJson(path, payload) {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${body.error ?? JSON.stringify(body)}`);
    return body;
  }
}
