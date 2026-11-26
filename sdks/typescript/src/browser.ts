import { blake3Hex } from "./blake3.js";
import { canonicalJsonBytes } from "./canonical.js";
import type { KeypairMaterial, NetworkInfo, ParticipationLevel, ProgramSubmission } from "./types.js";

const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

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
    if (info.protocol_version !== "vnetwork/1.0") throw new Error("Protocol mismatch");
    if (this.expectedNetworkId && info.network_id !== this.expectedNetworkId) throw new Error("Network mismatch");
    this.connectedNetworkId = info.network_id;
    return info;
  }

  async join(scopes: ParticipationLevel[] = ["NETWORK", "SPACE", "REGION", "WALLET", "TOKEN"]): Promise<unknown> {
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
      }),
    });
    return res.json();
  }

  async submitProgram(fileName: string, sourceBytes: string, modules: Record<string, string> = {}): Promise<ProgramSubmission> {
    if (!this.connectedNetworkId) await this.connect();
    const networkId = this.connectedNetworkId!;
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
        execution_params: {},
      }),
    });
    return (await res.json()) as ProgramSubmission;
  }
}
