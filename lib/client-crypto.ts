import * as ed from "@noble/ed25519";
import { blake3 } from "@noble/hashes/blake3.js";

const encoder = new TextEncoder();

export function utf8ToBytes(value: string): Uint8Array {
  return encoder.encode(value);
}

export function bytesToHex(bytes: Uint8Array): string {
  return ed.etc.bytesToHex(bytes);
}

export function hexToBytes(hex: string): Uint8Array {
  return ed.etc.hexToBytes(hex);
}

export function blake3HexClient(input: Uint8Array | string): string {
  const bytes = typeof input === "string" ? utf8ToBytes(input) : input;
  return bytesToHex(blake3(bytes));
}

export function sortedJsonStringifyClient(obj: Record<string, unknown>): string {
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    const val = obj[key];
    if (val !== null && typeof val === "object" && !Array.isArray(val)) {
      sorted[key] = JSON.parse(sortedJsonStringifyClient(val as Record<string, unknown>));
    } else {
      sorted[key] = val;
    }
  }
  return JSON.stringify(sorted);
}

export function canonicalRequestSigningBytesClient(
  operation: string,
  requestId: string,
  actorPublicKey: string,
  params: Record<string, unknown>,
): Uint8Array {
  const payload = sortedJsonStringifyClient({
    actor_public_key: actorPublicKey,
    operation,
    params: sortedJsonStringifyClient(params),
    request_id: requestId,
  });
  return utf8ToBytes(payload);
}

export function canonicalTokenRequestSigningBytes(
  operation: string,
  requestId: string,
  actorPublicKey: string,
  params: Record<string, unknown>,
): Uint8Array {
  return canonicalRequestSigningBytesClient(operation, requestId, actorPublicKey, params);
}

export function canonicalVectorOpSigningBytes(
  operation: string,
  requestId: string,
  actorPublicKey: string,
  params: Record<string, unknown>,
): Uint8Array {
  return canonicalRequestSigningBytesClient(operation, requestId, actorPublicKey, params);
}

export function canonicalRegionRequestSignatureBytesClient(request: {
  region_name: string;
  region_prefix?: string | null;
  suggested_title?: string | null;
  visibility: "public" | "private";
  section: number;
  trigger_event_hash: string;
  creation_proof: string;
  access_key?: string | null;
  metadata?: Record<string, string>;
}): Uint8Array {
  const metadataSorted = sortedJsonStringifyClient(request.metadata ?? {});
  const payload: Record<string, string> = {
    access_key: request.access_key ?? "",
    creation_proof: request.creation_proof,
    metadata: metadataSorted,
    region_name: request.region_name,
    region_prefix: request.region_prefix ?? "",
    section: String(request.section),
    suggested_title: request.suggested_title ?? "",
    trigger_event_hash: request.trigger_event_hash,
    visibility: request.visibility,
  };
  return utf8ToBytes(sortedJsonStringifyClient(payload));
}

export function findBlake3NonceClient(
  seed: string,
  difficulty: number,
  maxAttempts = 1_000_000,
): { nonce: number; proofHash: string } {
  const seedBytes = utf8ToBytes(seed);
  const combined = new Uint8Array(seedBytes.length + 8);
  combined.set(seedBytes, 0);
  const view = new DataView(combined.buffer);
  const prefix = difficulty > 0 ? "0".repeat(difficulty) : "";
  for (let nonce = 0; nonce < maxAttempts; nonce += 1) {
    view.setBigUint64(seedBytes.length, BigInt(nonce), false);
    const proof = bytesToHex(blake3(combined));
    if (!prefix || proof.startsWith(prefix)) {
      return { nonce, proofHash: proof };
    }
  }
  throw new Error(`Unable to find valid BLAKE3 nonce for difficulty ${difficulty}`);
}

export async function generateBrowserKeypair(): Promise<{
  wallet_id: string;
  public_key_hex: string;
  private_key_hex: string;
}> {
  const secretKey = ed.utils.randomSecretKey();
  const publicKey = await ed.getPublicKeyAsync(secretKey);
  const public_key_hex = bytesToHex(publicKey);
  const private_key_hex = bytesToHex(secretKey);
  const wallet_id = deriveWalletIdClient(public_key_hex);
  return { wallet_id, public_key_hex, private_key_hex };
}

export async function derivePublicKeyFromPrivateHex(privateKeyHex: string): Promise<string> {
  const clean = privateKeyHex.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean)) {
    throw new Error("Private key must be a 64-character (32-byte) Ed25519 hex seed");
  }
  const pub = await ed.getPublicKeyAsync(hexToBytes(clean));
  return bytesToHex(pub);
}

export function deriveWalletIdClient(publicKeyHex: string): string {
  const clean = publicKeyHex.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean)) {
    throw new Error("Public key must be a 64-character (32-byte) Ed25519 hex key");
  }
  const prefixBytes = utf8ToBytes("v-kernelx/wallet-id-v1:");
  const pkBytes = hexToBytes(clean);
  const buf = new Uint8Array(prefixBytes.length + pkBytes.length);
  buf.set(prefixBytes, 0);
  buf.set(pkBytes, prefixBytes.length);
  return `wlt_${bytesToHex(blake3(buf)).slice(0, 24)}`;
}

export async function signBytesWithPrivateKey(
  privateKeyHex: string,
  payload: Uint8Array,
): Promise<string> {
  const clean = privateKeyHex.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean)) {
    throw new Error("Invalid Ed25519 private signing key");
  }
  const sig = await ed.signAsync(payload, hexToBytes(clean));
  return bytesToHex(sig);
}

export async function signOperationRequest(
  privateKeyHex: string,
  actorPublicKey: string,
  operation: string,
  requestId: string,
  params: Record<string, unknown>,
): Promise<string> {
  const bytes = canonicalRequestSigningBytesClient(operation, requestId, actorPublicKey, params);
  return signBytesWithPrivateKey(privateKeyHex, bytes);
}

export function canonicalAttestationSigningBytesClient(params: {
  event_hash: string;
  validator_id: string;
  validator_pubkey: string;
  vote_accept: boolean;
  state_root_hash: string;
  timestamp_ms: number;
}): Uint8Array {
  return utf8ToBytes(
    sortedJsonStringifyClient({
      event_hash: params.event_hash,
      state_root_hash: params.state_root_hash,
      timestamp_ms: params.timestamp_ms,
      validator_id: params.validator_id,
      validator_pubkey: params.validator_pubkey,
      vote_accept: params.vote_accept,
    }),
  );
}
