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

export function sortJsonValueClient(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortJsonValueClient);
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortJsonValueClient((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

export function sortedJsonStringifyClient(obj: Record<string, unknown>): string {
  return JSON.stringify(sortJsonValueClient(obj));
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
  const secretKey = ed.utils.randomPrivateKey();
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

export const PROTOCOL_VERSION = "vector-network/1.0.0";
export const LANGUAGE_VERSION = "v-langx/1.2.0";
export const COMPILER_VERSION = "vectorspace-compiler/1.2.0";
export const DOM_TRANSFER_APPROVAL_V1 = "vnetwork/transfer-approval/v1";

export function deriveParticipantIdClient(publicKeyHex: string): string {
  const clean = publicKeyHex.trim().toLowerCase();
  return `prt_${blake3HexClient(`vnetwork/participant-id-v1:${clean}`).slice(0, 24)}`;
}

export function deriveNodeIdClient(publicKeyHex: string): string {
  const clean = publicKeyHex.trim().toLowerCase();
  return `nod_${blake3HexClient(`vnetwork/node-id-v1:${clean}`).slice(0, 24)}`;
}

export function canonicalProgramSubmitBytesClient(params: {
  actor_pubkey: string;
  file_name: string;
  source_bytes: string;
  modules?: Record<string, string>;
  network_id: string;
  request_id: string;
  nonce: number;
  execution_params?: Record<string, unknown>;
}): Uint8Array {
  const modules = params.modules ?? {};
  const module_hashes: Record<string, string> = {};
  for (const k of Object.keys(modules).sort()) {
    module_hashes[k] = blake3HexClient(modules[k]);
  }
  return utf8ToBytes(
    sortedJsonStringifyClient({
      actor_pubkey: params.actor_pubkey,
      compiler_version: COMPILER_VERSION,
      execution_params: params.execution_params ?? {},
      file_kind: params.file_name.endsWith(".vdx") ? "vdx" : "vx",
      file_name: params.file_name,
      language_version: LANGUAGE_VERSION,
      module_hashes,
      network_id: params.network_id,
      nonce: params.nonce,
      protocol_version: PROTOCOL_VERSION,
      request_id: params.request_id,
      source_hash: blake3HexClient(params.source_bytes),
    }),
  );
}

export function canonicalWalletPopBytesClient(params: {
  network_id: string;
  wallet_id: string;
  participant_identity: string;
  authorized_pubkey: string;
  purpose: string;
  nonce: string;
  expires_at_ms?: number | null;
}): Uint8Array {
  return utf8ToBytes(
    sortedJsonStringifyClient({
      authorized_pubkey: params.authorized_pubkey,
      expires_at_ms: params.expires_at_ms ?? null,
      network_id: params.network_id,
      nonce: params.nonce,
      participant_identity: params.participant_identity,
      protocol_version: PROTOCOL_VERSION,
      purpose: params.purpose,
      wallet_id: params.wallet_id,
    }),
  );
}

export function canonicalTransferApprovalBytesClient(params: {
  network_id: string;
  token_id: string;
  from_wallet_id: string;
  to_wallet_id: string;
  amount: string | number | bigint;
}): Uint8Array {
  return utf8ToBytes(
    sortedJsonStringifyClient({
      amount: String(params.amount),
      domain: DOM_TRANSFER_APPROVAL_V1,
      from_wallet_id: params.from_wallet_id,
      network_id: params.network_id,
      protocol_version: PROTOCOL_VERSION,
      to_wallet_id: params.to_wallet_id,
      token_id: params.token_id,
    }),
  );
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

export interface SignedTransactionEnvelopePayload {
  request_id: string;
  network_id: string;
  actor_pubkey: string;
  nonce: number;
  timestamp_ms: number;
  signature: string;
  operation: {
    op: string;
    payload: Record<string, unknown>;
  };
}

export async function signTransactionEnvelopeClient(params: {
  privateKeyHex: string;
  actorPubkey: string;
  networkId: string;
  requestId: string;
  nonce: number;
  timestampMs: number;
  operation: { op: string; payload: Record<string, unknown> };
}): Promise<SignedTransactionEnvelopePayload> {
  const payloadHash = blake3HexClient(
    JSON.stringify(sortJsonValueClient(params.operation)),
  );
  const signingBytes = utf8ToBytes(
    sortedJsonStringifyClient({
      actor_pubkey: params.actorPubkey,
      network_id: params.networkId,
      nonce: params.nonce,
      payload_hash: payloadHash,
      request_id: params.requestId,
      timestamp_ms: params.timestampMs,
    }),
  );
  const signature = await signBytesWithPrivateKey(params.privateKeyHex, signingBytes);
  return {
    request_id: params.requestId,
    network_id: params.networkId,
    actor_pubkey: params.actorPubkey,
    nonce: params.nonce,
    timestamp_ms: params.timestampMs,
    signature,
    operation: params.operation,
  };
}

export async function signProgramSubmissionClient(params: {
  privateKeyHex: string;
  actorPubkey: string;
  fileName: string;
  sourceBytes: string;
  modules?: Record<string, string>;
  networkId: string;
  requestId: string;
  nonce: number;
  executionParams?: Record<string, unknown>;
}) {
  const signingBytes = canonicalProgramSubmitBytesClient({
    actor_pubkey: params.actorPubkey,
    file_name: params.fileName,
    source_bytes: params.sourceBytes,
    modules: params.modules,
    network_id: params.networkId,
    request_id: params.requestId,
    nonce: params.nonce,
    execution_params: params.executionParams,
  });
  const signature = await signBytesWithPrivateKey(params.privateKeyHex, signingBytes);
  return {
    actor_pubkey: params.actorPubkey,
    file_name: params.fileName,
    source_bytes: params.sourceBytes,
    modules: params.modules ?? {},
    network_id: params.networkId,
    request_id: params.requestId,
    nonce: params.nonce,
    execution_params: params.executionParams ?? {},
    signature,
  };
}
