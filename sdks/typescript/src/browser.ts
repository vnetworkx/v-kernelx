import { blake3Hex } from "./blake3.js";
import { canonicalJsonBytes } from "./canonical.js";
import type {
  KeypairMaterial,
  NetworkInfo,
  NetworkOperation,
  NetworkStatus,
  ParticipationLevel,
  ProgramSubmission,
  ReconstructionReport,
  VerificationStatus,
} from "./types.js";

export { blake3Hex } from "./blake3.js";
export { canonicalJsonBytes, canonicalJsonString, sortJsonValue } from "./canonical.js";

type BrowserNonceStorage = {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
};

type BrowserNonceLockManager = {
  request<T>(name: string, callback: () => Promise<T>): Promise<T>;
};

const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

const ED25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
  0x70, 0x03, 0x21, 0x00,
]);

const WEAK_PUBKEY_HEXES = new Set([
  "0".repeat(64),
  "01" + "0".repeat(62),
]);

export const PROTOCOL_VERSION = "vector-network/1.0.0";
export const LANGUAGE_VERSION = "v-langx/1.2.0";
export const COMPILER_VERSION = "vectorspace-compiler/1.2.0";
export const DOM_TRANSFER_APPROVAL_V1 = "vnetwork/transfer-approval/v1";
export const VERIFICATION_STATUSES: readonly VerificationStatus[] = [
  "VERIFIED",
  "UNVERIFIED",
  "INVALID",
  "UNAVAILABLE",
];

export function normalizeVerificationStatus(raw: unknown): VerificationStatus {
  const norm = typeof raw === "string" ? raw.trim().toUpperCase() : "";
  if (norm === "VERIFIED" || norm === "UNVERIFIED" || norm === "INVALID" || norm === "UNAVAILABLE") {
    return norm;
  }
  return "UNAVAILABLE";
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  const clean = hex.trim();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function derivePrefixedId(prefix: string, domain: string, materialBytes: Uint8Array): string {
  const domainBytes = new TextEncoder().encode(`${domain}:`);
  const combined = new Uint8Array(domainBytes.length + materialBytes.length);
  combined.set(domainBytes, 0);
  combined.set(materialBytes, domainBytes.length);
  return `${prefix}_${blake3Hex(combined).slice(0, 24)}`;
}

export function deriveParticipantId(pubkeyHex: string): string {
  return derivePrefixedId("prt", "vnetwork/participant-id-v1", new TextEncoder().encode(pubkeyHex));
}

export function deriveNodeId(pubkeyHex: string): string {
  return derivePrefixedId("nod", "vnetwork/node-id-v1", new TextEncoder().encode(pubkeyHex));
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

export async function generateBrowserKeypair(role = "participant"): Promise<KeypairMaterial> {
  const kp = (await globalThis.crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array(await globalThis.crypto.subtle.exportKey("spki", kp.publicKey));
  const pkcs8 = new Uint8Array(await globalThis.crypto.subtle.exportKey("pkcs8", kp.privateKey));
  const publicKeyHex = toHex(spki.slice(spki.length - 32));
  const privateKeyHex = toHex(pkcs8.slice(pkcs8.length - 32));
  const derived_id = role === "node" ? deriveNodeId(publicKeyHex) : deriveParticipantId(publicKeyHex);
  return { key_role: role, derived_id, public_key_hex: publicKeyHex, private_key_hex: privateKeyHex };
}

export async function browserKeypairFromPrivateHex(role: string, privateKeyHex: string): Promise<KeypairMaterial> {
  const clean = privateKeyHex.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean)) {
    throw new Error("Ed25519 private key must be 32 bytes hex");
  }
  const raw = fromHex(clean);
  const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + raw.length);
  pkcs8.set(ED25519_PKCS8_PREFIX, 0);
  pkcs8.set(raw, ED25519_PKCS8_PREFIX.length);
  const privKey = await globalThis.crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
  const jwk = (await globalThis.crypto.subtle.exportKey("jwk", privKey)) as { x?: string };
  if (!jwk.x) throw new Error("Failed to derive Ed25519 public key in browser WebCrypto");
  const base64 = jwk.x.replace(/-/g, "+").replace(/_/g, "/") + "==".slice(0, (4 - (jwk.x.length % 4)) % 4);
  const pubRaw = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  const publicKeyHex = toHex(pubRaw);
  const derived_id = role === "node" ? deriveNodeId(publicKeyHex) : deriveParticipantId(publicKeyHex);
  return { key_role: role, derived_id, public_key_hex: publicKeyHex, private_key_hex: clean };
}

export async function signBrowserEd25519(privateKeyHex: string, messageBytes: Uint8Array): Promise<string> {
  const clean = privateKeyHex.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean)) {
    throw new Error("Ed25519 private key must be 32 bytes hex");
  }
  const raw = fromHex(clean);
  const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + raw.length);
  pkcs8.set(ED25519_PKCS8_PREFIX, 0);
  pkcs8.set(raw, ED25519_PKCS8_PREFIX.length);
  const key = await globalThis.crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
  const sig = await globalThis.crypto.subtle.sign("Ed25519", key, new Uint8Array(messageBytes));
  return toHex(new Uint8Array(sig));
}

export async function verifyBrowserEd25519(
  publicKeyHex: string,
  messageBytes: Uint8Array,
  signatureHex: string,
): Promise<boolean> {
  const pkClean = publicKeyHex.trim().toLowerCase();
  const sigClean = signatureHex.trim().toLowerCase();
  if (
    !/^[0-9a-f]{64}$/.test(pkClean) ||
    WEAK_PUBKEY_HEXES.has(pkClean) ||
    !/^[0-9a-f]{128}$/.test(sigClean)
  ) {
    return false;
  }
  try {
    const pubRaw = fromHex(pkClean);
    const sigRaw = fromHex(sigClean);
    const spki = new Uint8Array(ED25519_SPKI_PREFIX.length + pubRaw.length);
    spki.set(ED25519_SPKI_PREFIX, 0);
    spki.set(pubRaw, ED25519_SPKI_PREFIX.length);
    const key = await globalThis.crypto.subtle.importKey("spki", spki, { name: "Ed25519" }, false, ["verify"]);
    return await globalThis.crypto.subtle.verify("Ed25519", key, new Uint8Array(sigRaw), new Uint8Array(messageBytes));
  } catch {
    return false;
  }
}

export class BrowserVectorNetworkClient {
  connectedNetworkId: string | null = null;
  private nonce = 1;

  constructor(
    readonly baseUrl: string,
    readonly identity: { display_name: string; participant_key: KeypairMaterial; node_key: KeypairMaterial },
    readonly expectedNetworkId: string | null = null,
    private readonly nonceStorage: BrowserNonceStorage | null = null,
    private readonly nonceLockManager: BrowserNonceLockManager | null = null,
  ) {}

  async reserveNonce(): Promise<number> {
    const networkId = this.resolvedNetworkId();
    const actorPubkey = this.identity.participant_key.public_key_hex;
    const key = blake3Hex(`${networkId}::${actorPubkey}`);
    let storage = this.nonceStorage;
    let lockManager = this.nonceLockManager;
    try {
      storage = storage ?? globalThis.localStorage;
      lockManager = lockManager ?? (globalThis.navigator?.locks as unknown as BrowserNonceLockManager | undefined) ?? null;
    } catch {
      throw new Error("Browser nonce persistence is unavailable; refusing to send a request with an ephemeral nonce");
    }
    if (!storage || typeof storage.getItem !== "function" || typeof storage.setItem !== "function") {
      throw new Error("Browser localStorage is unavailable; refusing to send a request with an ephemeral nonce");
    }
    if (!lockManager || typeof lockManager.request !== "function") {
      throw new Error("Browser Web Locks API is unavailable; refusing to risk duplicate request nonces across tabs");
    }
    const storageKey = `vnetwork:request-nonce:v1:${key}`;
    return lockManager.request(`vnetwork-request-nonce-${key}`, async () => {
      let current = this.nonce;
      const raw = storage!.getItem(storageKey);
      if (raw !== null) {
        let stored: any;
        try {
          stored = JSON.parse(raw);
        } catch {
          throw new Error("Persisted browser request nonce state is corrupt");
        }
        if (
          stored.version !== 1 ||
          stored.network_id !== networkId ||
          stored.actor_pubkey !== actorPubkey ||
          !Number.isSafeInteger(stored.next_nonce) ||
          stored.next_nonce < 1
        ) {
          throw new Error("Persisted browser request nonce state does not match this network/participant");
        }
        current = Math.max(current, stored.next_nonce);
      }
      if (!Number.isSafeInteger(current) || current < 1 || current >= Number.MAX_SAFE_INTEGER) {
        throw new Error("Request nonce exhausted JavaScript's safe integer range");
      }
      storage!.setItem(storageKey, JSON.stringify({
        version: 1,
        network_id: networkId,
        actor_pubkey: actorPubkey,
        next_nonce: current + 1,
      }));
      this.nonce = current + 1;
      return current;
    });
  }

  async connect(): Promise<NetworkInfo> {
    const info = await this.getJson<NetworkInfo>("/v1/network/info");
    if (info.protocol_version !== PROTOCOL_VERSION) {
      throw new Error(`Protocol mismatch: ${info.protocol_version} != ${PROTOCOL_VERSION}`);
    }
    if (this.expectedNetworkId && info.network_id !== this.expectedNetworkId) {
      throw new Error(`Expected network ${this.expectedNetworkId}, got ${info.network_id}`);
    }
    this.connectedNetworkId = info.network_id;
    return info;
  }

  private resolvedNetworkId(): string {
    const net = this.connectedNetworkId ?? this.expectedNetworkId;
    if (!net) {
      throw new Error("Client must call connect() before write operations");
    }
    return net;
  }

  async join(
    scopes: ParticipationLevel[] = ["NETWORK", "SPACE", "REGION", "WALLET", "TOKEN"],
    scopeAuthorizations: Array<Record<string, unknown>> = [],
  ): Promise<Record<string, unknown>> {
    if (!this.connectedNetworkId) await this.connect();
    const ch = await this.postJson<{ challenge_id: string; network_id: string; nonce: string }>(
      "/v1/participants/challenge",
      {},
    );
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
    return this.postJson("/v1/participants/join", {
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
    });
  }

  async submitProgram(
    fileName: string,
    sourceBytes: string,
    modules: Record<string, string> = {},
    executionParams: Record<string, unknown> = {},
  ): Promise<ProgramSubmission> {
    if (!this.connectedNetworkId) await this.connect();
    const networkId = this.resolvedNetworkId();
    const requestId = `req_${globalThis.crypto.randomUUID().replace(/-/g, "")}`;
    const nonce = await this.reserveNonce();
    const msg = canonicalJsonBytes(
      canonicalProgramSubmitObject({
        actorPubkey: this.identity.participant_key.public_key_hex,
        fileName,
        sourceBytes,
        modules,
        networkId,
        requestId,
        nonce,
        executionParams,
      }),
    );
    const signature = await signBrowserEd25519(this.identity.participant_key.private_key_hex, msg);
    return this.postJson<ProgramSubmission>("/v1/programs/submit", {
      file_name: fileName,
      source_bytes: sourceBytes,
      modules,
      actor_pubkey: this.identity.participant_key.public_key_hex,
      network_id: networkId,
      request_id: requestId,
      nonce,
      signature,
      execution_params: executionParams,
    });
  }

  async signWalletPop(
    walletId: string,
    participantIdentity: string,
    purpose: string,
    popNonce: string,
    authorizedKey: KeypairMaterial,
    expiresAtMs: number | null = null,
  ): Promise<string> {
    if (!this.connectedNetworkId && !this.expectedNetworkId) await this.connect();
    const msg = canonicalJsonBytes(
      canonicalWalletPopObject({
        networkId: this.resolvedNetworkId(),
        walletId,
        participantIdentity,
        authorizedPubkey: authorizedKey.public_key_hex,
        purpose,
        nonce: popNonce,
        expiresAtMs,
      }),
    );
    return signBrowserEd25519(authorizedKey.private_key_hex, msg);
  }

  async signTransferApproval(
    tokenId: string,
    fromWalletId: string,
    toWalletId: string,
    amount: number | bigint | string,
    cosignerKey: KeypairMaterial,
  ): Promise<string> {
    if (!this.connectedNetworkId && !this.expectedNetworkId) await this.connect();
    const msg = canonicalJsonBytes(
      canonicalTransferApprovalObject({
        networkId: this.resolvedNetworkId(),
        tokenId,
        fromWalletId,
        toWalletId,
        amount,
      }),
    );
    return signBrowserEd25519(cosignerKey.private_key_hex, msg);
  }

  updateWalletReceivePolicy(
    walletId: string,
    mode: "OPEN" | "RESTRICTED" | "FROZEN",
    allowedSenders: string[] = [],
  ): Promise<Record<string, unknown>> {
    return this.submitOperation({
      op: "UpdateWalletReceivePolicy",
      payload: {
        wallet_id: walletId,
        mode,
        allowed_senders: allowedSenders,
      },
    });
  }

  async submitOperation(operation: NetworkOperation): Promise<Record<string, unknown>> {
    if (!this.connectedNetworkId) await this.connect();
    const networkId = this.resolvedNetworkId();
    const requestId = `req_${globalThis.crypto.randomUUID().replace(/-/g, "")}`;
    const nonce = await this.reserveNonce();
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
    return this.postJson("/v1/transactions", {
      request_id: requestId,
      network_id: networkId,
      actor_pubkey: this.identity.participant_key.public_key_hex,
      nonce,
      timestamp_ms: timestampMs,
      signature,
      operation,
    });
  }

  getNetworkInfo(): Promise<NetworkInfo> { return this.getJson("/v1/network/info"); }
  getNetworkStatus(): Promise<NetworkStatus> { return this.getJson("/v1/network/status"); }
  listNodes(): Promise<Record<string, unknown>> { return this.getJson("/v1/nodes"); }
  getNodeDetails(nodeId: string): Promise<Record<string, unknown>> { return this.getJson(`/v1/nodes/${nodeId}`); }
  getExplorerNetwork(): Promise<Record<string, unknown>> { return this.getJson("/v1/explorer/network"); }
  compileSource(
    fileName: string,
    sourceBytes: string,
    modules: Record<string, string> = {},
  ): Promise<Record<string, unknown>> {
    return this.postJson("/v1/language/compile", { file_name: fileName, source_bytes: sourceBytes, modules });
  }
  getProgram(programId: string): Promise<ProgramSubmission> { return this.getJson(`/v1/programs/${programId}`); }
  getProgramStatus(programId: string): Promise<Record<string, unknown>> { return this.getJson(`/v1/programs/${programId}/status`); }
  getTransaction(txId: string): Promise<Record<string, unknown>> { return this.getJson(`/v1/transactions/${txId}`); }
  listSpaces(): Promise<unknown[]> { return this.getJson("/v1/spaces"); }
  listRegions(): Promise<unknown[]> { return this.getJson("/v1/regions"); }
  listWallets(): Promise<unknown[]> { return this.getJson("/v1/wallets"); }
  getWallet(walletId: string): Promise<Record<string, unknown>> { return this.getJson(`/v1/wallets/${walletId}`); }
  listTokens(): Promise<unknown[]> { return this.getJson("/v1/tokens"); }
  getToken(tokenId: string): Promise<Record<string, unknown>> { return this.getJson(`/v1/tokens/${tokenId}`); }
  listContracts(): Promise<unknown[]> { return this.getJson("/v1/contracts"); }
  getContract(contractId: string): Promise<Record<string, unknown>> { return this.getJson(`/v1/contracts/${contractId}`); }
  listLoans(): Promise<unknown[]> { return this.getJson("/v1/loans"); }
  getLoan(loanId: string): Promise<Record<string, unknown>> { return this.getJson(`/v1/loans/${loanId}`); }
  getLedgerEvents(): Promise<unknown[]> { return this.getJson("/v1/ledger/events"); }
  getLedgerProofs(): Promise<Record<string, unknown>> { return this.getJson("/v1/ledger/proofs"); }
  verifyLedgerReplay(): Promise<Record<string, unknown>> { return this.getJson("/v1/ledger/replay"); }
  verifyTokenSupply(tokenId: string): Promise<Record<string, unknown>> { return this.getJson(`/v1/tokens/${tokenId}/supply`); }
  getConsensusStatus(): Promise<Record<string, unknown>> { return this.getJson("/v1/consensus/status"); }
  getEquivocations(): Promise<Record<string, unknown>> { return this.getJson("/v1/consensus/equivocations"); }
  createContract(name: string, regionId: string | null, rules: unknown, actions: unknown[]): Promise<Record<string, unknown>> {
    return this.submitOperation({ op: "CreateContract", payload: { name, region_id: regionId, rules, actions } });
  }
  executeContract(contractId: string, action: string, args: unknown = {}): Promise<Record<string, unknown>> {
    return this.submitOperation({ op: "ExecuteContract", payload: { contract_id: contractId, action, args } });
  }
  createLoan(
    name: string,
    tokenId: string,
    lenderWalletId: string,
    borrowerWalletId: string,
    principal: number,
    collateral: number,
    interestBps: number,
    maturityAtMs: number | null = null,
  ): Promise<Record<string, unknown>> {
    return this.submitOperation({
      op: "CreateLoan",
      payload: {
        name,
        token_id: tokenId,
        lender_wallet_id: lenderWalletId,
        borrower_wallet_id: borrowerWalletId,
        principal,
        collateral,
        interest_bps: interestBps,
        maturity_at_ms: maturityAtMs,
      },
    });
  }
  executeLoan(loanId: string, action: string, amount: number): Promise<Record<string, unknown>> {
    return this.submitOperation({ op: "ExecuteLoan", payload: { loan_id: loanId, action, amount } });
  }
  verifyReconstruction(entityKind: string, entityId: string): Promise<ReconstructionReport> {
    return this.postJson<ReconstructionReport>("/v1/reconstruction/verify", {
      entity_kind: entityKind,
      entity_id: entityId,
    });
  }

  async getJson<T = Record<string, unknown>>(endpointPath: string): Promise<T> {
    const res = await fetch(`${this.baseUrl.replace(/\/+$/, "")}${endpointPath}`);
    const body = (await res.json()) as Record<string, unknown>;
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${(body.error as string) ?? JSON.stringify(body)}`);
    }
    return body as T;
  }

  async postJson<T = Record<string, unknown>>(endpointPath: string, payload: unknown): Promise<T> {
    const res = await fetch(`${this.baseUrl.replace(/\/+$/, "")}${endpointPath}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = (await res.json()) as Record<string, unknown>;
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${(body.error as string) ?? JSON.stringify(body)}`);
    }
    return body as T;
  }
}
