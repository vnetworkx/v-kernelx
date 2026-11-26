import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { blake3Hex } from "./blake3.js";
import { canonicalJsonBytes } from "./canonical.js";
import {
  ClientIdentity,
  PROTOCOL_VERSION,
  canonicalProgramSubmitObject,
  canonicalTransferApprovalObject,
  canonicalWalletPopObject,
  signEd25519,
} from "./crypto.js";
import type {
  KeypairMaterial,
  NetworkInfo,
  NetworkOperation,
  NetworkStatus,
  ParticipationLevel,
  ProgramSubmission,
  ReconstructionReport,
} from "./types.js";

const IMPORT_RE = /^\s*import\s+"([^"]+)"(?:\s+(?:blake3|sha256)\s+"([^"]+)")?(?:\s+as\s+[A-Za-z0-9_]+)?\s*;/gm;

export class VectorNetworkClient {
  readonly baseUrl: string;
  readonly identity: ClientIdentity;
  readonly expectedNetworkId: string | null;
  connectedNetworkId: string | null = null;
  private nonce = 1;

  constructor(baseUrl: string, identity: ClientIdentity, expectedNetworkId: string | null = null) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.identity = identity;
    this.expectedNetworkId = expectedNetworkId;
  }

  async connect(): Promise<NetworkInfo> {
    const info = await this.getJson<NetworkInfo>("/v1/network/info");
    if (info.protocol_version !== PROTOCOL_VERSION) {
      throw new Error(`Protocol mismatch: remote ${info.protocol_version} != ${PROTOCOL_VERSION}`);
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
    const challenge = await this.postJson<{
      challenge_id: string;
      network_id: string;
      nonce: string;
    }>("/v1/participants/challenge", {});

    const msg = canonicalJsonBytes({
      challenge_id: challenge.challenge_id,
      network_id: challenge.network_id,
      node_pubkey: this.identity.node_key.public_key_hex,
      nonce: challenge.nonce,
      participant_pubkey: this.identity.participant_key.public_key_hex,
      requested_scopes: scopes,
    });
    const participantSig = signEd25519(this.identity.participant_key.private_key_hex, msg);
    const nodeSig = signEd25519(this.identity.node_key.private_key_hex, msg);
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
      scope_authorizations: scopeAuthorizations,
    });
  }

  async participantStatus(participantId = this.identity.participant_id): Promise<Record<string, unknown>> {
    return this.getJson(`/v1/participants/${participantId}/scope`);
  }

  async loadModulesForSource(sourceBytes: string, baseDir: string): Promise<Record<string, string>> {
    const modules: Record<string, string> = {};
    const queue = [sourceBytes];
    while (queue.length > 0) {
      const current = queue.pop()!;
      IMPORT_RE.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = IMPORT_RE.exec(current)) !== null) {
        const importPath = match[1];
        if (!modules[importPath]) {
          const full = path.resolve(baseDir, importPath);
          const content = await fs.readFile(full, "utf8");
          modules[importPath] = content;
          queue.push(content);
        }
      }
    }
    return modules;
  }

  async compileSource(
    fileName: string,
    sourceBytes: string,
    modules: Record<string, string> = {},
  ): Promise<Record<string, unknown>> {
    return this.postJson("/v1/language/compile", {
      file_name: fileName,
      source_bytes: sourceBytes,
      modules,
    });
  }

  async submitVxFile(
    filePath: string,
    executionParams: Record<string, unknown> = {},
  ): Promise<ProgramSubmission> {
    const abs = path.resolve(filePath);
    const sourceBytes = await fs.readFile(abs, "utf8");
    const modules = await this.loadModulesForSource(sourceBytes, path.dirname(abs));
    return this.submitProgram(path.basename(abs), sourceBytes, modules, executionParams);
  }

  async submitProgram(
    fileName: string,
    sourceBytes: string,
    modules: Record<string, string> = {},
    executionParams: Record<string, unknown> = {},
  ): Promise<ProgramSubmission> {
    if (!this.connectedNetworkId) await this.connect();
    const networkId = this.resolvedNetworkId();
    const requestId = `req_${crypto.randomUUID().replace(/-/g, "")}`;
    const nonce = this.nonce++;
    const signingBytes = canonicalJsonBytes(
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
    const signature = signEd25519(this.identity.participant_key.private_key_hex, signingBytes);
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

  signWalletPop(
    walletId: string,
    participantIdentity: string,
    purpose: string,
    popNonce: string,
    authorizedKey: KeypairMaterial,
    expiresAtMs: number | null = null,
  ): string {
    const networkId = this.resolvedNetworkId();
    const msg = canonicalJsonBytes(
      canonicalWalletPopObject({
        networkId,
        walletId,
        participantIdentity,
        authorizedPubkey: authorizedKey.public_key_hex,
        purpose,
        nonce: popNonce,
        expiresAtMs,
      }),
    );
    return signEd25519(authorizedKey.private_key_hex, msg);
  }

  signTransferApproval(
    tokenId: string,
    fromWalletId: string,
    toWalletId: string,
    amount: number | bigint | string,
    cosignerKey: KeypairMaterial,
  ): string {
    const networkId = this.resolvedNetworkId();
    const msg = canonicalJsonBytes(
      canonicalTransferApprovalObject({
        networkId,
        tokenId,
        fromWalletId,
        toWalletId,
        amount,
      }),
    );
    return signEd25519(cosignerKey.private_key_hex, msg);
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
    const requestId = `req_${crypto.randomUUID().replace(/-/g, "")}`;
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
    const signature = signEd25519(this.identity.participant_key.private_key_hex, signingBytes);
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
  getProgram(programId: string): Promise<ProgramSubmission> { return this.getJson(`/v1/programs/${programId}`); }
  getTransaction(txId: string): Promise<Record<string, unknown>> { return this.getJson(`/v1/transactions/${txId}`); }
  listSpaces(): Promise<unknown[]> { return this.getJson("/v1/spaces"); }
  listRegions(): Promise<unknown[]> { return this.getJson("/v1/regions"); }
  listWallets(): Promise<unknown[]> { return this.getJson("/v1/wallets"); }
  listTokens(): Promise<unknown[]> { return this.getJson("/v1/tokens"); }
  listContracts(): Promise<unknown[]> { return this.getJson("/v1/contracts"); }
  listLoans(): Promise<unknown[]> { return this.getJson("/v1/loans"); }
  getLedgerEvents(): Promise<unknown[]> { return this.getJson("/v1/ledger/events"); }
  getLedgerProofs(): Promise<Record<string, unknown>> { return this.getJson("/v1/ledger/proofs"); }
  verifyLedgerReplay(): Promise<Record<string, unknown>> { return this.getJson("/v1/ledger/replay"); }
  verifyTokenSupply(tokenId: string): Promise<Record<string, unknown>> { return this.getJson(`/v1/tokens/${tokenId}/supply`); }
  getConsensusStatus(): Promise<Record<string, unknown>> { return this.getJson("/v1/consensus/status"); }
  getEquivocations(): Promise<Record<string, unknown>> { return this.getJson("/v1/consensus/equivocations"); }

  verifyReconstruction(entityKind: string, entityId: string): Promise<ReconstructionReport> {
    return this.postJson<ReconstructionReport>("/v1/reconstruction/verify", {
      entity_kind: entityKind,
      entity_id: entityId,
    });
  }

  subscribeEvents(onEvent: (evt: Record<string, unknown>) => void): WebSocket {
    const wsUrl = this.baseUrl.replace(/^https:\/\//, "wss://").replace(/^http:\/\//, "ws://") + "/v1/ws";
    const ws = new WebSocket(wsUrl);
    ws.addEventListener("message", (evt) => {
      try {
        onEvent(JSON.parse(String(evt.data)) as Record<string, unknown>);
      } catch {
        // ignore malformed frames
      }
    });
    return ws;
  }

  async getJson<T = Record<string, unknown>>(endpointPath: string): Promise<T> {
    const res = await fetch(`${this.baseUrl}${endpointPath}`);
    const body = (await res.json()) as Record<string, unknown>;
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${(body.error as string) ?? JSON.stringify(body)}`);
    }
    return body as T;
  }

  async postJson<T = Record<string, unknown>>(endpointPath: string, payload: unknown): Promise<T> {
    const res = await fetch(`${this.baseUrl}${endpointPath}`, {
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
