import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
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
const MAX_IMPORT_MODULES = 64;

async function reserveDurableNonce(filePath: string, networkId: string, actorPubkey: string, minimumNextNonce: number): Promise<number> {
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.chmod(dir, 0o700).catch(() => {});
  const lockPath = `${filePath}.lock`;
  let lockHandle: Awaited<ReturnType<typeof fs.open>> | null = null;

  for (let attempt = 0; attempt < 400; attempt += 1) {
    try {
      lockHandle = await fs.open(lockPath, "wx", 0o600);
      await lockHandle.writeFile(JSON.stringify({ pid: process.pid, created_at_ms: Date.now() }));
      await lockHandle.sync();
      break;
    } catch (error: any) {
      if (error.code !== "EEXIST") throw error;
      try {
        const stat = await fs.stat(lockPath);
        if (Date.now() - stat.mtimeMs > 30_000) {
          let ownerPid: number | null = null;
          try {
            const owner = JSON.parse(await fs.readFile(lockPath, "utf8"));
            ownerPid = Number.isSafeInteger(owner.pid) ? owner.pid : null;
          } catch {}
          let ownerAlive = false;
          if (ownerPid !== null) {
            try {
              process.kill(ownerPid, 0);
              ownerAlive = true;
            } catch (probeError: any) {
              ownerAlive = probeError.code !== "ESRCH";
            }
          }
          if (!ownerAlive) {
            await fs.unlink(lockPath).catch(() => {});
            continue;
          }
        }
      } catch (statError: any) {
        if (statError.code === "ENOENT") continue;
      }
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
  if (!lockHandle) {
    throw new Error(`Timed out acquiring durable nonce lock ${lockPath}; refusing to risk nonce reuse`);
  }

  try {
    let current = minimumNextNonce;
    try {
      const stored = JSON.parse(await fs.readFile(filePath, "utf8"));
      if (
        stored.version !== 1 ||
        stored.network_id !== networkId ||
        stored.actor_pubkey !== actorPubkey ||
        !Number.isSafeInteger(stored.next_nonce) ||
        stored.next_nonce < 1
      ) {
        throw new Error(`Invalid or mismatched durable nonce state at ${filePath}`);
      }
      current = Math.max(current, stored.next_nonce);
    } catch (error: any) {
      if (error.code !== "ENOENT") throw error;
    }

    if (!Number.isSafeInteger(current) || current < 1 || current >= Number.MAX_SAFE_INTEGER) {
      throw new Error("Request nonce exhausted JavaScript's safe integer range");
    }
    const nextNonce = current + 1;
    const tempPath = `${filePath}.tmp-${process.pid}-${crypto.randomUUID()}`;
    const tempHandle = await fs.open(tempPath, "wx", 0o600);
    try {
      await tempHandle.writeFile(JSON.stringify({
        version: 1,
        network_id: networkId,
        actor_pubkey: actorPubkey,
        next_nonce: nextNonce,
      }) + "\n");
      await tempHandle.sync();
    } finally {
      await tempHandle.close();
    }
    await fs.rename(tempPath, filePath);
    await fs.chmod(filePath, 0o600).catch(() => {});
    return current;
  } finally {
    await lockHandle.close();
    await fs.unlink(lockPath).catch(() => {});
  }
}


export async function loadModulesForSource(
  sourceBytes: string,
  baseDir: string,
): Promise<Record<string, string>> {
  const realBase = await fs.realpath(baseDir);
  const modules: Record<string, string> = {};
  const queue = [sourceBytes];
  while (queue.length > 0) {
    const current = queue.pop()!;
    IMPORT_RE.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = IMPORT_RE.exec(current)) !== null) {
      const importPath = match[1].trim();
      if (
        !importPath ||
        importPath.includes("\\") ||
        path.isAbsolute(importPath) ||
        importPath.split("/").some((seg) => seg === "..")
      ) {
        throw new Error(`Unsafe module import path: ${importPath}`);
      }
      if (!(importPath in modules)) {
        if (Object.keys(modules).length >= MAX_IMPORT_MODULES) {
          throw new Error(`Imported module count exceeded limit (${MAX_IMPORT_MODULES})`);
        }
        const candidate = path.resolve(realBase, importPath);
        if (candidate !== realBase && !candidate.startsWith(realBase + path.sep)) {
          throw new Error(`Module import path escapes base directory: ${importPath}`);
        }
        const realTarget = await fs.realpath(candidate);
        if (realTarget !== realBase && !realTarget.startsWith(realBase + path.sep)) {
          throw new Error(`Module import symlink escapes base directory: ${importPath}`);
        }
        const content = await fs.readFile(realTarget, "utf8");
        modules[importPath] = content;
        queue.push(content);
      }
    }
  }
  return modules;
}

export class VectorNetworkClient {
  readonly baseUrl: string;
  readonly identity: ClientIdentity;
  readonly expectedNetworkId: string | null;
  connectedNetworkId: string | null = null;
  private nonce = 1;
  private readonly nonceStorePath: string | null;

  constructor(baseUrl: string, identity: ClientIdentity, expectedNetworkId: string | null = null, nonceStorePath: string | null = null) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.identity = identity;
    this.expectedNetworkId = expectedNetworkId;
    this.nonceStorePath = nonceStorePath;
  }

  async reserveNonce(): Promise<number> {
    const networkId = this.resolvedNetworkId();
    const actorPubkey = this.identity.participant_key.public_key_hex;
    const key = crypto.createHash("sha256").update(`${networkId}::${actorPubkey}`).digest("hex");
    const storePath = this.nonceStorePath ?? path.join(os.homedir(), ".vnetwork", "nonces", `${key}.json`);
    const reserved = await reserveDurableNonce(storePath, networkId, actorPubkey, this.nonce);
    this.nonce = reserved + 1;
    return reserved;
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
    return loadModulesForSource(sourceBytes, baseDir);
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
    const nonce = await this.reserveNonce();
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
  getNodeDetails(nodeId: string): Promise<Record<string, unknown>> { return this.getJson(`/v1/nodes/${nodeId}`); }
  getExplorerNetwork(): Promise<Record<string, unknown>> { return this.getJson("/v1/explorer/network"); }
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

  createContract(
    name: string,
    regionId: string | null,
    rules: unknown,
    actions: unknown[],
  ): Promise<Record<string, unknown>> {
    return this.submitOperation({
      op: "CreateContract",
      payload: { name, region_id: regionId, rules, actions },
    });
  }

  executeContract(
    contractId: string,
    action: string,
    args: unknown = {},
  ): Promise<Record<string, unknown>> {
    return this.submitOperation({
      op: "ExecuteContract",
      payload: { contract_id: contractId, action, args },
    });
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

  executeLoan(
    loanId: string,
    action: string,
    amount: number,
  ): Promise<Record<string, unknown>> {
    return this.submitOperation({
      op: "ExecuteLoan",
      payload: { loan_id: loanId, action, amount },
    });
  }

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
