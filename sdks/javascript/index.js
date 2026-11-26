import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { blake3Hex } from "./blake3.js";
import { canonicalJsonBytes } from "./canonical.js";
import {
  ClientIdentity,
  COMPILER_VERSION,
  LANGUAGE_VERSION,
  PROTOCOL_VERSION,
  canonicalProgramSubmitObject,
  canonicalTransferApprovalObject,
  canonicalWalletPopObject,
  signEd25519,
} from "./crypto.js";

export * from "./blake3.js";
export * from "./canonical.js";
export * from "./crypto.js";

const IMPORT_RE = /^\s*import\s+"([^"]+)"(?:\s+(?:blake3|sha256)\s+"([^"]+)")?(?:\s+as\s+[A-Za-z0-9_]+)?\s*;/gm;
const MAX_IMPORT_MODULES = 64;

export async function loadModulesForSource(sourceBytes, baseDir) {
  const realBase = await fs.realpath(baseDir);
  const modules = {};
  const queue = [sourceBytes];
  while (queue.length > 0) {
    const current = queue.pop();
    IMPORT_RE.lastIndex = 0;
    let match;
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
  constructor(baseUrl, identity, expectedNetworkId = null) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.identity = identity;
    this.expectedNetworkId = expectedNetworkId;
    this.connectedNetworkId = null;
    this.nonce = 1;
  }

  async connect() {
    const info = await this.getJson("/v1/network/info");
    if (info.protocol_version !== PROTOCOL_VERSION) {
      throw new Error(`Protocol mismatch: remote ${info.protocol_version} != ${PROTOCOL_VERSION}`);
    }
    if (this.expectedNetworkId && info.network_id !== this.expectedNetworkId) {
      throw new Error(`Expected network ${this.expectedNetworkId}, got ${info.network_id}`);
    }
    this.connectedNetworkId = info.network_id;
    return info;
  }

  resolvedNetworkId() {
    const net = this.connectedNetworkId || this.expectedNetworkId;
    if (!net) {
      throw new Error("Client must call connect() before write operations");
    }
    return net;
  }

  async join(scopes = ["NETWORK", "SPACE", "REGION", "WALLET", "TOKEN"], scopeAuthorizations = []) {
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

  async participantStatus(participantId = this.identity.participant_id) {
    return this.getJson(`/v1/participants/${participantId}/scope`);
  }

  async loadModulesForSource(sourceBytes, baseDir) {
    return loadModulesForSource(sourceBytes, baseDir);
  }

  async compileSource(fileName, sourceBytes, modules = {}) {
    return this.postJson("/v1/language/compile", {
      file_name: fileName,
      source_bytes: sourceBytes,
      modules,
    });
  }

  async submitVxFile(filePath, executionParams = {}) {
    const abs = path.resolve(filePath);
    const sourceBytes = await fs.readFile(abs, "utf8");
    const modules = await this.loadModulesForSource(sourceBytes, path.dirname(abs));
    return this.submitProgram(path.basename(abs), sourceBytes, modules, executionParams);
  }

  async submitProgram(fileName, sourceBytes, modules = {}, executionParams = {}) {
    if (!this.connectedNetworkId) await this.connect();
    const networkId = this.resolvedNetworkId();
    const requestId = `req_${crypto.randomUUID().replace(/-/g, "")}`;
    const nonce = this.nonce++;
    const signingObj = canonicalProgramSubmitObject({
      actorPubkey: this.identity.participant_key.public_key_hex,
      fileName,
      sourceBytes,
      modules,
      networkId,
      requestId,
      nonce,
      executionParams,
    });
    const signingBytes = canonicalJsonBytes(signingObj);
    const signature = signEd25519(this.identity.participant_key.private_key_hex, signingBytes);
    return this.postJson("/v1/programs/submit", {
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

  signWalletPop(walletId, participantIdentity, purpose, popNonce, authorizedKey, expiresAtMs = null) {
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

  signTransferApproval(tokenId, fromWalletId, toWalletId, amount, cosignerKey) {
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

  updateWalletReceivePolicy(walletId, mode, allowedSenders = []) {
    return this.submitOperation({
      op: "UpdateWalletReceivePolicy",
      payload: {
        wallet_id: walletId,
        mode,
        allowed_senders: allowedSenders,
      },
    });
  }

  async submitOperation(operation) {
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

  getNetworkInfo() { return this.getJson("/v1/network/info"); }
  getNetworkStatus() { return this.getJson("/v1/network/status"); }
  listNodes() { return this.getJson("/v1/nodes"); }
  getNodeDetails(nodeId) { return this.getJson(`/v1/nodes/${nodeId}`); }
  getExplorerNetwork() { return this.getJson("/v1/explorer/network"); }
  getProgram(programId) { return this.getJson(`/v1/programs/${programId}`); }
  getProgramStatus(programId) { return this.getJson(`/v1/programs/${programId}/status`); }
  getTransaction(txId) { return this.getJson(`/v1/transactions/${txId}`); }
  listSpaces() { return this.getJson("/v1/spaces"); }
  listRegions() { return this.getJson("/v1/regions"); }
  listWallets() { return this.getJson("/v1/wallets"); }
  getWallet(walletId) { return this.getJson(`/v1/wallets/${walletId}`); }
  listTokens() { return this.getJson("/v1/tokens"); }
  getToken(tokenId) { return this.getJson(`/v1/tokens/${tokenId}`); }
  listContracts() { return this.getJson("/v1/contracts"); }
  getContract(contractId) { return this.getJson(`/v1/contracts/${contractId}`); }
  listLoans() { return this.getJson("/v1/loans"); }
  getLoan(loanId) { return this.getJson(`/v1/loans/${loanId}`); }
  getLedgerEvents() { return this.getJson("/v1/ledger/events"); }
  getLedgerProofs() { return this.getJson("/v1/ledger/proofs"); }
  verifyLedgerReplay() { return this.getJson("/v1/ledger/replay"); }
  verifyTokenSupply(tokenId) { return this.getJson(`/v1/tokens/${tokenId}/supply`); }
  getConsensusStatus() { return this.getJson("/v1/consensus/status"); }
  getEquivocations() { return this.getJson("/v1/consensus/equivocations"); }

  createContract(name, regionId, rules, actions) {
    return this.submitOperation({
      op: "CreateContract",
      payload: { name, region_id: regionId, rules, actions },
    });
  }

  executeContract(contractId, action, args = {}) {
    return this.submitOperation({
      op: "ExecuteContract",
      payload: { contract_id: contractId, action, args },
    });
  }

  createLoan(name, tokenId, lenderWalletId, borrowerWalletId, principal, collateral, interestBps, maturityAtMs = null) {
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

  executeLoan(loanId, action, amount) {
    return this.submitOperation({
      op: "ExecuteLoan",
      payload: { loan_id: loanId, action, amount },
    });
  }

  verifyReconstruction(entityKind, entityId) {
    return this.postJson("/v1/reconstruction/verify", {
      entity_kind: entityKind,
      entity_id: entityId,
    });
  }

  subscribeEvents(onEvent) {
    const wsUrl = this.baseUrl.replace(/^https:\/\//, "wss://").replace(/^http:\/\//, "ws://") + "/v1/ws";
    const ws = new WebSocket(wsUrl);
    ws.addEventListener("message", (evt) => {
      try {
        onEvent(JSON.parse(String(evt.data)));
      } catch {
        // ignore non-json frames
      }
    });
    return ws;
  }

  async getJson(endpointPath) {
    const res = await fetch(`${this.baseUrl}${endpointPath}`);
    const body = await res.json();
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${body.error ?? JSON.stringify(body)}`);
    }
    return body;
  }

  async postJson(endpointPath, payload) {
    const res = await fetch(`${this.baseUrl}${endpointPath}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await res.json();
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${body.error ?? JSON.stringify(body)}`);
    }
    return body;
  }
}

export { ClientIdentity };
