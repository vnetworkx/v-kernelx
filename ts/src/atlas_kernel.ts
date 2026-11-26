import { createHash } from "node:crypto";
import path from "node:path";
import {
  blake3Hex,
  deriveWalletId,
  EncryptedKeystore,
  generateEd25519Keypair,
  isValidHex,
  resolveOrCreateLocalSecret,
  verifyEd25519,
} from "./crypto.ts";
import {
  buildRegionGenesisEvent,
  canonicalRegionId,
  createEmptyCoreState,
  insertRegionIntoCore,
  isRegionCreateEvent,
  regionLookupKey,
  regionStateFromEvent,
  validateRegionCreateRequest,
  verifyRegionCreateRequestSignature,
  type CoreState,
  type RegionCreateRequest,
  type RegionState,
  type RegionVisibility,
} from "./region.ts";
import {
  canonicalEventHash,
  canonicalEventId,
  canonicalPayloadHash,
  canonicalReplayHash,
  canonicalStateMapBytes,
  canonicalStateRootHash,
  canonicalTaggedHash,
  computeStateRootFromCanonicalBytes,
  sortedJsonStringify,
  type CanonicalOperationType,
  type CanonicalSnapshot,
  type CanonicalStateRoot,
  type CanonicalVectorEvent,
  type CanonicalVectorState,
} from "./serialization.ts";
import { SqliteKernelStore, type PublicWalletRecord } from "./sqlite_store.ts";
import {
  canonicalTokenRequestSigningBytes,
  checkedAddU128,
  checkedSubU128,
  computeDrainDistribution,
  DEFAULT_AUTH_RATIO_THRESHOLD,
  DEFAULT_TRANSFER_DRAIN_BPS,
  deriveTokenId,
  parseU128,
  TOKEN_BURN_OP,
  TOKEN_CREATE_OP,
  TOKEN_MINT_OP,
  TOKEN_TRANSFER_OP,
  TOKEN_TRANSPORT_OP,
  type BeneficiaryRole,
  type DrainFeeBreakdown,
  type DrainRewardRecord,
  type TokenBalance,
  type TokenBurnRequest,
  type TokenCreateRequest,
  type TokenDefinition,
  type TokenTransferRequest,
  type TokenTransportRequest,
} from "./token.ts";
import {
  buildCertificationState,
  canonicalAttestationSigningBytes,
  canonicalVectorOpSigningBytes,
  computeMultidimensionalDrainDistribution,
  DEFAULT_QUORUM_BPS,
  VECTOR_CERTIFY_OP,
  VECTOR_DRAIN_OP,
  VECTOR_ORIGIN_OP,
  VECTOR_PROJECT_OP,
  VECTOR_RECONSTRUCT_OP,
  VECTOR_TRANSFER_OP,
  VECTOR_TRANSPORT_OP,
  type ConsensusRound,
  type EventAttestation,
  type ValidatorNode,
} from "./vectors.ts";
import {
  STATE_SCHEMA_V1,
  type CertificationState,
  type VectorRecordV1,
  type VectorStateV1,
} from "./types.ts";

export const KERNEL_VERSION = "0.1.4-atlas";
export const NETWORK_NAME = "ATLAS VECTOR NETWORK";
export const NETWORK_MODE = "decentralized-quorum-ledger";

export interface ReplayResult {
  final_state: Record<string, CanonicalVectorState>;
  core_state: CoreState;
  regions: Record<string, RegionState>;
  tokens: Record<string, TokenDefinition>;
  token_balances: Record<string, Record<string, string>>;
  state_root: CanonicalStateRoot;
  replay_hash: string;
  applied_event_hashes: string[];
  matches_stored_state: boolean;
  mismatch_reasons: string[];
}

export interface NodeStatus {
  kernel_version: string;
  network_name: string;
  network_mode: string;
  node_id: string;
  node_pubkey: string;
  storage_engine: string;
  db_path: string;
  db_integrity_ok: boolean;
  vector_count: number;
  record_count: number;
  event_count: number;
  region_count: number;
  wallet_count: number;
  token_count: number;
  validator_count: number;
  finalized_event_count: number;
  total_drain_rewards_count: number;
  state_root: CanonicalStateRoot;
  replay_hash: string;
  replay_verified: boolean;
}

export interface SyncBundle {
  protocol: "v-kernelx-sync-v1";
  source_node_id: string;
  source_node_pubkey: string;
  exported_at_ms: number;
  state_root: CanonicalStateRoot;
  replay_hash: string;
  validators: ValidatorNode[];
  events: CanonicalVectorEvent[];
  attestations: EventAttestation[];
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

export function findBlake3Nonce(seed: string, difficulty: number, maxAttempts = 1_000_000): number {
  if (difficulty <= 0) return 0;
  const prefix = "0".repeat(difficulty);
  for (let nonce = 0; nonce < maxAttempts; nonce += 1) {
    const buf = Buffer.allocUnsafe(8);
    buf.writeBigUInt64BE(BigInt(nonce), 0);
    const proof = blake3Hex(Buffer.concat([Buffer.from(seed, "utf8"), buf]));
    if (proof.startsWith(prefix)) {
      return nonce;
    }
  }
  throw new Error(`unable to find valid BLAKE3 nonce for difficulty ${difficulty}`);
}

export function verifyBlake3Origin(seed: string, nonce: number, difficulty: number): string {
  const buf = Buffer.allocUnsafe(8);
  buf.writeBigUInt64BE(BigInt(nonce), 0);
  const proof = blake3Hex(Buffer.concat([Buffer.from(seed, "utf8"), buf]));
  if (difficulty > 0 && !proof.startsWith("0".repeat(difficulty))) {
    throw new Error("origin proof rejected");
  }
  return proof;
}

function makeRecordId(prefix: string, vectorId: string, discriminator: string): string {
  return blake3Hex(`${prefix}:${vectorId}:${discriminator}`);
}

function buildRecordProof(record: Omit<VectorRecordV1, "proof">): string {
  return blake3Hex(
    sortedJsonStringify({
      after: record.after as unknown as Record<string, unknown>,
      before: (record.before ?? null) as unknown as Record<string, unknown>,
      certification: record.certification as unknown as Record<string, unknown>,
      operation: record.operation,
      parameters: (record.parameters ?? {}) as Record<string, unknown>,
      recordId: record.recordId,
      schema: record.schema,
      timestampMs: record.timestampMs,
      vectorId: record.vectorId,
    }),
  );
}

function sortEvents(events: CanonicalVectorEvent[]): CanonicalVectorEvent[] {
  return [...events].sort((a, b) => {
    if (a.logical_clock !== b.logical_clock) return a.logical_clock - b.logical_clock;
    if (a.timestamp !== b.timestamp) return a.timestamp - b.timestamp;
    if (a.event_hash !== b.event_hash) return a.event_hash < b.event_hash ? -1 : 1;
    return a.event_id < b.event_id ? -1 : a.event_id > b.event_id ? 1 : 0;
  });
}

export function validateDag(events: CanonicalVectorEvent[]): void {
  const index = new Map<string, number>();
  events.forEach((ev, i) => {
    if (!ev.event_hash) {
      throw new Error(`event ${ev.event_id} has empty event_hash`);
    }
    if (index.has(ev.event_hash)) {
      throw new Error(`duplicate event_hash detected: ${ev.event_hash}`);
    }
    index.set(ev.event_hash, i);
  });

  const indegree = new Map<string, number>();
  const children = new Map<string, string[]>();
  for (const ev of events) {
    indegree.set(ev.event_hash, 0);
    children.set(ev.event_hash, []);
  }

  for (const ev of events) {
    const seen = new Set<string>();
    for (const parentHash of ev.parent_hashes) {
      if (seen.has(parentHash)) {
        throw new Error(`duplicate parent hash in event: ${ev.event_hash}`);
      }
      seen.add(parentHash);
      const pIdx = index.get(parentHash);
      if (pIdx === undefined) {
        throw new Error(`missing parent event: ${parentHash}`);
      }
      const parent = events[pIdx];
      if (parent.region_id !== ev.region_id) {
        throw new Error(
          `region inadmissible: parent region ${parent.region_id} != child region ${ev.region_id}`,
        );
      }
      children.get(parentHash)!.push(ev.event_hash);
      indegree.set(ev.event_hash, (indegree.get(ev.event_hash) ?? 0) + 1);
    }
  }

  const queue: string[] = [];
  for (const [hash, deg] of indegree.entries()) {
    if (deg === 0) queue.push(hash);
  }

  let visited = 0;
  while (queue.length > 0) {
    const curr = queue.shift()!;
    visited += 1;
    for (const child of children.get(curr) ?? []) {
      const next = (indegree.get(child) ?? 0) - 1;
      indegree.set(child, next);
      if (next === 0) queue.push(child);
    }
  }

  if (visited !== events.length) {
    throw new Error("cycle detected in event DAG");
  }
}

export function validateEventIntegrity(event: CanonicalVectorEvent): void {
  if (!event.event_id.trim()) throw new Error("event_id is required");
  if (!event.region_id.trim()) throw new Error("region_id is required");
  if (!event.entity_id.trim()) throw new Error("entity_id is required");
  if (!event.actor_public_key.trim()) throw new Error("actor_public_key is required");
  if (!Number.isFinite(event.auth_ratio) || event.auth_ratio < 0 || event.auth_ratio > 1) {
    throw new Error("auth_ratio must be in [0, 1]");
  }
  if (event.vector_before.components.length !== event.vector_after.components.length) {
    throw new Error("dimension mismatch");
  }
  const expectedPayload = canonicalPayloadHash(event);
  if (event.payload_hash !== expectedPayload) {
    throw new Error(`payload_hash mismatch on event ${event.event_id}`);
  }
  const expectedEvent = canonicalEventHash(event);
  if (event.event_hash !== expectedEvent) {
    throw new Error(`event_hash mismatch on event ${event.event_id}`);
  }
  if (isRegionCreateEvent(event)) {
    if (!event.signature.trim()) {
      throw new Error("region create event requires a signature");
    }
    if (event.parent_hashes.length > 0) {
      throw new Error("region create event must be a root event");
    }
  }
}

export class AtlasKernel {
  readonly dataDir: string;
  readonly store: SqliteKernelStore;
  readonly keystore: EncryptedKeystore;
  readonly nodeId: string;
  readonly nodePubkey: string;

  constructor(dataDir = path.resolve(process.cwd(), "data")) {
    this.dataDir = dataDir;
    const dbPath = path.join(dataDir, "atlas-kernel.db");
    const keystoreDir = path.join(dataDir, "keystore");
    const passphraseFile = path.join(dataDir, ".keystore-passphrase");
    const passphrase = resolveOrCreateLocalSecret(passphraseFile, "ATLAS_KEYSTORE_PASSPHRASE");

    this.store = new SqliteKernelStore(dbPath);
    this.keystore = new EncryptedKeystore(keystoreDir, passphrase);

    const existingNodeId = this.store.getMeta("node_id");
    const existingNodePub = this.store.getMeta("node_pubkey");
    if (existingNodeId && existingNodePub) {
      this.nodeId = existingNodeId;
      this.nodePubkey = existingNodePub;
    } else {
      const nodeKey = generateEd25519Keypair();
      const nodeWalletId = `node_${blake3Hex(Buffer.from(nodeKey.publicKeyHex, "hex")).slice(0, 20)}`;
      this.keystore.storeKey(nodeWalletId, nodeKey);
      this.store.inTransaction(() => {
        this.store.setMeta("node_id", nodeWalletId);
        this.store.setMeta("node_pubkey", nodeKey.publicKeyHex);
        this.store.setMeta("network_name", NETWORK_NAME);
        this.store.setMeta("kernel_version", KERNEL_VERSION);
      });
      this.nodeId = nodeWalletId;
      this.nodePubkey = nodeKey.publicKeyHex;
    }

    this.ensureNodeWalletAndValidator();
  }

  private ensureNodeWalletAndValidator(): void {
    const now = Date.now();
    this.store.inTransaction(() => {
      if (!this.store.getWallet(this.nodeId)) {
        this.store.putWallet({
          wallet_id: this.nodeId,
          public_key_hex: this.nodePubkey,
          label: "Atlas Network Pool",
          region_id: null,
          creator_wallet_id: null,
          created_at_ms: now,
        });
      }
      if (!this.store.getValidator(this.nodeId)) {
        this.store.putValidator({
          node_id: this.nodeId,
          public_key_hex: this.nodePubkey,
          label: "Atlas Genesis Node",
          weight: 100,
          active: true,
          joined_at_ms: now,
        });
      }
    });
  }

  close(): void {
    this.store.close();
  }

  private nextLogicalClock(): number {
    const events = this.store.listEvents();
    if (events.length === 0) return 0;
    return Math.max(...events.map((e) => e.logical_clock)) + 1;
  }

  private latestParentHashForEntity(entityId: string): string[] {
    const events = sortEvents(this.store.listEvents());
    for (let i = events.length - 1; i >= 0; i -= 1) {
      if (events[i].entity_id === entityId) {
        return [events[i].event_hash];
      }
    }
    return [];
  }

  private nextSequenceForEntity(entityId: string, regionId: string): number {
    const events = this.store.listEvents();
    return events.filter((e) => e.entity_id === entityId && e.region_id === regionId).length + 1;
  }

  private ensureParentClosure(event: CanonicalVectorEvent): void {
    for (const parentHash of event.parent_hashes) {
      if (!this.store.getEventByHash(parentHash)) {
        throw new Error(`orphan event ${event.event_hash} references missing parent ${parentHash}`);
      }
    }
  }

  private buildTransitionEvent(params: {
    before: VectorStateV1 | null;
    after: VectorStateV1;
    operation: CanonicalOperationType;
    logicalClock: number;
    timestamp: number;
    parentHashes: string[];
    actorPublicKey: string;
    signature?: string;
    sequenceOffset?: number;
  }): CanonicalVectorEvent {
    const toEventState = (s: VectorStateV1): CanonicalVectorState => ({
      components: s.components.map((c) => String(c)),
      owner_public_key: s.ownerPubkey,
      type_tag: s.vectorType,
      metadata: { ...s.typeMetadata },
    });

    const vectorBefore: CanonicalVectorState = params.before
      ? toEventState(params.before)
      : {
          components: params.after.components.map(() => "0"),
          owner_public_key: params.after.ownerPubkey,
          type_tag: params.after.vectorType,
          metadata: {},
        };

    const vectorAfter = toEventState(params.after);
    const seq =
      this.nextSequenceForEntity(params.after.vectorId, params.after.spaceId) +
      (params.sequenceOffset ?? 0);
    const eventId = canonicalEventId(
      params.after.vectorId,
      params.after.spaceId,
      params.operation,
      params.logicalClock,
      seq,
    );

    const event: CanonicalVectorEvent = {
      event_id: eventId,
      parent_hashes: params.parentHashes,
      region_id: params.after.spaceId,
      entity_id: params.after.vectorId,
      operation: params.operation,
      vector_before: vectorBefore,
      vector_after: vectorAfter,
      auth_ratio: params.after.certification.authRatio / 1000,
      certified: params.after.certification.certified,
      actor_public_key: params.actorPublicKey,
      logical_clock: params.logicalClock,
      timestamp: params.timestamp,
      payload_hash: "",
      event_hash: "",
      signature: params.signature ?? "",
    };

    event.payload_hash = canonicalPayloadHash(event);
    event.event_hash = canonicalEventHash(event);
    return event;
  }

  private recordLocalValidatorAttestation(eventHash: string, stateRootHash: string): void {
    if (!this.keystore.hasKey(this.nodeId)) return;
    const validator = this.store.getValidator(this.nodeId);
    if (!validator || !validator.active) return;
    const timestamp_ms = Date.now();
    const bytes = canonicalAttestationSigningBytes({
      event_hash: eventHash,
      validator_id: this.nodeId,
      validator_pubkey: this.nodePubkey,
      vote_accept: true,
      state_root_hash: stateRootHash,
      timestamp_ms,
    });
    const signature = this.keystore.signWithWallet(this.nodeId, bytes);
    this.store.putAttestation({
      event_hash: eventHash,
      validator_id: this.nodeId,
      validator_pubkey: this.nodePubkey,
      vote_accept: true,
      state_root_hash: stateRootHash,
      signature,
      timestamp_ms,
    });
  }

  private computeLightStateRootHash(): string {
    const events = this.store.listEvents();
    const lastClock = events.length > 0 ? events[events.length - 1].logical_clock : 0;
    const stateMap: Record<string, CanonicalVectorState> = {};
    for (const v of this.store.listVectors()) {
      stateMap[v.vectorId] = {
        components: v.components.map((c) => String(c)),
        owner_public_key: v.ownerPubkey,
        type_tag: v.vectorType,
        metadata: { ...v.typeMetadata },
      };
    }
    const bytes = canonicalStateMapBytes(stateMap);
    return computeStateRootFromCanonicalBytes(bytes, events.length, lastClock).root_hash;
  }

  // -------------------------
  // Decentralized Open Wallets
  // -------------------------
  createOpenWallet(
    label: string,
    regionId: string | null = null,
    creatorWalletId: string | null = null,
  ): { wallet: PublicWalletRecord; private_key_hex: string } {
    const cleanLabel = label.trim();
    if (!cleanLabel) {
      throw new Error("wallet label cannot be empty");
    }
    if (regionId) {
      const region = this.store.getRegion(regionId);
      if (!region) {
        throw new Error(`region not found: ${regionId}`);
      }
    }
    if (creatorWalletId) {
      const creator = this.store.getWallet(creatorWalletId);
      if (!creator) {
        throw new Error(`creator wallet not found: ${creatorWalletId}`);
      }
    }
    const kp = generateEd25519Keypair();
    const walletId = deriveWalletId(kp.publicKeyHex);
    const record: PublicWalletRecord = {
      wallet_id: walletId,
      public_key_hex: kp.publicKeyHex,
      label: cleanLabel,
      region_id: regionId,
      creator_wallet_id: creatorWalletId,
      created_at_ms: Date.now(),
    };
    this.keystore.storeKey(walletId, kp);
    this.store.inTransaction(() => {
      this.store.putWallet(record);
    });
    return { wallet: record, private_key_hex: kp.privateSeedHex };
  }

  createWallet(
    label: string,
    regionId: string | null = null,
    creatorWalletId: string | null = null,
  ): PublicWalletRecord {
    return this.createOpenWallet(label, regionId, creatorWalletId).wallet;
  }

  registerExternalWallet(params: {
    public_key_hex: string;
    label: string;
    region_id?: string | null;
    creator_wallet_id?: string | null;
  }): PublicWalletRecord {
    const cleanPub = params.public_key_hex.trim().toLowerCase();
    if (!isValidHex(cleanPub, 32)) {
      throw new Error("public_key_hex must be a 64-character Ed25519 public key");
    }
    const cleanLabel = params.label.trim();
    if (!cleanLabel) {
      throw new Error("wallet label cannot be empty");
    }
    const regionId = params.region_id?.trim() || null;
    if (regionId && !this.store.getRegion(regionId)) {
      throw new Error(`region not found: ${regionId}`);
    }
    const creatorWalletId = params.creator_wallet_id?.trim() || null;
    if (creatorWalletId && !this.store.getWallet(creatorWalletId)) {
      throw new Error(`creator wallet not found: ${creatorWalletId}`);
    }
    const existing = this.store.getWallet(cleanPub);
    if (existing) {
      throw new Error(`wallet already registered for public key: ${existing.wallet_id}`);
    }
    const walletId = deriveWalletId(cleanPub);
    const record: PublicWalletRecord = {
      wallet_id: walletId,
      public_key_hex: cleanPub,
      label: cleanLabel,
      region_id: regionId,
      creator_wallet_id: creatorWalletId,
      created_at_ms: Date.now(),
    };
    this.store.inTransaction(() => {
      this.store.putWallet(record);
    });
    return record;
  }

  getWallet(walletIdOrPubkey: string): PublicWalletRecord | null {
    return this.store.getWallet(walletIdOrPubkey);
  }

  listWallets(): PublicWalletRecord[] {
    return this.store.listWallets();
  }

  computeWalletAuthRatio(wallet: PublicWalletRecord): number {
    // Verified Ed25519 pubkey (300) + base balance/structure (350) + region membership (350)
    const base = 650;
    const regionBonus = wallet.region_id && this.store.getRegion(wallet.region_id) ? 350 : 0;
    return Math.min(1000, base + regionBonus);
  }

  signWithWallet(walletId: string, payload: Uint8Array): string {
    return this.keystore.signWithWallet(walletId, payload);
  }

  getWalletTransactions(walletIdOrPubkey: string): VectorRecordV1[] {
    const wallet = this.store.getWallet(walletIdOrPubkey);
    const targetId = wallet ? wallet.wallet_id : walletIdOrPubkey;
    const targetPubkey = wallet ? wallet.public_key_hex : walletIdOrPubkey;
    return this.store.listRecords().filter((rec) => {
      const p = (rec.parameters ?? {}) as Record<string, unknown>;
      return (
        rec.vectorId === targetId ||
        rec.after.ownerPubkey === targetPubkey ||
        p.wallet_id === targetId ||
        p.from_wallet_id === targetId ||
        p.to_wallet_id === targetId
      );
    });
  }

  // -------------------------
  // Canonical Region Engine (v0.1.4 compatible)
  // -------------------------
  createSignedRegionWithWallet(params: {
    creatorWalletId: string;
    regionName: string;
    regionPrefix?: string | null;
    suggestedTitle?: string | null;
    visibility: RegionVisibility;
    section: number;
    triggerEventHash?: string;
    difficulty?: number;
    accessKey?: string | null;
    metadata?: Record<string, string>;
  }): { region: RegionState; event: CanonicalVectorEvent; request: RegionCreateRequest } {
    const wallet = this.store.getWallet(params.creatorWalletId);
    if (!wallet) {
      throw new Error(`creator wallet not found: ${params.creatorWalletId}`);
    }

    let triggerEventHash = params.triggerEventHash?.trim() ?? "";
    if (!triggerEventHash) {
      triggerEventHash = this.ensureCoreTriggerEventHash(wallet.public_key_hex, wallet.wallet_id);
    }

    const difficulty = params.difficulty ?? 1;
    const proofSeed = `${params.regionName}:${params.regionPrefix ?? ""}:${triggerEventHash}`;
    const proofNonce = findBlake3Nonce(proofSeed, difficulty);
    const creationProof = `${proofSeed}:${proofNonce}:${verifyBlake3Origin(proofSeed, proofNonce, difficulty)}`;

    const unsignedRequest: RegionCreateRequest = {
      region_name: params.regionName,
      region_prefix: params.regionPrefix ?? null,
      suggested_title: params.suggestedTitle ?? null,
      visibility: params.visibility,
      section: params.section,
      trigger_event_hash: triggerEventHash,
      creation_proof: creationProof,
      access_key: params.accessKey ?? null,
      metadata: params.metadata ?? {},
      request_signature: "pending",
    };

    const sigBytes = canonicalRegionRequestSignatureBytesCompat(unsignedRequest);
    const signature = this.keystore.signWithWallet(wallet.wallet_id, sigBytes);
    const signedRequest: RegionCreateRequest = {
      ...unsignedRequest,
      request_signature: signature,
    };

    const result = this.createRegion(signedRequest, wallet.public_key_hex);
    return { ...result, request: signedRequest };
  }

  ensureCoreTriggerEventHash(actorPublicKey: string, signerWalletId?: string): string {
    const coreVector = this.store.getVector("core");
    if (!coreVector) {
      const seedCore = "core-registry-seed";
      const nonceCore = findBlake3Nonce(seedCore, 1);
      this.originCreate({
        vectorId: "core",
        ownerPubkey: actorPublicKey,
        spaceId: "core",
        components: [1],
        seed: seedCore,
        nonce: nonceCore,
        difficulty: 1,
        signerWalletId,
      });
    }
    const events = this.store.listEvents();
    const coreEv = events.find((e) => e.entity_id === "core") ?? events[0];
    if (!coreEv) {
      throw new Error("unable to establish trigger_event_hash for region genesis");
    }
    return coreEv.event_hash;
  }

  createRegion(
    request: RegionCreateRequest,
    actorPublicKey: string,
  ): { region: RegionState; event: CanonicalVectorEvent } {
    validateRegionCreateRequest(request);
    verifyRegionCreateRequestSignature(actorPublicKey, request);

    const triggerExists = this.store.getEventByHash(request.trigger_event_hash);
    if (!triggerExists) {
      throw new Error(
        `trigger_event_hash not found in event store: ${request.trigger_event_hash}`,
      );
    }

    const lookup = regionLookupKey(request.region_name, request.region_prefix);
    if (this.store.getRegionByLookupKey(lookup)) {
      throw new Error(`region already exists for lookup key: ${lookup}`);
    }

    const logicalClock = this.nextLogicalClock();
    const timestamp = Date.now();
    const sequence = 1;

    const event = buildRegionGenesisEvent(
      request,
      actorPublicKey,
      logicalClock,
      timestamp,
      sequence,
    );

    validateEventIntegrity(event);
    const region = regionStateFromEvent(event);

    if (this.store.getRegion(region.region_id)) {
      throw new Error(`region already exists: ${region.region_id}`);
    }

    const expectedRegionId = canonicalRegionId(request, actorPublicKey, sequence);
    if (region.region_id !== expectedRegionId) {
      throw new Error("canonical region ID mismatch");
    }

    this.store.inTransaction(() => {
      this.ensureParentClosure(event);
      this.store.appendEvent(event);
      this.store.putRegion(region, lookup);
      this.recordLocalValidatorAttestation(event.event_hash, this.computeLightStateRootHash());
    });

    return { region, event };
  }

  listRegions(): RegionState[] {
    return this.store.listRegions();
  }

  getRegion(regionIdOrName: string): RegionState | null {
    const byId = this.store.getRegion(regionIdOrName);
    if (byId) return byId;
    const regions = this.store.listRegions();
    const lower = regionIdOrName.trim().toLowerCase();
    return (
      regions.find(
        (r) =>
          r.normalized_name === lower ||
          (r.region_prefix && r.region_prefix.toLowerCase() === lower),
      ) ?? null
    );
  }

  // -------------------------
  // Core & Multidimensional Vector Operations (Persistent SQLite + Replay + Auth Ratio + Escrow)
  // -------------------------
  originCreate(params: {
    vectorId: string;
    ownerPubkey: string;
    spaceId: string;
    components: number[];
    seed: string;
    nonce: number;
    difficulty: number;
    signerWalletId?: string;
    dimensionLabels?: string[];
    creatorWalletId?: string;
    drainBps?: number;
    signature?: string;
  }): VectorStateV1 {
    if (!params.vectorId.trim() || !params.ownerPubkey.trim() || !params.spaceId.trim()) {
      throw new Error("vectorId, ownerPubkey, and spaceId are required");
    }
    if (!Array.isArray(params.components) || params.components.length === 0) {
      throw new Error("components must be a non-empty array");
    }
    if (params.components.some((c) => !Number.isInteger(c) || c < 0)) {
      throw new Error("components must be non-negative integers");
    }
    if (this.store.getVector(params.vectorId)) {
      throw new Error(`vector already exists: ${params.vectorId}`);
    }
    const proofHash = verifyBlake3Origin(params.seed, params.nonce, params.difficulty);
    const now = Date.now();
    const typeMetadata: Record<string, string> = {};
    if (params.dimensionLabels && params.dimensionLabels.length > 0) {
      typeMetadata.dimension_labels = JSON.stringify(params.dimensionLabels);
    }
    if (params.creatorWalletId) {
      typeMetadata.creator_wallet_id = params.creatorWalletId;
    }
    if (params.drainBps !== undefined) {
      typeMetadata.drain_bps = String(params.drainBps);
    }

    const baseState: VectorStateV1 = {
      schema: STATE_SCHEMA_V1,
      vectorId: params.vectorId,
      ownerPubkey: params.ownerPubkey,
      spaceId: params.spaceId,
      vectorType: "Origin",
      status: "Active",
      components: [...params.components],
      typeMetadata,
      certification: {
        certified: false,
        authRatio: 0,
        threshold: DEFAULT_AUTH_RATIO_THRESHOLD,
        lastCheckedAtMs: now,
        reason: null,
      },
      projection: null,
      origin: {
        seed: params.seed,
        nonce: params.nonce,
        difficulty: params.difficulty,
        proofHash,
      },
      version: 1,
      createdAtMs: now,
      updatedAtMs: now,
    };

    const ownershipVerified = Boolean(params.signature || (params.signerWalletId && this.keystore.hasKey(params.signerWalletId)) || isValidHex(params.ownerPubkey, 32));
    baseState.certification = buildCertificationState(baseState, ownershipVerified, true);

    const recordBody: Omit<VectorRecordV1, "proof"> = {
      schema: "v.kernelx/VectorRecordV1",
      recordId: makeRecordId("origin", baseState.vectorId, `difficulty=${params.difficulty};version=${baseState.version}`),
      vectorId: baseState.vectorId,
      before: null,
      after: baseState,
      operation: "OriginCreate",
      parameters: { difficulty: params.difficulty, dimension_labels: params.dimensionLabels ?? [] },
      certification: baseState.certification,
      timestampMs: now,
    };
    const record: VectorRecordV1 = { ...recordBody, proof: buildRecordProof(recordBody) };

    const logicalClock = this.nextLogicalClock();
    const event = this.buildTransitionEvent({
      before: null,
      after: baseState,
      operation: { type: "OriginCreate" },
      logicalClock,
      timestamp: now,
      parentHashes: [],
      actorPublicKey: params.ownerPubkey,
      signature: params.signature ?? "",
    });
    if (!event.signature && params.signerWalletId && this.keystore.hasKey(params.signerWalletId)) {
      const payload = Buffer.from(event.payload_hash, "utf8");
      event.signature = this.keystore.signWithWallet(params.signerWalletId, payload);
    }

    validateEventIntegrity(event);
    this.store.inTransaction(() => {
      this.store.putVector(baseState);
      this.store.putRecord(record);
      this.store.appendEvent(event);
      this.recordLocalValidatorAttestation(event.event_hash, this.computeLightStateRootHash());
    });
    return baseState;
  }

  createSignedOriginVector(request: {
    request_id: string;
    vector_id: string;
    space_id: string;
    components: number[];
    dimension_labels?: string[];
    seed: string;
    nonce: number;
    difficulty: number;
    creator_wallet_id?: string;
    drain_bps?: number;
    actor_public_key: string;
    signature: string;
  }): VectorStateV1 {
    if (!request.request_id.trim()) throw new Error("request_id is required");
    if (!this.store.getRegion(request.space_id)) {
      throw new Error(`region/space not found: ${request.space_id}`);
    }
    const params = {
      components: request.components,
      difficulty: request.difficulty,
      nonce: request.nonce,
      seed: request.seed,
      space_id: request.space_id,
      vector_id: request.vector_id,
    };
    const signingBytes = canonicalVectorOpSigningBytes(
      VECTOR_ORIGIN_OP,
      request.request_id,
      request.actor_public_key,
      params,
    );
    if (!verifyEd25519(request.actor_public_key, signingBytes, request.signature)) {
      throw new Error("vector origin create signature verification failed");
    }
    if (this.store.hasSeenRequest(request.request_id)) {
      throw new Error(`duplicate request_id: ${request.request_id}`);
    }
    const creatorWalletId =
      request.creator_wallet_id ?? this.store.getWallet(request.actor_public_key)?.wallet_id ?? undefined;

    const state = this.originCreate({
      vectorId: request.vector_id,
      ownerPubkey: request.actor_public_key,
      spaceId: request.space_id,
      components: request.components,
      seed: request.seed,
      nonce: request.nonce,
      difficulty: request.difficulty,
      dimensionLabels: request.dimension_labels,
      creatorWalletId,
      drainBps: request.drain_bps ?? DEFAULT_TRANSFER_DRAIN_BPS,
      signature: request.signature,
    });
    this.store.inTransaction(() => {
      this.store.markRequestSeen(request.request_id, VECTOR_ORIGIN_OP, Date.now());
    });
    return state;
  }

  transportMultidimensionalVector(request: {
    request_id: string;
    from_reserve_id: string;
    to_vector_id: string;
    amount: number[];
    actor_public_key: string;
    signature: string;
  }): { reserve: VectorStateV1; recipient: VectorStateV1; event: CanonicalVectorEvent } {
    if (!request.request_id.trim()) throw new Error("request_id is required");
    const reserve = this.store.getVector(request.from_reserve_id);
    const recipient = this.store.getVector(request.to_vector_id);
    if (!reserve || !recipient) throw new Error("reserve or recipient vector not found");
    if (reserve.spaceId !== recipient.spaceId) {
      throw new Error("cross-region vector transport denied");
    }
    if (reserve.components.length !== recipient.components.length || reserve.components.length !== request.amount.length) {
      throw new Error("dimension mismatch");
    }
    if (request.amount.every((a) => a === 0) || request.amount.some((a) => !Number.isInteger(a) || a < 0)) {
      throw new Error("transport amount must contain positive integer components");
    }
    const signingBytes = canonicalVectorOpSigningBytes(
      VECTOR_TRANSPORT_OP,
      request.request_id,
      request.actor_public_key,
      {
        amount: request.amount,
        from_reserve_id: request.from_reserve_id,
        to_vector_id: request.to_vector_id,
      },
    );
    if (!verifyEd25519(request.actor_public_key, signingBytes, request.signature)) {
      throw new Error("vector transport signature verification failed");
    }
    if (request.actor_public_key !== reserve.ownerPubkey) {
      throw new Error("unauthorized vector transport: actor must own reserve vector");
    }
    if (this.store.hasSeenRequest(request.request_id)) {
      throw new Error(`duplicate request_id: ${request.request_id}`);
    }
    if (request.amount.some((a, i) => a > reserve.components[i])) {
      throw new Error("insufficient reserve vector components");
    }

    const now = Date.now();
    const afterReserve: VectorStateV1 = {
      ...reserve,
      components: reserve.components.map((c, i) => c - request.amount[i]),
      version: reserve.version + 1,
      updatedAtMs: now,
    };
    afterReserve.certification = buildCertificationState(afterReserve, true, true);

    const afterRecipient: VectorStateV1 = {
      ...recipient,
      components: recipient.components.map((c, i) => c + request.amount[i]),
      vectorType: "Standard",
      version: recipient.version + 1,
      updatedAtMs: now,
    };
    afterRecipient.certification = buildCertificationState(afterRecipient, true, true);

    const recOutBody: Omit<VectorRecordV1, "proof"> = {
      schema: "v.kernelx/VectorRecordV1",
      recordId: makeRecordId("vec-transport-out", reserve.vectorId, request.request_id),
      vectorId: reserve.vectorId,
      before: reserve,
      after: afterReserve,
      operation: "Custom",
      parameters: {
        custom_operation: VECTOR_TRANSPORT_OP,
        request_id: request.request_id,
        direction: "out",
        amount: request.amount,
        to_vector_id: recipient.vectorId,
      },
      certification: afterReserve.certification,
      timestampMs: now,
    };
    const recInBody: Omit<VectorRecordV1, "proof"> = {
      schema: "v.kernelx/VectorRecordV1",
      recordId: makeRecordId("vec-transport-in", recipient.vectorId, request.request_id),
      vectorId: recipient.vectorId,
      before: recipient,
      after: afterRecipient,
      operation: "Custom",
      parameters: {
        custom_operation: VECTOR_TRANSPORT_OP,
        request_id: request.request_id,
        direction: "in",
        amount: request.amount,
        from_reserve_id: reserve.vectorId,
      },
      certification: afterRecipient.certification,
      timestampMs: now,
    };

    const baseClock = this.nextLogicalClock();
    const evOut = this.buildTransitionEvent({
      before: reserve,
      after: afterReserve,
      operation: { type: "Other", value: VECTOR_TRANSPORT_OP },
      logicalClock: baseClock,
      timestamp: now,
      parentHashes: this.latestParentHashForEntity(reserve.vectorId),
      actorPublicKey: request.actor_public_key,
      signature: request.signature,
    });
    const evIn = this.buildTransitionEvent({
      before: recipient,
      after: afterRecipient,
      operation: { type: "Other", value: VECTOR_TRANSPORT_OP },
      logicalClock: baseClock + 1,
      timestamp: now,
      parentHashes: this.latestParentHashForEntity(recipient.vectorId),
      actorPublicKey: request.actor_public_key,
      signature: request.signature,
    });
    validateEventIntegrity(evOut);
    validateEventIntegrity(evIn);

    this.store.inTransaction(() => {
      if (this.store.hasSeenRequest(request.request_id)) {
        throw new Error(`duplicate request_id: ${request.request_id}`);
      }
      this.store.markRequestSeen(request.request_id, VECTOR_TRANSPORT_OP, now);
      this.store.putVector(afterReserve);
      this.store.putVector(afterRecipient);
      this.store.putRecord({ ...recOutBody, proof: buildRecordProof(recOutBody) });
      this.store.putRecord({ ...recInBody, proof: buildRecordProof(recInBody) });
      this.store.appendEvent(evOut);
      this.store.appendEvent(evIn);
      this.recordLocalValidatorAttestation(evIn.event_hash, this.computeLightStateRootHash());
    });

    return { reserve: afterReserve, recipient: afterRecipient, event: evIn };
  }

  transferMultidimensionalVector(request: {
    request_id: string;
    from_vector_id: string;
    to_vector_id: string;
    amount: number[];
    drain_bps?: number;
    actor_public_key: string;
    signature: string;
  }): {
    from: VectorStateV1;
    to: VectorStateV1;
    effective_bps: number;
    fees: number[];
    net_received: number[];
    rewards: DrainRewardRecord[];
  } {
    if (!request.request_id.trim()) throw new Error("request_id is required");
    if (request.from_vector_id === request.to_vector_id) {
      throw new Error("cannot transfer to the same vector");
    }
    const from = this.store.getVector(request.from_vector_id);
    const to = this.store.getVector(request.to_vector_id);
    if (!from || !to) throw new Error("sender or receiver vector not found");
    if (from.spaceId !== to.spaceId) {
      throw new Error("cross-region vector transfer denied");
    }
    if (from.components.length !== to.components.length || from.components.length !== request.amount.length) {
      throw new Error("dimension mismatch");
    }
    if (request.amount.every((a) => a === 0) || request.amount.some((a) => !Number.isInteger(a) || a < 0)) {
      throw new Error("transfer amount must contain positive integer components");
    }
    const signingBytes = canonicalVectorOpSigningBytes(
      VECTOR_TRANSFER_OP,
      request.request_id,
      request.actor_public_key,
      {
        amount: request.amount,
        from_vector_id: request.from_vector_id,
        to_vector_id: request.to_vector_id,
      },
    );
    if (!verifyEd25519(request.actor_public_key, signingBytes, request.signature)) {
      throw new Error("vector transfer signature verification failed");
    }
    if (request.actor_public_key !== from.ownerPubkey) {
      throw new Error("unauthorized vector transfer: actor must own source vector");
    }
    if (this.store.hasSeenRequest(request.request_id)) {
      throw new Error(`duplicate request_id: ${request.request_id}`);
    }
    if (request.amount.some((a, i) => a > from.components[i])) {
      throw new Error("insufficient multidimensional vector balance");
    }

    const baseDrainBps = Number(from.typeMetadata.drain_bps ?? request.drain_bps ?? DEFAULT_TRANSFER_DRAIN_BPS);
    const dist = computeMultidimensionalDrainDistribution(
      request.amount,
      baseDrainBps,
      from.certification.authRatio,
      from.certification.threshold,
    );

    const now = Date.now();
    const afterFrom: VectorStateV1 = {
      ...from,
      components: from.components.map((c, i) => c - request.amount[i]),
      vectorType: "Standard",
      version: from.version + 1,
      updatedAtMs: now,
    };
    afterFrom.certification = buildCertificationState(afterFrom, true, true);

    const afterTo: VectorStateV1 = {
      ...to,
      components: to.components.map((c, i) => c + dist.netReceived[i]),
      vectorType: "Standard",
      version: to.version + 1,
      updatedAtMs: now,
    };
    afterTo.certification = buildCertificationState(afterTo, true, true);

    // Resolve the 4 beneficiary wallets for reward ledger attribution
    const region = this.store.getRegion(from.spaceId);
    const senderWallet = this.store.getWallet(from.ownerPubkey);
    const regionCreatorWallet =
      (region ? this.store.getWallet(region.creator_public_key) : null) ??
      this.store.getWallet(this.nodeId)!;
    const walletCreatorWallet =
      (senderWallet?.creator_wallet_id ? this.store.getWallet(senderWallet.creator_wallet_id) : null) ??
      senderWallet ??
      this.store.getWallet(this.nodeId)!;
    const vectorCreatorWallet =
      (from.typeMetadata.creator_wallet_id ? this.store.getWallet(from.typeMetadata.creator_wallet_id) : null) ??
      senderWallet ??
      this.store.getWallet(this.nodeId)!;
    const networkPoolWallet = this.store.getWallet(this.nodeId)!;

    const roles: Array<{ role: BeneficiaryRole; wallet: PublicWalletRecord; dims: number[] }> = [
      { role: "region_creator", wallet: regionCreatorWallet, dims: dist.regionRewards },
      { role: "wallet_creator", wallet: walletCreatorWallet, dims: dist.walletRewards },
      { role: "token_creator", wallet: vectorCreatorWallet, dims: dist.tokenRewards },
      { role: "network_pool", wallet: networkPoolWallet, dims: dist.networkRewards },
    ];

    const rewards: DrainRewardRecord[] = roles.map((r) => ({
      reward_id: makeRecordId("vec-reward", `${from.vectorId}:${r.role}`, request.request_id),
      tx_request_id: request.request_id,
      token_id: null,
      vector_id: from.vectorId,
      beneficiary_role: r.role,
      wallet_id: r.wallet.wallet_id,
      amount: String(r.dims.reduce((a, b) => a + b, 0)),
      dimension_amounts: r.dims.map(String),
      timestamp_ms: now,
    }));

    const recFromBody: Omit<VectorRecordV1, "proof"> = {
      schema: "v.kernelx/VectorRecordV1",
      recordId: makeRecordId("vec-transfer-out", from.vectorId, request.request_id),
      vectorId: from.vectorId,
      before: from,
      after: afterFrom,
      operation: "Transfer",
      parameters: {
        direction: "out",
        request_id: request.request_id,
        amount: request.amount,
        fees: dist.totalFees,
        effective_bps: dist.effectiveBps,
      },
      certification: afterFrom.certification,
      timestampMs: now,
    };
    const recToBody: Omit<VectorRecordV1, "proof"> = {
      schema: "v.kernelx/VectorRecordV1",
      recordId: makeRecordId("vec-transfer-in", to.vectorId, request.request_id),
      vectorId: to.vectorId,
      before: to,
      after: afterTo,
      operation: "Transfer",
      parameters: {
        direction: "in",
        request_id: request.request_id,
        amount: dist.netReceived,
        fees: dist.totalFees,
        effective_bps: dist.effectiveBps,
      },
      certification: afterTo.certification,
      timestampMs: now,
    };

    const baseClock = this.nextLogicalClock();
    const evFrom = this.buildTransitionEvent({
      before: from,
      after: afterFrom,
      operation: { type: "Transfer" },
      logicalClock: baseClock,
      timestamp: now,
      parentHashes: this.latestParentHashForEntity(from.vectorId),
      actorPublicKey: request.actor_public_key,
      signature: request.signature,
    });
    const evTo = this.buildTransitionEvent({
      before: to,
      after: afterTo,
      operation: { type: "Transfer" },
      logicalClock: baseClock + 1,
      timestamp: now,
      parentHashes: this.latestParentHashForEntity(to.vectorId),
      actorPublicKey: request.actor_public_key,
      signature: request.signature,
    });
    validateEventIntegrity(evFrom);
    validateEventIntegrity(evTo);

    this.store.inTransaction(() => {
      if (this.store.hasSeenRequest(request.request_id)) {
        throw new Error(`duplicate request_id: ${request.request_id}`);
      }
      this.store.markRequestSeen(request.request_id, VECTOR_TRANSFER_OP, now);
      this.store.putVector(afterFrom);
      this.store.putVector(afterTo);
      for (const reward of rewards) {
        this.store.putDrainReward(reward);
      }
      this.store.putRecord({ ...recFromBody, proof: buildRecordProof(recFromBody) });
      this.store.putRecord({ ...recToBody, proof: buildRecordProof(recToBody) });
      this.store.appendEvent(evFrom);
      this.store.appendEvent(evTo);
      this.recordLocalValidatorAttestation(evTo.event_hash, this.computeLightStateRootHash());
    });

    return {
      from: afterFrom,
      to: afterTo,
      effective_bps: dist.effectiveBps,
      fees: dist.totalFees,
      net_received: dist.netReceived,
      rewards,
    };
  }

  projectMultidimensionalVector(request: {
    request_id: string;
    vector_id: string;
    projected_components: number[];
    escrow_id: string;
    actor_public_key: string;
    signature: string;
  }): VectorStateV1 {
    if (!request.request_id.trim()) throw new Error("request_id is required");
    const state = this.store.getVector(request.vector_id);
    if (!state) throw new Error(`vector not found: ${request.vector_id}`);
    if (state.status === "Projected") throw new Error("vector already has an active escrow projection");
    if (request.projected_components.length !== state.components.length) {
      throw new Error("dimension mismatch");
    }
    if (request.projected_components.some((p, i) => !Number.isInteger(p) || p < 0 || p > state.components[i])) {
      throw new Error("insufficient multidimensional balance for projection");
    }
    const signingBytes = canonicalVectorOpSigningBytes(
      VECTOR_PROJECT_OP,
      request.request_id,
      request.actor_public_key,
      {
        escrow_id: request.escrow_id,
        projected_components: request.projected_components,
        vector_id: request.vector_id,
      },
    );
    if (!verifyEd25519(request.actor_public_key, signingBytes, request.signature)) {
      throw new Error("vector project signature verification failed");
    }
    if (request.actor_public_key !== state.ownerPubkey) {
      throw new Error("unauthorized project: actor_public_key does not match vector owner");
    }
    if (this.store.hasSeenRequest(request.request_id)) {
      throw new Error(`duplicate request_id: ${request.request_id}`);
    }

    const now = Date.now();
    const after: VectorStateV1 = {
      ...state,
      components: state.components.map((c, i) => c - request.projected_components[i]),
      vectorType: "Projected",
      status: "Projected",
      projection: {
        escrowId: request.escrow_id.trim() || `escrow_${request.request_id}`,
        projectedComponents: [...request.projected_components],
        settledComponents: [],
        startedAtMs: now,
        settlementAtMs: null,
        outcomeTag: null,
      },
      version: state.version + 1,
      updatedAtMs: now,
    };
    after.certification = buildCertificationState(after, true, true);

    const recordBody: Omit<VectorRecordV1, "proof"> = {
      schema: "v.kernelx/VectorRecordV1",
      recordId: makeRecordId("vec-project", state.vectorId, request.request_id),
      vectorId: state.vectorId,
      before: state,
      after,
      operation: "Project",
      parameters: {
        request_id: request.request_id,
        escrow_id: after.projection?.escrowId,
        projected_components: request.projected_components,
      },
      certification: after.certification,
      timestampMs: now,
    };

    const event = this.buildTransitionEvent({
      before: state,
      after,
      operation: { type: "Project" },
      logicalClock: this.nextLogicalClock(),
      timestamp: now,
      parentHashes: this.latestParentHashForEntity(state.vectorId),
      actorPublicKey: request.actor_public_key,
      signature: request.signature,
    });
    validateEventIntegrity(event);

    this.store.inTransaction(() => {
      if (this.store.hasSeenRequest(request.request_id)) {
        throw new Error(`duplicate request_id: ${request.request_id}`);
      }
      this.store.markRequestSeen(request.request_id, VECTOR_PROJECT_OP, now);
      this.store.putVector(after);
      this.store.putRecord({ ...recordBody, proof: buildRecordProof(recordBody) });
      this.store.appendEvent(event);
      this.recordLocalValidatorAttestation(event.event_hash, this.computeLightStateRootHash());
    });

    return after;
  }

  reconstructMultidimensionalVector(request: {
    request_id: string;
    vector_id: string;
    gains: number[];
    losses: number[];
    outcome_tag: string;
    actor_public_key: string;
    signature: string;
  }): VectorStateV1 {
    if (!request.request_id.trim()) throw new Error("request_id is required");
    const state = this.store.getVector(request.vector_id);
    if (!state) throw new Error(`vector not found: ${request.vector_id}`);
    if (!state.projection || state.status !== "Projected") {
      throw new Error("vector has no active escrow projection to reconstruct");
    }
    const principal = state.projection.projectedComponents;
    if (request.gains.length !== principal.length || request.losses.length !== principal.length) {
      throw new Error("dimension mismatch between gains, losses, and projected escrow");
    }
    const signingBytes = canonicalVectorOpSigningBytes(
      VECTOR_RECONSTRUCT_OP,
      request.request_id,
      request.actor_public_key,
      {
        gains: request.gains,
        losses: request.losses,
        outcome_tag: request.outcome_tag,
        vector_id: request.vector_id,
      },
    );
    if (!verifyEd25519(request.actor_public_key, signingBytes, request.signature)) {
      throw new Error("vector reconstruct signature verification failed");
    }
    if (request.actor_public_key !== state.ownerPubkey) {
      throw new Error("unauthorized reconstruct: actor_public_key does not match vector owner");
    }
    if (this.store.hasSeenRequest(request.request_id)) {
      throw new Error(`duplicate request_id: ${request.request_id}`);
    }

    const settled = principal.map((p, i) => {
      const g = Number(request.gains[i] ?? 0);
      const l = Number(request.losses[i] ?? 0);
      if (!Number.isInteger(g) || g < 0 || !Number.isInteger(l) || l < 0) {
        throw new Error("gains and losses must be non-negative integers");
      }
      const next = p + g - l;
      if (next < 0) {
        throw new Error(`settlement loss exceeds projected principal on dimension ${i}`);
      }
      return next;
    });

    const now = Date.now();
    const after: VectorStateV1 = {
      ...state,
      components: state.components.map((c, i) => c + settled[i]),
      vectorType: "Settlement",
      status: "Settled",
      projection: {
        ...state.projection,
        settledComponents: settled,
        settlementAtMs: now,
        outcomeTag: request.outcome_tag.trim() || "settled",
      },
      version: state.version + 1,
      updatedAtMs: now,
    };
    after.certification = buildCertificationState(after, true, true);

    const recordBody: Omit<VectorRecordV1, "proof"> = {
      schema: "v.kernelx/VectorRecordV1",
      recordId: makeRecordId("vec-reconstruct", state.vectorId, request.request_id),
      vectorId: state.vectorId,
      before: state,
      after,
      operation: "Reconstruct",
      parameters: {
        request_id: request.request_id,
        outcome_tag: after.projection?.outcomeTag,
        gains: request.gains,
        losses: request.losses,
        settled_components: settled,
      },
      certification: after.certification,
      timestampMs: now,
    };

    const event = this.buildTransitionEvent({
      before: state,
      after,
      operation: { type: "Reconstruct" },
      logicalClock: this.nextLogicalClock(),
      timestamp: now,
      parentHashes: this.latestParentHashForEntity(state.vectorId),
      actorPublicKey: request.actor_public_key,
      signature: request.signature,
    });
    validateEventIntegrity(event);

    this.store.inTransaction(() => {
      if (this.store.hasSeenRequest(request.request_id)) {
        throw new Error(`duplicate request_id: ${request.request_id}`);
      }
      this.store.markRequestSeen(request.request_id, VECTOR_RECONSTRUCT_OP, now);
      this.store.putVector(after);
      this.store.putRecord({ ...recordBody, proof: buildRecordProof(recordBody) });
      this.store.appendEvent(event);
      this.recordLocalValidatorAttestation(event.event_hash, this.computeLightStateRootHash());
    });

    return after;
  }

  certifyMultidimensionalVector(request: {
    request_id: string;
    vector_id: string;
    actor_public_key: string;
    signature: string;
  }): VectorStateV1 {
    if (!request.request_id.trim()) throw new Error("request_id is required");
    const state = this.store.getVector(request.vector_id);
    if (!state) throw new Error(`vector not found: ${request.vector_id}`);
    const signingBytes = canonicalVectorOpSigningBytes(
      VECTOR_CERTIFY_OP,
      request.request_id,
      request.actor_public_key,
      { vector_id: request.vector_id },
    );
    const sigOk = verifyEd25519(request.actor_public_key, signingBytes, request.signature);
    if (!sigOk) {
      throw new Error("vector certify signature verification failed");
    }
    if (this.store.hasSeenRequest(request.request_id)) {
      throw new Error(`duplicate request_id: ${request.request_id}`);
    }

    const now = Date.now();
    const ownershipVerified = request.actor_public_key === state.ownerPubkey;
    const structureVerified = state.components.length > 0 && Boolean(this.store.getRegion(state.spaceId));
    const after: VectorStateV1 = {
      ...state,
      certification: buildCertificationState(state, ownershipVerified, structureVerified),
      version: state.version + 1,
      updatedAtMs: now,
    };

    const recordBody: Omit<VectorRecordV1, "proof"> = {
      schema: "v.kernelx/VectorRecordV1",
      recordId: makeRecordId("vec-certify", state.vectorId, request.request_id),
      vectorId: state.vectorId,
      before: state,
      after,
      operation: "Certify",
      parameters: {
        request_id: request.request_id,
        auth_ratio: after.certification.authRatio,
        certified: after.certification.certified,
      },
      certification: after.certification,
      timestampMs: now,
    };

    const event = this.buildTransitionEvent({
      before: state,
      after,
      operation: { type: "Certify" },
      logicalClock: this.nextLogicalClock(),
      timestamp: now,
      parentHashes: this.latestParentHashForEntity(state.vectorId),
      actorPublicKey: request.actor_public_key,
      signature: request.signature,
    });
    validateEventIntegrity(event);

    this.store.inTransaction(() => {
      if (this.store.hasSeenRequest(request.request_id)) {
        throw new Error(`duplicate request_id: ${request.request_id}`);
      }
      this.store.markRequestSeen(request.request_id, VECTOR_CERTIFY_OP, now);
      this.store.putVector(after);
      this.store.putRecord({ ...recordBody, proof: buildRecordProof(recordBody) });
      this.store.appendEvent(event);
      this.recordLocalValidatorAttestation(event.event_hash, this.computeLightStateRootHash());
    });

    return after;
  }

  drainMultidimensionalVector(request: {
    request_id: string;
    vector_id: string;
    basis_points: number;
    actor_public_key: string;
    signature: string;
  }): { state: VectorStateV1; effective_bps: number; drained: number[] } {
    if (!request.request_id.trim()) throw new Error("request_id is required");
    const state = this.store.getVector(request.vector_id);
    if (!state) throw new Error(`vector not found: ${request.vector_id}`);
    if (!Number.isInteger(request.basis_points) || request.basis_points <= 0 || request.basis_points > 10_000) {
      throw new Error("basis_points must be between 1 and 10000");
    }
    const signingBytes = canonicalVectorOpSigningBytes(
      VECTOR_DRAIN_OP,
      request.request_id,
      request.actor_public_key,
      { basis_points: request.basis_points, vector_id: request.vector_id },
    );
    if (!verifyEd25519(request.actor_public_key, signingBytes, request.signature)) {
      throw new Error("vector drain signature verification failed");
    }
    if (request.actor_public_key !== state.ownerPubkey) {
      throw new Error("unauthorized drain: actor_public_key does not match vector owner");
    }
    if (this.store.hasSeenRequest(request.request_id)) {
      throw new Error(`duplicate request_id: ${request.request_id}`);
    }

    const dist = computeMultidimensionalDrainDistribution(
      state.components,
      request.basis_points,
      state.certification.authRatio,
      state.certification.threshold,
    );
    const now = Date.now();
    const after: VectorStateV1 = {
      ...state,
      components: dist.netReceived,
      version: state.version + 1,
      updatedAtMs: now,
    };
    after.certification = buildCertificationState(after, true, true);

    const recordBody: Omit<VectorRecordV1, "proof"> = {
      schema: "v.kernelx/VectorRecordV1",
      recordId: makeRecordId("vec-drain", state.vectorId, request.request_id),
      vectorId: state.vectorId,
      before: state,
      after,
      operation: "Drain",
      parameters: {
        request_id: request.request_id,
        basis_points: request.basis_points,
        effective_bps: dist.effectiveBps,
        drained: dist.totalFees,
      },
      certification: after.certification,
      timestampMs: now,
    };

    const event = this.buildTransitionEvent({
      before: state,
      after,
      operation: { type: "Drain" },
      logicalClock: this.nextLogicalClock(),
      timestamp: now,
      parentHashes: this.latestParentHashForEntity(state.vectorId),
      actorPublicKey: request.actor_public_key,
      signature: request.signature,
    });
    validateEventIntegrity(event);

    const networkReward: DrainRewardRecord = {
      reward_id: makeRecordId("vec-drain-reward", state.vectorId, request.request_id),
      tx_request_id: request.request_id,
      token_id: null,
      vector_id: state.vectorId,
      beneficiary_role: "network_pool",
      wallet_id: this.nodeId,
      amount: String(dist.totalFees.reduce((a, b) => a + b, 0)),
      dimension_amounts: dist.totalFees.map(String),
      timestamp_ms: now,
    };

    this.store.inTransaction(() => {
      if (this.store.hasSeenRequest(request.request_id)) {
        throw new Error(`duplicate request_id: ${request.request_id}`);
      }
      this.store.markRequestSeen(request.request_id, VECTOR_DRAIN_OP, now);
      this.store.putVector(after);
      this.store.putDrainReward(networkReward);
      this.store.putRecord({ ...recordBody, proof: buildRecordProof(recordBody) });
      this.store.appendEvent(event);
      this.recordLocalValidatorAttestation(event.event_hash, this.computeLightStateRootHash());
    });

    return { state: after, effective_bps: dist.effectiveBps, drained: dist.totalFees };
  }

  // -------------------------
  // Token Issuance, Transport & Drain Transfer Ledger
  // -------------------------
  createTokenWithWallet(params: {
    authorityWalletId: string;
    requestId: string;
    name: string;
    symbol: string;
    regionId: string;
    decimals: number;
    maxSupply: string;
    supplyPolicy: string;
    tokenType?: string;
    drainBps?: number;
  }): { token: TokenDefinition; event: CanonicalVectorEvent; record: VectorRecordV1 } {
    const wallet = this.store.getWallet(params.authorityWalletId);
    if (!wallet) {
      throw new Error(`authority wallet not found: ${params.authorityWalletId}`);
    }
    const reqParams: Record<string, unknown> = {
      decimals: params.decimals,
      max_supply: params.maxSupply,
      name: params.name,
      region_id: params.regionId,
      supply_policy: params.supplyPolicy,
      symbol: params.symbol.trim().toUpperCase(),
      token_type: params.tokenType ?? "Native Vector Network asset",
    };
    if (params.drainBps !== undefined) {
      reqParams.drain_bps = params.drainBps;
    }
    const signingBytes = canonicalTokenRequestSigningBytes(
      TOKEN_CREATE_OP,
      params.requestId,
      wallet.public_key_hex,
      reqParams,
    );
    const signature = this.keystore.signWithWallet(wallet.wallet_id, signingBytes);
    return this.createToken({
      request_id: params.requestId,
      name: params.name,
      symbol: params.symbol,
      region_id: params.regionId,
      decimals: params.decimals,
      max_supply: params.maxSupply,
      supply_policy: params.supplyPolicy,
      token_type: params.tokenType,
      drain_bps: params.drainBps,
      authority_pubkey: wallet.public_key_hex,
      signature,
    });
  }

  createToken(
    request: TokenCreateRequest,
  ): { token: TokenDefinition; event: CanonicalVectorEvent; record: VectorRecordV1 } {
    if (!request.request_id.trim()) throw new Error("request_id is required");
    if (!request.name.trim()) throw new Error("token name is required");
    const symbol = request.symbol.trim().toUpperCase();
    if (!symbol || !/^[A-Z0-9_-]{1,16}$/.test(symbol)) {
      throw new Error("token symbol must be 1-16 uppercase alphanumeric characters");
    }
    if (!Number.isInteger(request.decimals) || request.decimals < 0 || request.decimals > 18) {
      throw new Error("decimals must be an integer between 0 and 18");
    }
    const maxSupply = parseU128(request.max_supply, "max_supply");
    if (maxSupply <= 0n) {
      throw new Error("max_supply must be greater than zero");
    }
    const drainBps = request.drain_bps ?? DEFAULT_TRANSFER_DRAIN_BPS;
    if (!Number.isInteger(drainBps) || drainBps < 0 || drainBps > 10_000) {
      throw new Error("drain_bps must be between 0 and 10000");
    }
    const region = this.store.getRegion(request.region_id);
    if (!region) {
      throw new Error(`region not found: ${request.region_id}`);
    }

    const reqParams: Record<string, unknown> = {
      decimals: request.decimals,
      max_supply: request.max_supply,
      name: request.name,
      region_id: request.region_id,
      supply_policy: request.supply_policy,
      symbol,
      token_type: request.token_type ?? "Native Vector Network asset",
    };
    if (request.drain_bps !== undefined) {
      reqParams.drain_bps = request.drain_bps;
    }
    const signingBytes = canonicalTokenRequestSigningBytes(
      TOKEN_CREATE_OP,
      request.request_id,
      request.authority_pubkey,
      reqParams,
    );
    if (!verifyEd25519(request.authority_pubkey, signingBytes, request.signature)) {
      throw new Error("token create signature verification failed");
    }

    if (this.store.hasSeenRequest(request.request_id)) {
      throw new Error(`duplicate request_id: ${request.request_id}`);
    }

    const tokenId = deriveTokenId(request.region_id, symbol, request.authority_pubkey);
    if (this.store.getToken(tokenId) || this.store.getToken(symbol)) {
      throw new Error(`token already registered: ${symbol} (${tokenId})`);
    }

    const now = Date.now();
    const token: TokenDefinition = {
      token_id: tokenId,
      name: request.name.trim(),
      symbol,
      region_id: region.region_id,
      decimals: request.decimals,
      max_supply: maxSupply.toString(),
      total_supply: "0",
      minted_supply: "0",
      transported_supply: "0",
      burned_supply: "0",
      drained_fees_collected: "0",
      drain_bps: drainBps,
      authority_pubkey: request.authority_pubkey,
      supply_policy: request.supply_policy,
      token_type: request.token_type ?? "Native Vector Network asset",
      created_at_ms: now,
      updated_at_ms: now,
      version: 1,
    };

    const vectorState: VectorStateV1 = {
      schema: STATE_SCHEMA_V1,
      vectorId: token.token_id,
      ownerPubkey: token.authority_pubkey,
      spaceId: region.region_id,
      vectorType: "Origin",
      status: "Active",
      components: [0],
      typeMetadata: {
        kind: "token_registry",
        name: token.name,
        symbol: token.symbol,
        decimals: String(token.decimals),
        max_supply: token.max_supply,
        total_supply: token.total_supply,
        minted_supply: token.minted_supply,
        transported_supply: "0",
        burned_supply: token.burned_supply,
        drained_fees_collected: "0",
        drain_bps: String(drainBps),
        supply_policy: token.supply_policy,
        token_type: token.token_type,
        authority_pubkey: token.authority_pubkey,
      },
      certification: {
        certified: true,
        authRatio: 1000,
        threshold: DEFAULT_AUTH_RATIO_THRESHOLD,
        lastCheckedAtMs: now,
        reason: null,
      },
      projection: null,
      origin: null,
      version: 1,
      createdAtMs: now,
      updatedAtMs: now,
    };

    const recordBody: Omit<VectorRecordV1, "proof"> = {
      schema: "v.kernelx/VectorRecordV1",
      recordId: makeRecordId("token-create", token.token_id, request.request_id),
      vectorId: token.token_id,
      before: null,
      after: vectorState,
      operation: "Custom",
      parameters: {
        custom_operation: TOKEN_CREATE_OP,
        request_id: request.request_id,
        token,
      },
      certification: vectorState.certification,
      timestampMs: now,
    };
    const record: VectorRecordV1 = { ...recordBody, proof: buildRecordProof(recordBody) };

    const event = this.buildTransitionEvent({
      before: null,
      after: vectorState,
      operation: { type: "Other", value: TOKEN_CREATE_OP },
      logicalClock: this.nextLogicalClock(),
      timestamp: now,
      parentHashes: [],
      actorPublicKey: request.authority_pubkey,
      signature: request.signature,
    });
    validateEventIntegrity(event);

    this.store.inTransaction(() => {
      if (this.store.hasSeenRequest(request.request_id)) {
        throw new Error(`duplicate request_id: ${request.request_id}`);
      }
      this.store.markRequestSeen(request.request_id, TOKEN_CREATE_OP, now);
      this.store.putToken(token);
      this.store.putVector(vectorState);
      this.store.putRecord(record);
      this.store.appendEvent(event);
      this.recordLocalValidatorAttestation(event.event_hash, this.computeLightStateRootHash());
    });

    return { token, event, record };
  }

  transportTokenWithWallet(params: {
    authorityWalletId: string;
    requestId: string;
    tokenId: string;
    toWalletId: string;
    amount: string;
  }): {
    token: TokenDefinition;
    balance: TokenBalance;
    event: CanonicalVectorEvent;
    record: VectorRecordV1;
  } {
    const wallet = this.store.getWallet(params.authorityWalletId);
    if (!wallet) throw new Error(`authority wallet not found: ${params.authorityWalletId}`);
    const reqParams = {
      amount: params.amount,
      to_wallet_id: params.toWalletId,
      token_id: params.tokenId,
    };
    const signingBytes = canonicalTokenRequestSigningBytes(
      TOKEN_TRANSPORT_OP,
      params.requestId,
      wallet.public_key_hex,
      reqParams,
    );
    const signature = this.keystore.signWithWallet(wallet.wallet_id, signingBytes);
    return this.transportToken({
      request_id: params.requestId,
      token_id: params.tokenId,
      to_wallet_id: params.toWalletId,
      amount: params.amount,
      actor_public_key: wallet.public_key_hex,
      signature,
    });
  }

  transportToken(request: TokenTransportRequest): {
    token: TokenDefinition;
    balance: TokenBalance;
    event: CanonicalVectorEvent;
    record: VectorRecordV1;
  } {
    if (!request.request_id.trim()) throw new Error("request_id is required");
    const amount = parseU128(request.amount, "transport amount");
    if (amount <= 0n) throw new Error("transport amount must be greater than zero");

    const token = this.store.getToken(request.token_id);
    if (!token) throw new Error(`token not found: ${request.token_id}`);

    const targetWallet = this.store.getWallet(request.to_wallet_id);
    if (!targetWallet) throw new Error(`destination wallet not found: ${request.to_wallet_id}`);

    const reqParams = {
      amount: request.amount,
      to_wallet_id: request.to_wallet_id,
      token_id: request.token_id,
    };
    const signingBytes = canonicalTokenRequestSigningBytes(
      TOKEN_TRANSPORT_OP,
      request.request_id,
      request.actor_public_key,
      reqParams,
    );
    if (!verifyEd25519(request.actor_public_key, signingBytes, request.signature)) {
      throw new Error("transport signature verification failed");
    }

    if (request.actor_public_key !== token.authority_pubkey) {
      throw new Error("unauthorized transport: actor_public_key does not match token authority_pubkey");
    }

    if (this.store.hasSeenRequest(request.request_id)) {
      throw new Error(`duplicate request_id: ${request.request_id}`);
    }

    const currentTotal = parseU128(token.total_supply, "total_supply");
    const currentTransported = parseU128(token.transported_supply ?? token.minted_supply, "transported_supply");
    const maxSupply = parseU128(token.max_supply, "max_supply");

    const nextTotal = checkedAddU128(currentTotal, amount, "total_supply");
    const nextTransported = checkedAddU128(currentTransported, amount, "transported_supply");
    if (nextTotal > maxSupply) {
      throw new Error(`transport exceeds reserve max_supply (${token.max_supply})`);
    }

    const existingBalance = this.store.getTokenBalance(token.token_id, targetWallet.wallet_id);
    const prevBal = existingBalance ? parseU128(existingBalance.balance, "balance") : 0n;
    const nextBal = checkedAddU128(prevBal, amount, "wallet balance");

    const now = Date.now();
    const updatedToken: TokenDefinition = {
      ...token,
      total_supply: nextTotal.toString(),
      minted_supply: nextTransported.toString(),
      transported_supply: nextTransported.toString(),
      updated_at_ms: now,
      version: token.version + 1,
    };
    const updatedBalance: TokenBalance = {
      token_id: token.token_id,
      wallet_id: targetWallet.wallet_id,
      owner_pubkey: targetWallet.public_key_hex,
      balance: nextBal.toString(),
      updated_at_ms: now,
      version: (existingBalance?.version ?? 0) + 1,
    };

    const prevVec = this.store.getVector(token.token_id);
    if (!prevVec) throw new Error(`missing canonical vector for token ${token.token_id}`);

    const nextVec: VectorStateV1 = {
      ...prevVec,
      components: [Number(nextTotal > BigInt(Number.MAX_SAFE_INTEGER) ? 0 : nextTotal)],
      typeMetadata: {
        ...prevVec.typeMetadata,
        total_supply: updatedToken.total_supply,
        minted_supply: updatedToken.minted_supply,
        transported_supply: updatedToken.transported_supply ?? updatedToken.minted_supply,
        burned_supply: updatedToken.burned_supply,
        last_transport_wallet: targetWallet.wallet_id,
        last_transport_amount: amount.toString(),
      },
      version: prevVec.version + 1,
      updatedAtMs: now,
    };

    const recordBody: Omit<VectorRecordV1, "proof"> = {
      schema: "v.kernelx/VectorRecordV1",
      recordId: makeRecordId("token-transport", token.token_id, request.request_id),
      vectorId: token.token_id,
      before: prevVec,
      after: nextVec,
      operation: "Custom",
      parameters: {
        custom_operation: TOKEN_TRANSPORT_OP,
        request_id: request.request_id,
        token_id: token.token_id,
        to_wallet_id: targetWallet.wallet_id,
        amount: amount.toString(),
        signature: request.signature,
        actor_public_key: request.actor_public_key,
      },
      certification: nextVec.certification,
      timestampMs: now,
    };
    const record: VectorRecordV1 = { ...recordBody, proof: buildRecordProof(recordBody) };

    const event = this.buildTransitionEvent({
      before: prevVec,
      after: nextVec,
      operation: { type: "Other", value: TOKEN_TRANSPORT_OP },
      logicalClock: this.nextLogicalClock(),
      timestamp: now,
      parentHashes: this.latestParentHashForEntity(token.token_id),
      actorPublicKey: request.actor_public_key,
      signature: request.signature,
    });
    validateEventIntegrity(event);

    this.store.inTransaction(() => {
      if (this.store.hasSeenRequest(request.request_id)) {
        throw new Error(`duplicate request_id: ${request.request_id}`);
      }
      this.store.markRequestSeen(request.request_id, TOKEN_TRANSPORT_OP, now);
      this.store.putToken(updatedToken);
      this.store.putTokenBalance(updatedBalance);
      this.store.putVector(nextVec);
      this.store.putRecord(record);
      this.store.appendEvent(event);
      this.recordLocalValidatorAttestation(event.event_hash, this.computeLightStateRootHash());
    });

    return { token: updatedToken, balance: updatedBalance, event, record };
  }

  burnTokenWithWallet(params: {
    ownerWalletId: string;
    requestId: string;
    tokenId: string;
    amount: string;
  }): {
    token: TokenDefinition;
    balance: TokenBalance;
    event: CanonicalVectorEvent;
    record: VectorRecordV1;
  } {
    const wallet = this.store.getWallet(params.ownerWalletId);
    if (!wallet) throw new Error(`wallet not found: ${params.ownerWalletId}`);
    const reqParams = {
      amount: params.amount,
      from_wallet_id: wallet.wallet_id,
      token_id: params.tokenId,
    };
    const signingBytes = canonicalTokenRequestSigningBytes(
      TOKEN_BURN_OP,
      params.requestId,
      wallet.public_key_hex,
      reqParams,
    );
    const signature = this.keystore.signWithWallet(wallet.wallet_id, signingBytes);
    return this.burnToken({
      request_id: params.requestId,
      token_id: params.tokenId,
      from_wallet_id: wallet.wallet_id,
      amount: params.amount,
      actor_public_key: wallet.public_key_hex,
      signature,
    });
  }

  burnToken(request: TokenBurnRequest): {
    token: TokenDefinition;
    balance: TokenBalance;
    event: CanonicalVectorEvent;
    record: VectorRecordV1;
  } {
    if (!request.request_id.trim()) throw new Error("request_id is required");
    const amount = parseU128(request.amount, "burn amount");
    if (amount <= 0n) throw new Error("burn amount must be greater than zero");

    const token = this.store.getToken(request.token_id);
    if (!token) throw new Error(`token not found: ${request.token_id}`);

    const wallet = this.store.getWallet(request.from_wallet_id);
    if (!wallet) throw new Error(`wallet not found: ${request.from_wallet_id}`);

    const reqParams = {
      amount: request.amount,
      from_wallet_id: request.from_wallet_id,
      token_id: request.token_id,
    };
    const signingBytes = canonicalTokenRequestSigningBytes(
      TOKEN_BURN_OP,
      request.request_id,
      request.actor_public_key,
      reqParams,
    );
    if (!verifyEd25519(request.actor_public_key, signingBytes, request.signature)) {
      throw new Error("burn signature verification failed");
    }
    if (request.actor_public_key !== wallet.public_key_hex) {
      throw new Error("unauthorized burn: actor_public_key does not match wallet owner");
    }
    if (this.store.hasSeenRequest(request.request_id)) {
      throw new Error(`duplicate request_id: ${request.request_id}`);
    }

    const existingBalance = this.store.getTokenBalance(token.token_id, wallet.wallet_id);
    const prevBal = existingBalance ? parseU128(existingBalance.balance, "balance") : 0n;
    const nextBal = checkedSubU128(prevBal, amount, "burn");

    const currentTotal = parseU128(token.total_supply, "total_supply");
    const currentBurned = parseU128(token.burned_supply, "burned_supply");
    const nextTotal = checkedSubU128(currentTotal, amount, "total_supply");
    const nextBurned = checkedAddU128(currentBurned, amount, "burned_supply");

    const now = Date.now();
    const updatedToken: TokenDefinition = {
      ...token,
      total_supply: nextTotal.toString(),
      burned_supply: nextBurned.toString(),
      updated_at_ms: now,
      version: token.version + 1,
    };
    const updatedBalance: TokenBalance = {
      token_id: token.token_id,
      wallet_id: wallet.wallet_id,
      owner_pubkey: wallet.public_key_hex,
      balance: nextBal.toString(),
      updated_at_ms: now,
      version: (existingBalance?.version ?? 0) + 1,
    };

    const prevVec = this.store.getVector(token.token_id);
    if (!prevVec) throw new Error(`missing canonical vector for token ${token.token_id}`);

    const nextVec: VectorStateV1 = {
      ...prevVec,
      components: [Number(nextTotal > BigInt(Number.MAX_SAFE_INTEGER) ? 0 : nextTotal)],
      typeMetadata: {
        ...prevVec.typeMetadata,
        total_supply: updatedToken.total_supply,
        burned_supply: updatedToken.burned_supply,
        last_burn_wallet: wallet.wallet_id,
        last_burn_amount: amount.toString(),
      },
      version: prevVec.version + 1,
      updatedAtMs: now,
    };

    const recordBody: Omit<VectorRecordV1, "proof"> = {
      schema: "v.kernelx/VectorRecordV1",
      recordId: makeRecordId("token-burn", token.token_id, request.request_id),
      vectorId: token.token_id,
      before: prevVec,
      after: nextVec,
      operation: "Custom",
      parameters: {
        custom_operation: TOKEN_BURN_OP,
        request_id: request.request_id,
        token_id: token.token_id,
        from_wallet_id: wallet.wallet_id,
        amount: amount.toString(),
        signature: request.signature,
        actor_public_key: request.actor_public_key,
      },
      certification: nextVec.certification,
      timestampMs: now,
    };
    const record: VectorRecordV1 = { ...recordBody, proof: buildRecordProof(recordBody) };

    const event = this.buildTransitionEvent({
      before: prevVec,
      after: nextVec,
      operation: { type: "Other", value: TOKEN_BURN_OP },
      logicalClock: this.nextLogicalClock(),
      timestamp: now,
      parentHashes: this.latestParentHashForEntity(token.token_id),
      actorPublicKey: request.actor_public_key,
      signature: request.signature,
    });
    validateEventIntegrity(event);

    this.store.inTransaction(() => {
      if (this.store.hasSeenRequest(request.request_id)) {
        throw new Error(`duplicate request_id: ${request.request_id}`);
      }
      this.store.markRequestSeen(request.request_id, TOKEN_BURN_OP, now);
      this.store.putToken(updatedToken);
      this.store.putTokenBalance(updatedBalance);
      this.store.putVector(nextVec);
      this.store.putRecord(record);
      this.store.appendEvent(event);
      this.recordLocalValidatorAttestation(event.event_hash, this.computeLightStateRootHash());
    });

    return { token: updatedToken, balance: updatedBalance, event, record };
  }

  transferTokenWithWallet(params: {
    senderWalletId: string;
    requestId: string;
    tokenId: string;
    toWalletId: string;
    amount: string;
  }): {
    token: TokenDefinition;
    fromBalance: TokenBalance;
    toBalance: TokenBalance;
    drain: DrainFeeBreakdown;
    rewards: DrainRewardRecord[];
    event: CanonicalVectorEvent;
    record: VectorRecordV1;
  } {
    const wallet = this.store.getWallet(params.senderWalletId);
    if (!wallet) throw new Error(`sender wallet not found: ${params.senderWalletId}`);
    const reqParams = {
      amount: params.amount,
      from_wallet_id: wallet.wallet_id,
      to_wallet_id: params.toWalletId,
      token_id: params.tokenId,
    };
    const signingBytes = canonicalTokenRequestSigningBytes(
      TOKEN_TRANSFER_OP,
      params.requestId,
      wallet.public_key_hex,
      reqParams,
    );
    const signature = this.keystore.signWithWallet(wallet.wallet_id, signingBytes);
    return this.transferToken({
      request_id: params.requestId,
      token_id: params.tokenId,
      from_wallet_id: wallet.wallet_id,
      to_wallet_id: params.toWalletId,
      amount: params.amount,
      actor_public_key: wallet.public_key_hex,
      signature,
    });
  }

  transferToken(request: TokenTransferRequest): {
    token: TokenDefinition;
    fromBalance: TokenBalance;
    toBalance: TokenBalance;
    drain: DrainFeeBreakdown;
    rewards: DrainRewardRecord[];
    event: CanonicalVectorEvent;
    record: VectorRecordV1;
  } {
    if (!request.request_id.trim()) throw new Error("request_id is required");
    if (request.from_wallet_id === request.to_wallet_id) {
      throw new Error("cannot transfer to the same wallet");
    }
    const amount = parseU128(request.amount, "transfer amount");
    if (amount <= 0n) throw new Error("transfer amount must be greater than zero");

    const token = this.store.getToken(request.token_id);
    if (!token) throw new Error(`token not found: ${request.token_id}`);

    const fromWallet = this.store.getWallet(request.from_wallet_id);
    const toWallet = this.store.getWallet(request.to_wallet_id);
    if (!fromWallet || !toWallet) {
      throw new Error("sender or receiver wallet not found");
    }

    const reqParams = {
      amount: request.amount,
      from_wallet_id: request.from_wallet_id,
      to_wallet_id: request.to_wallet_id,
      token_id: request.token_id,
    };
    const signingBytes = canonicalTokenRequestSigningBytes(
      TOKEN_TRANSFER_OP,
      request.request_id,
      request.actor_public_key,
      reqParams,
    );
    if (!verifyEd25519(request.actor_public_key, signingBytes, request.signature)) {
      throw new Error("transfer signature verification failed");
    }
    if (request.actor_public_key !== fromWallet.public_key_hex) {
      throw new Error("unauthorized transfer: actor_public_key does not match sender wallet owner");
    }
    if (this.store.hasSeenRequest(request.request_id)) {
      throw new Error(`duplicate request_id: ${request.request_id}`);
    }

    const existingFrom = this.store.getTokenBalance(token.token_id, fromWallet.wallet_id);
    const prevFromBal = existingFrom ? parseU128(existingFrom.balance, "sender balance") : 0n;
    if (amount > prevFromBal) {
      throw new Error("transfer: insufficient balance");
    }

    // Drain Fee + Auth Ratio Discount + 4-Way Creator & Network Pool Split
    const baseDrainBps = token.drain_bps ?? DEFAULT_TRANSFER_DRAIN_BPS;
    const authRatio = this.computeWalletAuthRatio(fromWallet);
    const dist = computeDrainDistribution(amount, baseDrainBps, authRatio, DEFAULT_AUTH_RATIO_THRESHOLD);

    const region = this.store.getRegion(token.region_id);
    const networkWallet = this.store.getWallet(this.nodeId)!;
    const tokenCreatorWallet = this.store.getWallet(token.authority_pubkey) ?? networkWallet;
    const regionCreatorWallet =
      (region ? this.store.getWallet(region.creator_public_key) : null) ?? tokenCreatorWallet;
    const walletCreatorWallet =
      (fromWallet.creator_wallet_id ? this.store.getWallet(fromWallet.creator_wallet_id) : null) ??
      fromWallet;

    const now = Date.now();

    // Accumulate net balance deltas cleanly by wallet_id so overlapping roles never overwrite one another
    const deltaMap = new Map<string, bigint>();
    const addDelta = (walletId: string, delta: bigint) => {
      deltaMap.set(walletId, (deltaMap.get(walletId) ?? 0n) + delta);
    };
    addDelta(fromWallet.wallet_id, -amount);
    addDelta(toWallet.wallet_id, dist.netReceived);

    const roleAssignments: Array<{ role: BeneficiaryRole; wallet: PublicWalletRecord; amount: bigint }> = [
      { role: "region_creator", wallet: regionCreatorWallet, amount: dist.regionReward },
      { role: "wallet_creator", wallet: walletCreatorWallet, amount: dist.walletReward },
      { role: "token_creator", wallet: tokenCreatorWallet, amount: dist.tokenReward },
      { role: "network_pool", wallet: networkWallet, amount: dist.networkReward },
    ];

    const rewardAllocationMap = new Map<string, bigint>();
    for (const r of roleAssignments) {
      if (r.amount > 0n) {
        addDelta(r.wallet.wallet_id, r.amount);
        rewardAllocationMap.set(
          r.wallet.wallet_id,
          (rewardAllocationMap.get(r.wallet.wallet_id) ?? 0n) + r.amount,
        );
      }
    }

    const rewardAllocations = [...rewardAllocationMap.entries()]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([wId, amt]) => [wId, amt.toString()] as [string, string]);

    const updatedBalances = new Map<string, TokenBalance>();
    for (const [walletId, delta] of deltaMap.entries()) {
      const targetWlt = this.store.getWallet(walletId)!;
      const prevRow = this.store.getTokenBalance(token.token_id, walletId);
      const prevAmt = prevRow ? parseU128(prevRow.balance, "balance") : 0n;
      const nextAmt = delta >= 0n ? checkedAddU128(prevAmt, delta, "wallet balance") : checkedSubU128(prevAmt, -delta, "transfer");
      updatedBalances.set(walletId, {
        token_id: token.token_id,
        wallet_id: walletId,
        owner_pubkey: targetWlt.public_key_hex,
        balance: nextAmt.toString(),
        updated_at_ms: now,
        version: (prevRow?.version ?? 0) + 1,
      });
    }

    const prevDrainedTotal = parseU128(token.drained_fees_collected ?? "0", "drained_fees_collected");
    const nextDrainedTotal = checkedAddU128(prevDrainedTotal, dist.totalFee, "drained_fees_collected");

    const updatedToken: TokenDefinition = {
      ...token,
      drained_fees_collected: nextDrainedTotal.toString(),
      updated_at_ms: now,
      version: token.version + 1,
    };

    const rewards: DrainRewardRecord[] = roleAssignments
      .filter((r) => r.amount > 0n)
      .map((r) => ({
        reward_id: makeRecordId("tkn-reward", `${token.token_id}:${r.role}`, request.request_id),
        tx_request_id: request.request_id,
        token_id: token.token_id,
        vector_id: null,
        beneficiary_role: r.role,
        wallet_id: r.wallet.wallet_id,
        amount: r.amount.toString(),
        timestamp_ms: now,
      }));

    const drainBreakdown: DrainFeeBreakdown = {
      base_bps: dist.baseBps,
      effective_bps: dist.effectiveBps,
      auth_ratio: authRatio,
      threshold: DEFAULT_AUTH_RATIO_THRESHOLD,
      discounted: dist.discounted,
      total_fee: dist.totalFee.toString(),
      net_received: dist.netReceived.toString(),
      region_creator_reward: dist.regionReward.toString(),
      wallet_creator_reward: dist.walletReward.toString(),
      token_creator_reward: dist.tokenReward.toString(),
      network_reward: dist.networkReward.toString(),
    };

    const prevVec = this.store.getVector(token.token_id);
    if (!prevVec) throw new Error(`missing canonical vector for token ${token.token_id}`);

    const nextVec: VectorStateV1 = {
      ...prevVec,
      typeMetadata: {
        ...prevVec.typeMetadata,
        drained_fees_collected: nextDrainedTotal.toString(),
        last_tx_id: request.request_id,
        last_tx_from: fromWallet.wallet_id,
        last_tx_to: toWallet.wallet_id,
        last_tx_amount: amount.toString(),
        last_tx_fee: dist.totalFee.toString(),
        last_tx_net: dist.netReceived.toString(),
        last_tx_effective_bps: String(dist.effectiveBps),
        last_tx_auth_ratio: String(authRatio),
        last_tx_reward_allocations: JSON.stringify(rewardAllocations),
      },
      version: prevVec.version + 1,
      updatedAtMs: now,
    };

    const recordBody: Omit<VectorRecordV1, "proof"> = {
      schema: "v.kernelx/VectorRecordV1",
      recordId: makeRecordId("token-transfer", token.token_id, request.request_id),
      vectorId: token.token_id,
      before: prevVec,
      after: nextVec,
      operation: "Transfer",
      parameters: {
        custom_operation: TOKEN_TRANSFER_OP,
        request_id: request.request_id,
        token_id: token.token_id,
        from_wallet_id: fromWallet.wallet_id,
        to_wallet_id: toWallet.wallet_id,
        amount: amount.toString(),
        drain_fee: dist.totalFee.toString(),
        net_received: dist.netReceived.toString(),
        effective_bps: dist.effectiveBps,
        auth_ratio: authRatio,
        rewards: roleAssignments.map((r) => ({
          role: r.role,
          wallet_id: r.wallet.wallet_id,
          amount: r.amount.toString(),
        })),
        signature: request.signature,
        actor_public_key: request.actor_public_key,
      },
      certification: nextVec.certification,
      timestampMs: now,
    };
    const record: VectorRecordV1 = { ...recordBody, proof: buildRecordProof(recordBody) };

    const event = this.buildTransitionEvent({
      before: prevVec,
      after: nextVec,
      operation: { type: "Other", value: TOKEN_TRANSFER_OP },
      logicalClock: this.nextLogicalClock(),
      timestamp: now,
      parentHashes: this.latestParentHashForEntity(token.token_id),
      actorPublicKey: request.actor_public_key,
      signature: request.signature,
    });
    validateEventIntegrity(event);

    this.store.inTransaction(() => {
      if (this.store.hasSeenRequest(request.request_id)) {
        throw new Error(`duplicate request_id: ${request.request_id}`);
      }
      this.store.markRequestSeen(request.request_id, TOKEN_TRANSFER_OP, now);
      this.store.putToken(updatedToken);
      for (const bal of updatedBalances.values()) {
        this.store.putTokenBalance(bal);
      }
      for (const reward of rewards) {
        this.store.putDrainReward(reward);
      }
      this.store.putVector(nextVec);
      this.store.putRecord(record);
      this.store.appendEvent(event);
      this.recordLocalValidatorAttestation(event.event_hash, this.computeLightStateRootHash());
    });

    return {
      token: updatedToken,
      fromBalance: updatedBalances.get(fromWallet.wallet_id)!,
      toBalance: updatedBalances.get(toWallet.wallet_id)!,
      drain: drainBreakdown,
      rewards,
      event,
      record,
    };
  }

  verifySupplyConservation(tokenId: string): {
    conserved: boolean;
    total_supply: string;
    sum_of_balances: string;
    minted_minus_burned: string;
    transported_minus_burned: string;
  } {
    const token = this.store.getToken(tokenId);
    if (!token) throw new Error(`token not found: ${tokenId}`);
    const balances = this.store.listTokenBalancesForToken(token.token_id);
    const sum = balances.reduce((acc, b) => acc + parseU128(b.balance, "balance"), 0n);
    const total = parseU128(token.total_supply, "total_supply");
    const transported = parseU128(token.transported_supply ?? token.minted_supply, "transported_supply");
    const burned = parseU128(token.burned_supply, "burned_supply");
    const transportedMinusBurned = transported - burned;
    return {
      conserved: sum === total && total === transportedMinusBurned,
      total_supply: total.toString(),
      sum_of_balances: sum.toString(),
      minted_minus_burned: transportedMinusBurned.toString(),
      transported_minus_burned: transportedMinusBurned.toString(),
    };
  }

  // -------------------------
  // Decentralized Quorum Consensus & Peer Sync
  // -------------------------
  registerValidator(params: {
    node_id: string;
    public_key_hex: string;
    label: string;
    weight: number;
    active?: boolean;
  }): ValidatorNode {
    const nodeId = params.node_id.trim();
    const pubkey = params.public_key_hex.trim().toLowerCase();
    const label = params.label.trim();
    if (!nodeId || !label) throw new Error("validator node_id and label are required");
    if (!isValidHex(pubkey, 32)) throw new Error("validator public_key_hex must be 32-byte hex");
    if (!Number.isInteger(params.weight) || params.weight <= 0) {
      throw new Error("validator weight must be a positive integer");
    }
    const validator: ValidatorNode = {
      node_id: nodeId,
      public_key_hex: pubkey,
      label,
      weight: params.weight,
      active: params.active ?? true,
      joined_at_ms: Date.now(),
    };
    this.store.inTransaction(() => {
      this.store.putValidator(validator);
    });
    return validator;
  }

  listValidators(): ValidatorNode[] {
    return this.store.listValidators();
  }

  attestEvent(attestation: EventAttestation): ConsensusRound {
    const validator = this.store.getValidator(attestation.validator_id);
    if (!validator) {
      throw new Error(`unknown validator: ${attestation.validator_id}`);
    }
    if (!validator.active) {
      throw new Error(`validator is inactive: ${attestation.validator_id}`);
    }
    if (validator.public_key_hex !== attestation.validator_pubkey.toLowerCase()) {
      throw new Error("validator_pubkey does not match registered validator");
    }
    const ev = this.store.getEventByHash(attestation.event_hash);
    if (!ev) {
      throw new Error(`event_hash not found: ${attestation.event_hash}`);
    }

    const bytes = canonicalAttestationSigningBytes({
      event_hash: attestation.event_hash,
      validator_id: attestation.validator_id,
      validator_pubkey: attestation.validator_pubkey,
      vote_accept: attestation.vote_accept,
      state_root_hash: attestation.state_root_hash,
      timestamp_ms: attestation.timestamp_ms,
    });
    if (!verifyEd25519(validator.public_key_hex, bytes, attestation.signature)) {
      throw new Error("attestation Ed25519 signature verification failed");
    }

    this.store.inTransaction(() => {
      this.store.putAttestation({
        ...attestation,
        validator_pubkey: validator.public_key_hex,
      });
    });

    return this.getConsensusRound(attestation.event_hash);
  }

  attestEventWithLocalNode(eventHash: string, voteAccept = true): ConsensusRound {
    const ev = this.store.getEventByHash(eventHash);
    if (!ev) throw new Error(`event_hash not found: ${eventHash}`);
    const stateRootHash = this.computeLightStateRootHash();
    const timestamp_ms = Date.now();
    const bytes = canonicalAttestationSigningBytes({
      event_hash: eventHash,
      validator_id: this.nodeId,
      validator_pubkey: this.nodePubkey,
      vote_accept: voteAccept,
      state_root_hash: stateRootHash,
      timestamp_ms,
    });
    const signature = this.keystore.signWithWallet(this.nodeId, bytes);
    return this.attestEvent({
      event_hash: eventHash,
      validator_id: this.nodeId,
      validator_pubkey: this.nodePubkey,
      vote_accept: voteAccept,
      state_root_hash: stateRootHash,
      signature,
      timestamp_ms,
    });
  }

  getConsensusRound(eventHash: string): ConsensusRound {
    const validators = this.store.listValidators();
    const validatorMap = new Map(validators.map((v) => [v.node_id, v]));
    const totalWeight = validators.filter((v) => v.active).reduce((acc, v) => acc + v.weight, 0);
    const attestations = this.store.listAttestationsForEvent(eventHash);
    const approvingWeight = attestations
      .filter((a) => a.vote_accept)
      .reduce((acc, a) => {
        const v = validatorMap.get(a.validator_id);
        return v && v.active ? acc + v.weight : acc;
      }, 0);
    const finalized =
      totalWeight > 0 &&
      BigInt(approvingWeight) * 10_000n >= BigInt(totalWeight) * BigInt(DEFAULT_QUORUM_BPS);
    return {
      event_hash: eventHash,
      total_weight: totalWeight,
      approving_weight: approvingWeight,
      quorum_threshold_bps: DEFAULT_QUORUM_BPS,
      finalized,
      attestations,
    };
  }

  listConsensusRounds(): ConsensusRound[] {
    const events = this.store.listEvents();
    return events.map((ev) => this.getConsensusRound(ev.event_hash));
  }

  exportSyncBundle(): SyncBundle {
    const replay = this.replayCanonicalHistory();
    return {
      protocol: "v-kernelx-sync-v1",
      source_node_id: this.nodeId,
      source_node_pubkey: this.nodePubkey,
      exported_at_ms: Date.now(),
      state_root: replay.state_root,
      replay_hash: replay.replay_hash,
      validators: this.store.listValidators(),
      events: this.store.listEvents(),
      attestations: this.store.listAllAttestations(),
    };
  }

  importPeerSyncBundle(bundle: {
    validators?: ValidatorNode[];
    events?: CanonicalVectorEvent[];
    attestations?: EventAttestation[];
  }): { imported_events: number; imported_attestations: number; replay: ReplayResult } {
    const incomingEvents = Array.isArray(bundle.events) ? bundle.events : [];
    const incomingValidators = Array.isArray(bundle.validators) ? bundle.validators : [];
    const incomingAtts = Array.isArray(bundle.attestations) ? bundle.attestations : [];

    // Verify full merged DAG before persisting any peer event
    const existingEvents = this.store.listEvents();
    const existingHashes = new Set(existingEvents.map((e) => e.event_hash));
    const newEvents = sortEvents(incomingEvents).filter((e) => !existingHashes.has(e.event_hash));

    for (const ev of newEvents) {
      validateEventIntegrity(ev);
    }

    const mergedEvents = sortEvents([...existingEvents, ...newEvents]);
    validateDag(mergedEvents);

    let importedAtts = 0;
    this.store.inTransaction(() => {
      for (const v of incomingValidators) {
        if (!this.store.getValidator(v.node_id) && isValidHex(v.public_key_hex, 32) && v.weight > 0) {
          this.store.putValidator(v);
        }
      }
      for (const ev of newEvents) {
        this.store.appendEvent(ev);
        if (isRegionCreateEvent(ev)) {
          const region = regionStateFromEvent(ev);
          const lookup = regionLookupKey(region.region_name, region.region_prefix);
          if (!this.store.getRegion(region.region_id)) {
            this.store.putRegion(region, lookup);
          }
        }
      }
      for (const att of incomingAtts) {
        const v = this.store.getValidator(att.validator_id);
        const evExists = this.store.getEventByHash(att.event_hash);
        if (v && v.active && evExists) {
          const bytes = canonicalAttestationSigningBytes(att);
          if (verifyEd25519(v.public_key_hex, bytes, att.signature)) {
            this.store.putAttestation(att);
            importedAtts += 1;
          }
        }
      }
    });

    const replay = this.replayCanonicalHistory();
    return {
      imported_events: newEvents.length,
      imported_attestations: importedAtts,
      replay,
    };
  }

  // -------------------------
  // Deterministic History Replay & Verification
  // -------------------------
  replayCanonicalHistory(): ReplayResult {
    const events = sortEvents(this.store.listEvents());
    validateDag(events);

    const finalState: Record<string, CanonicalVectorState> = {};
    const coreState = createEmptyCoreState();
    const regions: Record<string, RegionState> = {};
    const tokens: Record<string, TokenDefinition> = {};
    const tokenBalances: Record<string, Record<string, string>> = {};
    const appliedEventHashes: string[] = [];
    let logicalClock = 0;

    for (const ev of events) {
      validateEventIntegrity(ev);
      if (isRegionCreateEvent(ev)) {
        const region = regionStateFromEvent(ev);
        insertRegionIntoCore(coreState, region);
        regions[region.region_id] = region;
        finalState[ev.entity_id] = ev.vector_after;
      } else {
        const current = finalState[ev.entity_id];
        if (
          ev.operation.type === "OriginCreate" ||
          (ev.operation.type === "Other" && ev.operation.value === TOKEN_CREATE_OP)
        ) {
          if (current !== undefined) {
            throw new Error(`origin create attempted for existing entity_id: ${ev.entity_id}`);
          }
        } else {
          if (current === undefined) {
            throw new Error(`non-origin event references missing entity state: ${ev.entity_id}`);
          }
          if (JSON.stringify(current) !== JSON.stringify(ev.vector_before)) {
            throw new Error(`vector_before mismatch for entity_id ${ev.entity_id}`);
          }
        }
        finalState[ev.entity_id] = ev.vector_after;

        if (ev.operation.type === "Other" && ev.operation.value === TOKEN_CREATE_OP) {
          const md = ev.vector_after.metadata;
          tokens[ev.entity_id] = {
            token_id: ev.entity_id,
            name: md.name,
            symbol: md.symbol,
            region_id: ev.region_id,
            decimals: Number(md.decimals),
            max_supply: md.max_supply,
            total_supply: "0",
            minted_supply: "0",
            transported_supply: "0",
            burned_supply: "0",
            drained_fees_collected: "0",
            drain_bps: md.drain_bps ? Number(md.drain_bps) : DEFAULT_TRANSFER_DRAIN_BPS,
            authority_pubkey: md.authority_pubkey,
            supply_policy: md.supply_policy,
            token_type: md.token_type,
            created_at_ms: ev.timestamp,
            updated_at_ms: ev.timestamp,
            version: 1,
          };
          tokenBalances[ev.entity_id] = {};
        } else if (
          ev.operation.type === "Other" &&
          (ev.operation.value === TOKEN_MINT_OP || ev.operation.value === TOKEN_TRANSPORT_OP)
        ) {
          const md = ev.vector_after.metadata;
          const t = tokens[ev.entity_id];
          if (!t) throw new Error(`replay missing token ${ev.entity_id}`);
          const amt = parseU128(
            md.last_transport_amount ?? md.last_mint_amount,
            "last_transport_amount",
          );
          const target = md.last_transport_wallet ?? md.last_mint_wallet;
          t.total_supply = checkedAddU128(parseU128(t.total_supply), amt).toString();
          const prevTrans = parseU128(t.transported_supply ?? t.minted_supply);
          const nextTrans = checkedAddU128(prevTrans, amt).toString();
          t.minted_supply = nextTrans;
          t.transported_supply = nextTrans;
          t.updated_at_ms = ev.timestamp;
          t.version += 1;
          const prevBal = parseU128(tokenBalances[ev.entity_id][target] ?? "0");
          tokenBalances[ev.entity_id][target] = checkedAddU128(prevBal, amt).toString();
        } else if (ev.operation.type === "Other" && ev.operation.value === TOKEN_BURN_OP) {
          const md = ev.vector_after.metadata;
          const t = tokens[ev.entity_id];
          if (!t) throw new Error(`replay missing token ${ev.entity_id}`);
          const amt = parseU128(md.last_burn_amount, "last_burn_amount");
          const from = md.last_burn_wallet;
          t.total_supply = checkedSubU128(parseU128(t.total_supply), amt).toString();
          t.burned_supply = checkedAddU128(parseU128(t.burned_supply), amt).toString();
          t.updated_at_ms = ev.timestamp;
          t.version += 1;
          const prevBal = parseU128(tokenBalances[ev.entity_id][from] ?? "0");
          tokenBalances[ev.entity_id][from] = checkedSubU128(prevBal, amt).toString();
        } else if (ev.operation.type === "Other" && ev.operation.value === TOKEN_TRANSFER_OP) {
          const md = ev.vector_after.metadata;
          const grossAmt = parseU128(md.last_tx_amount, "last_tx_amount");
          const netAmt = md.last_tx_net ? parseU128(md.last_tx_net, "last_tx_net") : grossAmt;
          const from = md.last_tx_from;
          const to = md.last_tx_to;

          const prevFrom = parseU128(tokenBalances[ev.entity_id][from] ?? "0");
          tokenBalances[ev.entity_id][from] = checkedSubU128(prevFrom, grossAmt).toString();

          const prevTo = parseU128(tokenBalances[ev.entity_id][to] ?? "0");
          tokenBalances[ev.entity_id][to] = checkedAddU128(prevTo, netAmt).toString();

          if (md.last_tx_reward_allocations) {
            const allocs = JSON.parse(md.last_tx_reward_allocations) as Array<[string, string]>;
            for (const [wId, amtStr] of allocs) {
              const rewardAmt = parseU128(amtStr, "reward_allocation");
              const prevW = parseU128(tokenBalances[ev.entity_id][wId] ?? "0");
              tokenBalances[ev.entity_id][wId] = checkedAddU128(prevW, rewardAmt).toString();
            }
          }
        }
      }

      appliedEventHashes.push(ev.event_hash);
      logicalClock = Math.max(logicalClock, ev.logical_clock);
    }

    const canonicalStateBytes = canonicalStateMapBytes(finalState);
    const stateRoot = computeStateRootFromCanonicalBytes(
      canonicalStateBytes,
      appliedEventHashes.length,
      logicalClock,
    );
    const replayHash = canonicalReplayHash(appliedEventHashes);

    const mismatchReasons: string[] = [];
    for (const storedRegion of this.store.listRegions()) {
      const replayed = regions[storedRegion.region_id];
      if (!replayed) {
        mismatchReasons.push(`stored region missing from replay: ${storedRegion.region_id}`);
      } else if (replayed.region_root !== storedRegion.region_root) {
        mismatchReasons.push(`region root mismatch for ${storedRegion.region_id}`);
      }
    }
    for (const storedToken of this.store.listTokens()) {
      const replayedToken = tokens[storedToken.token_id];
      if (!replayedToken) {
        mismatchReasons.push(`stored token missing from replay: ${storedToken.token_id}`);
      } else if (replayedToken.total_supply !== storedToken.total_supply) {
        mismatchReasons.push(
          `token total_supply mismatch for ${storedToken.symbol}: replayed=${replayedToken.total_supply} stored=${storedToken.total_supply}`,
        );
      }
      for (const storedBal of this.store.listTokenBalancesForToken(storedToken.token_id)) {
        const replayedBal = tokenBalances[storedToken.token_id]?.[storedBal.wallet_id] ?? "0";
        if (replayedBal !== storedBal.balance) {
          mismatchReasons.push(
            `balance mismatch for ${storedBal.wallet_id}: replayed=${replayedBal} stored=${storedBal.balance}`,
          );
        }
      }
    }
    for (const storedVec of this.store.listVectors()) {
      const replayedVec = finalState[storedVec.vectorId];
      if (!replayedVec) {
        mismatchReasons.push(`stored vector missing from replay: ${storedVec.vectorId}`);
      } else if (
        JSON.stringify(replayedVec.components) !==
        JSON.stringify(storedVec.components.map((c) => String(c)))
      ) {
        mismatchReasons.push(`vector components mismatch for ${storedVec.vectorId}`);
      }
    }

    return {
      final_state: finalState,
      core_state: coreState,
      regions,
      tokens,
      token_balances: tokenBalances,
      state_root: stateRoot,
      replay_hash: replayHash,
      applied_event_hashes: appliedEventHashes,
      matches_stored_state: mismatchReasons.length === 0,
      mismatch_reasons: mismatchReasons,
    };
  }

  createAndStoreSnapshot(): CanonicalSnapshot {
    const replay = this.replayCanonicalHistory();
    const stateBytes = canonicalStateMapBytes(replay.final_state);
    const snapshotId = canonicalTaggedHash("snapshot-v1", stateBytes);

    const events = this.store.listEvents();
    const referenced = new Set<string>();
    for (const ev of events) {
      for (const p of ev.parent_hashes) referenced.add(p);
    }
    const dagHeads = events
      .filter((e) => !referenced.has(e.event_hash))
      .map((e) => e.event_hash)
      .sort();

    const snapshot: CanonicalSnapshot = {
      snapshot_id: snapshotId,
      state_root: replay.state_root,
      event_root: replay.replay_hash,
      replay_hash: replay.replay_hash,
      event_count: replay.state_root.event_count,
      logical_clock: replay.state_root.logical_clock,
      dag_heads: dagHeads,
      state_bytes_hex: stateBytes.toString("hex"),
      created_at: Date.now(),
    };

    this.store.inTransaction(() => {
      this.store.putSnapshot(snapshot);
    });

    return snapshot;
  }

  verifySnapshot(snapshot: CanonicalSnapshot): boolean {
    const replay = this.replayCanonicalHistory();
    const expectedStateBytes = canonicalStateMapBytes(replay.final_state);
    const expectedId = canonicalTaggedHash("snapshot-v1", expectedStateBytes);
    const expectedRootHash = canonicalStateRootHash(snapshot.state_root);
    return (
      snapshot.snapshot_id === expectedId &&
      snapshot.state_bytes_hex === expectedStateBytes.toString("hex") &&
      snapshot.replay_hash === replay.replay_hash &&
      expectedRootHash.length > 0
    );
  }

  status(): NodeStatus {
    const replay = this.replayCanonicalHistory();
    const rounds = this.listConsensusRounds();
    return {
      kernel_version: KERNEL_VERSION,
      network_name: NETWORK_NAME,
      network_mode: NETWORK_MODE,
      node_id: this.nodeId,
      node_pubkey: this.nodePubkey,
      storage_engine: "SQLite (WAL + synchronous=FULL via node:sqlite)",
      db_path: this.store.dbPath,
      db_integrity_ok: this.store.integrityCheck(),
      vector_count: this.store.listVectors().length,
      record_count: this.store.listRecords().length,
      event_count: this.store.listEvents().length,
      region_count: this.store.listRegions().length,
      wallet_count: this.store.listWallets().length,
      token_count: this.store.listTokens().length,
      validator_count: this.store.listValidators().filter((v) => v.active).length,
      finalized_event_count: rounds.filter((r) => r.finalized).length,
      total_drain_rewards_count: this.store.listDrainRewards(10_000).length,
      state_root: replay.state_root,
      replay_hash: replay.replay_hash,
      replay_verified: replay.matches_stored_state,
    };
  }
}

function canonicalRegionRequestSignatureBytesCompat(request: RegionCreateRequest): Buffer {
  const metadataSorted = sortedJsonStringify(request.metadata ?? {});
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
  return Buffer.from(sortedJsonStringify(payload), "utf8");
}
