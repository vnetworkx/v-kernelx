import { blake3Hex, verifyEd25519 } from "./crypto.ts";
import {
  canonicalEventHash,
  canonicalEventId,
  canonicalPayloadHash,
  sortedJsonStringify,
  type CanonicalOperationType,
  type CanonicalVectorEvent,
  type CanonicalVectorState,
} from "./serialization.ts";

export const REGION_CREATE_OPERATION_NAME = "REGION_CREATE";
export const REGION_TYPE_TAG = "region";
export const DEFAULT_REGION_AUTH_RATIO_BPS = 1000;

export type RegionVisibility = "public" | "private";

export interface RegionCreateRequest {
  region_name: string;
  region_prefix?: string | null;
  suggested_title?: string | null;
  visibility: RegionVisibility;
  section: number;
  trigger_event_hash: string;
  creation_proof: string;
  access_key?: string | null;
  metadata: Record<string, string>;
  request_signature: string;
}

export interface RegionState {
  region_id: string;
  region_root: string;
  region_name: string;
  normalized_name: string;
  region_prefix: string | null;
  suggested_title: string | null;
  visibility: RegionVisibility;
  section: number;
  auth_ratio_bps: number;
  creator_public_key: string;
  trigger_event_hash: string;
  creation_proof_hash: string;
  access_key_hash: string | null;
  created_at_ms: number;
  updated_at_ms: number;
  version: number;
  metadata: Record<string, string>;
}

export interface CoreState {
  regions: Record<string, RegionState>;
  total_auth_ratio_bps: number;
  core_root: string;
  version: number;
}

export function normalizeRegionName(name: string): string {
  return name.trim().toLowerCase();
}

export function normalizeRegionPrefix(prefix?: string | null): string | null {
  if (!prefix) return null;
  const trimmed = prefix.trim().toUpperCase();
  return trimmed.length > 0 ? trimmed : null;
}

export function regionLookupKey(name: string, prefix?: string | null): string {
  return `${normalizeRegionPrefix(prefix) ?? ""}::${normalizeRegionName(name)}`;
}

export function canonicalRegionRequestSignatureBytes(request: RegionCreateRequest): Buffer {
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

export function canonicalRegionSeedBytes(
  request: RegionCreateRequest,
  actorPublicKey: string,
): Buffer {
  const metadataSorted = sortedJsonStringify(request.metadata ?? {});
  const payload: Record<string, string> = {
    access_key_hash: request.access_key ? blake3Hex(request.access_key) : "",
    actor_public_key: actorPublicKey,
    creation_proof_hash: blake3Hex(request.creation_proof),
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

export function canonicalRegionId(
  request: RegionCreateRequest,
  actorPublicKey: string,
  sequence = 1,
): string {
  const seed = canonicalRegionSeedBytes(request, actorPublicKey);
  const digest = blake3Hex(seed);
  const short = digest.slice(0, 24);
  const prefix = normalizeRegionPrefix(request.region_prefix) ?? "RGN";
  return `${prefix}::rgn_${short}::${sequence}`;
}

export function validateRegionCreateRequest(request: RegionCreateRequest): void {
  if (!request.region_name || !request.region_name.trim()) {
    throw new Error("region_name cannot be empty");
  }
  if (!Number.isInteger(request.section) || request.section <= 0) {
    throw new Error("section must be greater than zero");
  }
  if (!request.trigger_event_hash || !request.trigger_event_hash.trim()) {
    throw new Error("trigger_event_hash cannot be empty");
  }
  if (!request.creation_proof || !request.creation_proof.trim()) {
    throw new Error("creation_proof cannot be empty");
  }
  if (!request.request_signature || !request.request_signature.trim()) {
    throw new Error("request_signature cannot be empty");
  }
  if (request.visibility === "public") {
    if (request.access_key !== undefined && request.access_key !== null && request.access_key !== "") {
      throw new Error("public regions must not include an access_key");
    }
  } else if (request.visibility === "private") {
    if (!request.access_key || !request.access_key.trim()) {
      throw new Error("private regions require a non-empty access_key");
    }
  } else {
    throw new Error(`invalid region visibility: ${String(request.visibility)}`);
  }
}

export function verifyRegionCreateRequestSignature(
  actorPublicKey: string,
  request: RegionCreateRequest,
): void {
  const bytes = canonicalRegionRequestSignatureBytes(request);
  const ok = verifyEd25519(actorPublicKey, bytes, request.request_signature);
  if (!ok) {
    throw new Error("region request signature verification failed");
  }
}

export function regionCreateOperation(): CanonicalOperationType {
  return { type: "Other", value: REGION_CREATE_OPERATION_NAME };
}

export function buildRegionGenesisEvent(
  request: RegionCreateRequest,
  actorPublicKey: string,
  logicalClock: number,
  timestamp: number,
  sequence = 1,
): CanonicalVectorEvent {
  validateRegionCreateRequest(request);

  const creationProofHash = blake3Hex(request.creation_proof);
  const accessKeyHash = request.access_key ? blake3Hex(request.access_key) : null;
  const regionId = canonicalRegionId(request, actorPublicKey, sequence);

  const metadata: Record<string, string> = {
    region_kind: REGION_TYPE_TAG,
    region_name: request.region_name,
    normalized_name: normalizeRegionName(request.region_name),
    region_prefix: normalizeRegionPrefix(request.region_prefix) ?? "",
    section: String(request.section),
    suggested_title: request.suggested_title ?? "",
    visibility: request.visibility,
    creator_public_key: actorPublicKey,
    trigger_event_hash: request.trigger_event_hash,
    creation_proof_hash: creationProofHash,
    access_key_hash: accessKeyHash ?? "",
    initial_auth_ratio_bps: String(DEFAULT_REGION_AUTH_RATIO_BPS),
    core_registry: "core",
    default_auth_ratio: "1.0",
  };

  for (const [k, v] of Object.entries(request.metadata ?? {})) {
    metadata[`meta:${k}`] = String(v);
  }

  const before: CanonicalVectorState = {
    components: [],
    owner_public_key: "",
    type_tag: REGION_TYPE_TAG,
    metadata: {},
  };

  const after: CanonicalVectorState = {
    components: [],
    owner_public_key: "",
    type_tag: REGION_TYPE_TAG,
    metadata,
  };

  const operation = regionCreateOperation();
  const eventId = canonicalEventId(regionId, regionId, operation, logicalClock, sequence);

  const event: CanonicalVectorEvent = {
    event_id: eventId,
    parent_hashes: [],
    region_id: regionId,
    entity_id: regionId,
    operation,
    vector_before: before,
    vector_after: after,
    auth_ratio: 1.0,
    certified: true,
    actor_public_key: actorPublicKey,
    logical_clock: logicalClock,
    timestamp,
    payload_hash: "",
    event_hash: "",
    signature: request.request_signature,
  };

  event.payload_hash = canonicalPayloadHash(event);
  event.event_hash = canonicalEventHash(event);
  return event;
}

export function isRegionCreateEvent(event: CanonicalVectorEvent): boolean {
  return (
    (event.operation.type === "OriginCreate" &&
      event.vector_after.metadata?.region_kind === REGION_TYPE_TAG) ||
    (event.operation.type === "Other" &&
      event.operation.value === REGION_CREATE_OPERATION_NAME)
  );
}

export function regionStateFromEvent(event: CanonicalVectorEvent): RegionState {
  if (!isRegionCreateEvent(event)) {
    throw new Error("event is not a region creation event");
  }
  if (!event.event_hash.trim()) {
    throw new Error("region event hash cannot be empty");
  }
  const md = event.vector_after.metadata;
  const regionName = md.region_name;
  const normalizedName = md.normalized_name;
  if (!regionName || !normalizedName) {
    throw new Error("missing region_name or normalized_name");
  }
  const section = Number(md.section);
  if (!Number.isInteger(section) || section <= 0) {
    throw new Error(`invalid section: ${md.section}`);
  }
  const authRatioBps = md.initial_auth_ratio_bps
    ? Number(md.initial_auth_ratio_bps)
    : DEFAULT_REGION_AUTH_RATIO_BPS;
  if (!Number.isInteger(authRatioBps) || authRatioBps <= 0) {
    throw new Error("initial_auth_ratio_bps must be greater than zero");
  }
  const visibility = md.visibility as RegionVisibility;
  if (visibility !== "public" && visibility !== "private") {
    throw new Error(`invalid region visibility: ${md.visibility}`);
  }
  const creatorPublicKey = md.creator_public_key;
  const triggerEventHash = md.trigger_event_hash;
  const creationProofHash = md.creation_proof_hash;
  if (!creatorPublicKey || !triggerEventHash || !creationProofHash) {
    throw new Error("missing creator_public_key, trigger_event_hash, or creation_proof_hash");
  }

  const metadata: Record<string, string> = {};
  for (const [k, v] of Object.entries(md)) {
    if (k.startsWith("meta:")) {
      metadata[k.slice(5)] = v;
    }
  }

  return {
    region_id: event.entity_id,
    region_root: event.event_hash,
    region_name: regionName,
    normalized_name: normalizedName,
    region_prefix: md.region_prefix?.trim() ? md.region_prefix : null,
    suggested_title: md.suggested_title?.trim() ? md.suggested_title : null,
    visibility,
    section,
    auth_ratio_bps: authRatioBps,
    creator_public_key: creatorPublicKey,
    trigger_event_hash: triggerEventHash,
    creation_proof_hash: creationProofHash,
    access_key_hash: md.access_key_hash?.trim() ? md.access_key_hash : null,
    created_at_ms: event.timestamp,
    updated_at_ms: event.timestamp,
    version: 1,
    metadata,
  };
}

export function canonicalCoreRoot(core: CoreState): string {
  const regionsSorted: Record<string, string> = {};
  for (const regionId of Object.keys(core.regions).sort()) {
    regionsSorted[regionId] = sortedJsonStringify(
      core.regions[regionId] as unknown as Record<string, unknown>,
    );
  }
  const payload = {
    region_count: String(Object.keys(core.regions).length),
    regions: JSON.stringify(regionsSorted),
    total_auth_ratio_bps: String(core.total_auth_ratio_bps),
    version: String(core.version),
  };
  return blake3Hex(Buffer.from(sortedJsonStringify(payload), "utf8"));
}

export function createEmptyCoreState(): CoreState {
  const core: CoreState = {
    regions: {},
    total_auth_ratio_bps: 0,
    core_root: "",
    version: 0,
  };
  core.core_root = canonicalCoreRoot(core);
  return core;
}

export function insertRegionIntoCore(core: CoreState, region: RegionState): void {
  if (core.regions[region.region_id]) {
    throw new Error(`region already exists in core: ${region.region_id}`);
  }
  core.total_auth_ratio_bps += region.auth_ratio_bps;
  core.regions[region.region_id] = region;
  core.version += 1;
  core.core_root = canonicalCoreRoot(core);
}

export function authorizeRegionAccess(region: RegionState, accessKey?: string | null): boolean {
  if (region.visibility === "public") return true;
  if (!region.access_key_hash || !accessKey) return false;
  return blake3Hex(accessKey) === region.access_key_hash;
}
