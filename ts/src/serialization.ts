import { blake3Hex } from "./crypto.ts";

export type CanonicalOperationType =
  | { type: "OriginCreate" }
  | { type: "Certify" }
  | { type: "Transfer" }
  | { type: "Drain" }
  | { type: "Project" }
  | { type: "Reconstruct" }
  | { type: "Move" }
  | { type: "Rotate" }
  | { type: "Scale" }
  | { type: "Normalize" }
  | { type: "Constrain" }
  | { type: "Query" }
  | { type: "Record" }
  | { type: "Other"; value: string };

export interface CanonicalVectorState {
  components: string[]; // u64 decimal strings or numeric strings
  owner_public_key: string;
  type_tag: string;
  metadata: Record<string, string>;
}

export interface CanonicalVectorEvent {
  event_id: string;
  parent_hashes: string[];
  region_id: string;
  entity_id: string;
  operation: CanonicalOperationType;
  vector_before: CanonicalVectorState;
  vector_after: CanonicalVectorState;
  auth_ratio: number;
  certified: boolean;
  actor_public_key: string;
  logical_clock: number;
  timestamp: number;
  payload_hash: string;
  event_hash: string;
  signature: string;
}

export interface CanonicalStateRoot {
  root_hash: string;
  event_count: number;
  logical_clock: number;
}

export interface CanonicalSnapshot {
  snapshot_id: string;
  state_root: CanonicalStateRoot;
  event_root: string;
  replay_hash: string;
  event_count: number;
  logical_clock: number;
  dag_heads: string[];
  state_bytes_hex: string;
  created_at: number;
}

class ByteWriter {
  private chunks: Buffer[] = [];

  writeU8(v: number): void {
    const b = Buffer.allocUnsafe(1);
    b.writeUInt8(v & 0xff, 0);
    this.chunks.push(b);
  }

  writeBool(v: boolean): void {
    this.writeU8(v ? 1 : 0);
  }

  writeU32(v: number): void {
    const b = Buffer.allocUnsafe(4);
    b.writeUInt32BE(v >>> 0, 0);
    this.chunks.push(b);
  }

  writeU64(v: number | bigint): void {
    const n = BigInt(v);
    const b = Buffer.allocUnsafe(8);
    b.writeBigUInt64BE(n, 0);
    this.chunks.push(b);
  }

  writeF64(v: number): void {
    const b = Buffer.allocUnsafe(8);
    b.writeDoubleBE(v, 0);
    this.chunks.push(b);
  }

  writeStr(v: string): void {
    const bytes = Buffer.from(v, "utf8");
    this.writeU64(bytes.length);
    this.chunks.push(bytes);
  }

  writeBytes(bytes: Uint8Array): void {
    this.writeU64(bytes.length);
    this.chunks.push(Buffer.from(bytes));
  }

  writeVecStr(values: string[]): void {
    this.writeU64(values.length);
    for (const v of values) {
      this.writeStr(v);
    }
  }

  writeSortedMapStrStr(map: Record<string, string>): void {
    const keys = Object.keys(map).sort();
    this.writeU64(keys.length);
    for (const k of keys) {
      this.writeStr(k);
      this.writeStr(map[k] ?? "");
    }
  }

  writeVecU64(values: Array<string | number | bigint>): void {
    this.writeU64(values.length);
    for (const v of values) {
      this.writeU64(BigInt(v));
    }
  }

  toBuffer(): Buffer {
    return Buffer.concat(this.chunks);
  }
}

export function operationCanonicalName(op: CanonicalOperationType): string {
  switch (op.type) {
    case "OriginCreate":
      return "ORIGIN_CREATE";
    case "Certify":
      return "CERTIFY";
    case "Transfer":
      return "TRANSFER";
    case "Drain":
      return "DRAIN";
    case "Project":
      return "PROJECT";
    case "Reconstruct":
      return "RECONSTRUCT";
    case "Move":
      return "MOVE";
    case "Rotate":
      return "ROTATE";
    case "Scale":
      return "SCALE";
    case "Normalize":
      return "NORMALIZE";
    case "Constrain":
      return "CONSTRAIN";
    case "Query":
      return "QUERY";
    case "Record":
      return "RECORD";
    case "Other":
      return "OTHER";
  }
}

export function canonicalEventId(
  entityId: string,
  regionId: string,
  operation: CanonicalOperationType,
  logicalClock: number,
  sequence: number,
): string {
  return `${entityId}::${regionId}::${operationCanonicalName(operation)}::${logicalClock}::${sequence}`;
}

export function canonicalOperationBytes(op: CanonicalOperationType): Buffer {
  const w = new ByteWriter();
  if (op.type === "Other") {
    w.writeStr("OTHER");
    w.writeStr(op.value);
  } else {
    w.writeStr(operationCanonicalName(op));
  }
  return w.toBuffer();
}

export function canonicalVectorStateBytes(state: CanonicalVectorState): Buffer {
  const w = new ByteWriter();
  w.writeVecU64(state.components);
  w.writeStr(state.owner_public_key);
  w.writeStr(state.type_tag);
  w.writeSortedMapStrStr(state.metadata);
  return w.toBuffer();
}

export function canonicalEventPayloadBytes(event: CanonicalVectorEvent): Buffer {
  const w = new ByteWriter();
  w.writeStr(event.event_id);
  w.writeVecStr(event.parent_hashes);
  w.writeStr(event.region_id);
  w.writeStr(event.entity_id);
  const opBytes = canonicalOperationBytes(event.operation);
  const beforeBytes = canonicalVectorStateBytes(event.vector_before);
  const afterBytes = canonicalVectorStateBytes(event.vector_after);
  const result = Buffer.concat([w.toBuffer(), opBytes, beforeBytes, afterBytes]);
  const tail = new ByteWriter();
  tail.writeF64(event.auth_ratio);
  tail.writeBool(event.certified);
  tail.writeStr(event.actor_public_key);
  tail.writeU64(event.logical_clock);
  tail.writeU64(event.timestamp);
  return Buffer.concat([result, tail.toBuffer()]);
}

export function canonicalEventBytes(event: CanonicalVectorEvent): Buffer {
  const payload = canonicalEventPayloadBytes(event);
  const tail = new ByteWriter();
  tail.writeStr(event.payload_hash);
  return Buffer.concat([payload, tail.toBuffer()]);
}

export function canonicalPayloadHash(event: CanonicalVectorEvent): string {
  return blake3Hex(canonicalEventPayloadBytes(event));
}

export function canonicalEventHash(event: CanonicalVectorEvent): string {
  return blake3Hex(canonicalEventBytes(event));
}

export function canonicalStateMapBytes(stateMap: Record<string, CanonicalVectorState>): Buffer {
  const keys = Object.keys(stateMap).sort();
  const w = new ByteWriter();
  w.writeU64(keys.length);
  const parts: Buffer[] = [w.toBuffer()];
  for (const key of keys) {
    const kw = new ByteWriter();
    kw.writeStr(key);
    parts.push(kw.toBuffer(), canonicalVectorStateBytes(stateMap[key]));
  }
  return Buffer.concat(parts);
}

export function canonicalBlobBytes(tag: string, payload: Uint8Array): Buffer {
  const w = new ByteWriter();
  w.writeStr(tag);
  w.writeBytes(payload);
  return w.toBuffer();
}

export function canonicalTaggedHash(tag: string, payload: Uint8Array): string {
  return blake3Hex(canonicalBlobBytes(tag, payload));
}

export function canonicalEventSequenceBytes(eventHashes: string[]): Buffer {
  const w = new ByteWriter();
  w.writeU64(eventHashes.length);
  for (const h of eventHashes) {
    w.writeStr(h);
  }
  return w.toBuffer();
}

export function canonicalReplayHash(eventHashes: string[]): string {
  const buf = Buffer.concat([
    canonicalBlobBytes("replay-v1", Buffer.alloc(0)),
    canonicalEventSequenceBytes(eventHashes),
  ]);
  return blake3Hex(buf);
}

export function computeStateRootFromCanonicalBytes(
  canonicalStateBytes: Uint8Array,
  eventCount: number,
  logicalClock: number,
): CanonicalStateRoot {
  const w = new ByteWriter();
  w.writeU64(eventCount);
  w.writeU64(logicalClock);
  w.writeU64(canonicalStateBytes.length);
  const buf = Buffer.concat([
    Buffer.from("v-kernelx/state-root-v1", "utf8"),
    w.toBuffer(),
    Buffer.from(canonicalStateBytes),
  ]);
  return {
    root_hash: blake3Hex(buf),
    event_count: eventCount,
    logical_clock: logicalClock,
  };
}

export function canonicalStateRootHash(root: CanonicalStateRoot): string {
  const w = new ByteWriter();
  w.writeStr(root.root_hash);
  w.writeU64(root.event_count);
  w.writeU64(root.logical_clock);
  return blake3Hex(w.toBuffer());
}

export function sortedJsonStringify(obj: Record<string, unknown>): string {
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    const val = obj[key];
    if (val !== null && typeof val === "object" && !Array.isArray(val)) {
      sorted[key] = JSON.parse(sortedJsonStringify(val as Record<string, unknown>));
    } else {
      sorted[key] = val;
    }
  }
  return JSON.stringify(sorted);
}
