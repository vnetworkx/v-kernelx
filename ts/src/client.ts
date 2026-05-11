import type {
  CertificationState,
  OriginState,
  ProjectionState,
  VectorRecordV1,
  VectorStateV1,
  VectorStatus,
  VectorType,
  SimulationReport,
} from "./types.ts";
import { STATE_SCHEMA_V1 } from "./types.ts";
import { createHash } from "node:crypto";

const now = () => Date.now();
const hash = (input: string): string => createHash("sha256").update(input).digest("hex");

export function findValidNonce(seed: string, difficulty: number, maxAttempts = 1_000_000): number | null {
  if (difficulty <= 0) return 0;
  for (let nonce = 0; nonce < maxAttempts; nonce += 1) {
    const proof = hash(`${seed}:${nonce}`);
    const leadingZeros = proof.match(/^0*/)?.[0].length ?? 0;
    if (leadingZeros >= difficulty) return nonce;
  }
  return null;
}

export class VectorKernelX {
  private states = new Map<string, VectorStateV1>();
  private records = new Map<string, VectorRecordV1>();

  private certifyState(state: VectorStateV1): CertificationState {
    const authRatio = state.ownerPubkey ? 1000 : 0;
    const certified = authRatio >= state.certification.threshold;
    return {
      certified,
      authRatio,
      threshold: state.certification.threshold,
      lastCheckedAtMs: now(),
      reason: certified ? null : "below threshold",
    };
  }

  newVector(vectorId: string, ownerPubkey: string, spaceId: string, components: number[], vectorType: VectorType = "Standard"): VectorStateV1 {
    const timestamp = now();
    return {
      schema: STATE_SCHEMA_V1,
      vectorId,
      ownerPubkey,
      spaceId,
      vectorType,
      status: "Active",
      components: [...components],
      typeMetadata: {},
      certification: {
        certified: false,
        authRatio: 0,
        threshold: 700,
        lastCheckedAtMs: timestamp,
        reason: "not yet certified",
      },
      projection: null,
      origin: null,
      version: 1,
      createdAtMs: timestamp,
      updatedAtMs: timestamp,
    };
  }

  magnitude(state: VectorStateV1): number {
    return state.components.reduce((a, b) => a + b, 0);
  }

  isZero(state: VectorStateV1): boolean {
    return state.components.every((x) => x === 0);
  }

  directionShares(state: VectorStateV1) {
    const m = this.magnitude(state);
    if (m === 0) throw new Error("zero vector cannot be normalized");
    return state.components.map((c, i) => ({ componentIndex: i, numerator: c, denominator: m }));
  }

  originCreate(vectorId: string, ownerPubkey: string, spaceId: string, components: number[], seed: string, nonce: number, difficulty: number): VectorStateV1 {
    const proof = hash(`${seed}:${nonce}`);
    const state = this.newVector(vectorId, ownerPubkey, spaceId, components, "Origin");
    const leadingZeros = proof.match(/^0*/)?.[0].length ?? 0;
    if (leadingZeros < difficulty) {
      throw new Error("origin proof rejected");
    }
    state.origin = { seed, nonce, difficulty, proofHash: proof };
    state.certification = this.certifyState(state);
    this.states.set(vectorId, state);
    this.record(null, state, "OriginCreate", { difficulty });
    return state;
  }

  transfer(fromId: string, toId: string, amount: number[]): [VectorStateV1, VectorStateV1] {
    const from = this.states.get(fromId);
    const to = this.states.get(toId);
    if (!from || !to) throw new Error("vector not found");
    if (from.components.length !== to.components.length || from.components.length !== amount.length) throw new Error("dimension mismatch");
    if (amount.some((a, i) => a > from.components[i])) throw new Error("insufficient balance");
    const beforeFrom = structuredClone(from);
    const beforeTo = structuredClone(to);

    from.components = from.components.map((c, i) => c - amount[i]);
    to.components = to.components.map((c, i) => c + amount[i]);
    from.certification = this.certifyState(from);
    to.certification = this.certifyState(to);
    this.states.set(fromId, from);
    this.states.set(toId, to);
    this.record(beforeFrom, from, "Transfer", { direction: "out", amount });
    this.record(beforeTo, to, "Transfer", { direction: "in", amount });
    return [from, to];
  }

  drain(vectorId: string, basisPoints: number): VectorStateV1 {
    const state = this.states.get(vectorId);
    if (!state) throw new Error("vector not found");
    if (basisPoints > 10_000) throw new Error("drain too large");
    const discount = state.certification.authRatio >= state.certification.threshold ? Math.floor(basisPoints / 2) : basisPoints;
    state.components = state.components.map((c) => c - Math.floor((c * discount) / 10_000));
    state.certification = this.certifyState(state);
    state.updatedAtMs = now();
    state.version += 1;
    this.states.set(vectorId, state);
    this.record(null, state, "Drain", { basisPoints });
    return state;
  }

  project(vectorId: string, projectedComponents: number[], escrowId: string): VectorStateV1 {
    const state = this.states.get(vectorId);
    if (!state) throw new Error("vector not found");
    if (projectedComponents.length !== state.components.length) throw new Error("dimension mismatch");
    if (projectedComponents.some((p, i) => p > state.components[i])) throw new Error("insufficient balance");
    state.components = state.components.map((c, i) => c - projectedComponents[i]);
    state.vectorType = "Projected";
    state.status = "Projected";
    state.projection = {
      escrowId,
      projectedComponents: [...projectedComponents],
      settledComponents: [],
      startedAtMs: now(),
      settlementAtMs: null,
      outcomeTag: null,
    };
    state.certification = this.certifyState(state);
    this.states.set(vectorId, state);
    this.record(null, state, "Project", { escrowId, projectedComponents });
    return state;
  }

  reconstruct(vectorId: string, gains: number[], losses: number[], outcomeTag = "settled"): VectorStateV1 {
    const state = this.states.get(vectorId);
    if (!state || !state.projection) throw new Error("missing projection");
    if (gains.length !== losses.length || gains.length !== state.projection.projectedComponents.length) throw new Error("dimension mismatch");
    const settled = state.projection.projectedComponents.map((principal, i) => {
      const value = principal + gains[i] - losses[i];
      if (value < 0) throw new Error("settlement rejected");
      return value;
    });
    state.components = state.components.map((c, i) => c + settled[i]);
    state.projection.settledComponents = settled;
    state.projection.settlementAtMs = now();
    state.projection.outcomeTag = outcomeTag;
    state.vectorType = "Settlement";
    state.status = "Settled";
    state.certification = this.certifyState(state);
    this.states.set(vectorId, state);
    this.record(null, state, "Reconstruct", { outcomeTag });
    return state;
  }

  certify(vectorId: string): VectorStateV1 {
    const state = this.states.get(vectorId);
    if (!state) throw new Error("vector not found");
    state.certification = this.certifyState(state);
    this.states.set(vectorId, state);
    this.record(null, state, "Certify", {});
    return state;
  }

  query(vectorId: string): VectorStateV1 | undefined {
    return this.states.get(vectorId);
  }

  queryVectors(): VectorStateV1[] {
    return [...this.states.values()];
  }

  queryRecords(): VectorRecordV1[] {
    return [...this.records.values()];
  }

  execute(script: string): string[] {
    const out: string[] = [];
    for (const raw of script.split("\n")) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      const [opcode, ...rest] = line.split(" ");
      const params = JSON.parse(rest.join(" ") || "{}");
      switch (opcode.toUpperCase()) {
        case "ORIGIN":
        case "ORIGIN_CREATE":
          out.push(`origin:${this.originCreate(params.vectorId, params.ownerPubkey, params.spaceId ?? "default", params.components ?? [], params.seed ?? "", params.nonce ?? 0, params.difficulty ?? 1).vectorId}`);
          break;
        case "TRANSFER":
          this.transfer(params.from, params.to, params.amount ?? []);
          out.push("transfer");
          break;
        case "DRAIN":
          this.drain(params.vectorId, params.basisPoints ?? 0);
          out.push("drain");
          break;
        case "PROJECT":
          this.project(params.vectorId, params.projectedComponents ?? [], params.escrowId ?? "escrow");
          out.push("project");
          break;
        case "RECONSTRUCT":
          this.reconstruct(params.vectorId, params.gains ?? [], params.losses ?? [], params.outcomeTag ?? "settled");
          out.push("reconstruct");
          break;
        case "CERTIFY":
          this.certify(params.vectorId);
          out.push("certify");
          break;
        case "QUERY":
          out.push(JSON.stringify(this.query(params.vectorId) ?? null));
          break;
        default:
          throw new Error(`unknown opcode ${opcode}`);
      }
    }
    return out;
  }

  private record(before: VectorStateV1 | null, after: VectorStateV1, operation: string, parameters: unknown) {
    const recordId = hash(JSON.stringify([after.vectorId, operation, before, after, parameters]));
    const payload = JSON.stringify([recordId, after.vectorId, before, after, operation, parameters, after.certification, now()]);
    const proof = hash(payload);
    const record: VectorRecordV1 = {
      schema: "v.kernelx/VectorRecordV1",
      recordId,
      vectorId: after.vectorId,
      before,
      after,
      operation: operation as any,
      parameters,
      certification: after.certification,
      timestampMs: now(),
      proof,
    };
    this.records.set(recordId, record);
  }
}
