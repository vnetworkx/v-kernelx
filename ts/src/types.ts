export const STATE_SCHEMA_V1 = "v.kernelx/VectorStateV1" as const;

export type VectorType = "Standard" | "Origin" | "Projected" | "Escrow" | "Settlement" | "Locked";
export type VectorStatus = "Active" | "Projected" | "Escrowed" | "Settled" | "Archived";
export type OperationKind = "OriginCreate" | "Transfer" | "Drain" | "Project" | "Reconstruct" | "Certify" | "Query" | "Custom";

export interface CertificationState {
  certified: boolean;
  authRatio: number;
  threshold: number;
  lastCheckedAtMs: number;
  reason?: string | null;
}

export interface ProjectionState {
  escrowId: string;
  projectedComponents: number[];
  settledComponents: number[];
  startedAtMs: number;
  settlementAtMs?: number | null;
  outcomeTag?: string | null;
}

export interface OriginState {
  seed: string;
  nonce: number;
  difficulty: number;
  proofHash: string;
}

export interface VectorStateV1 {
  schema: typeof STATE_SCHEMA_V1;
  vectorId: string;
  ownerPubkey: string;
  spaceId: string;
  vectorType: VectorType;
  status: VectorStatus;
  components: number[];
  typeMetadata: Record<string, string>;
  certification: CertificationState;
  projection?: ProjectionState | null;
  origin?: OriginState | null;
  version: number;
  createdAtMs: number;
  updatedAtMs: number;
}

export interface VectorRecordV1 {
  schema: "v.kernelx/VectorRecordV1";
  recordId: string;
  vectorId: string;
  before?: VectorStateV1 | null;
  after: VectorStateV1;
  operation: OperationKind;
  parameters: unknown;
  certification: CertificationState;
  timestampMs: number;
  proof: string;
}

export interface SimulationReport {
  vectors: VectorStateV1[];
  records: VectorRecordV1[];
}
