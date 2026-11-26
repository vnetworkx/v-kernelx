import { sortedJsonStringify } from "./serialization.ts";
import { computeDrainDistribution, DEFAULT_AUTH_RATIO_THRESHOLD, DEFAULT_TRANSFER_DRAIN_BPS } from "./token.ts";
import type { CertificationState, VectorStateV1 } from "./types.ts";

export const VECTOR_ORIGIN_OP = "VECTOR_ORIGIN_CREATE";
export const VECTOR_TRANSPORT_OP = "VECTOR_TRANSPORT";
export const VECTOR_TRANSFER_OP = "VECTOR_TRANSFER";
export const VECTOR_PROJECT_OP = "VECTOR_PROJECT";
export const VECTOR_RECONSTRUCT_OP = "VECTOR_RECONSTRUCT";
export const VECTOR_CERTIFY_OP = "VECTOR_CERTIFY";
export const VECTOR_DRAIN_OP = "VECTOR_DRAIN";

export const DEFAULT_QUORUM_BPS = 6667; // >= 2/3 BFT supermajority

export interface DirectionShare {
  index: number;
  label: string;
  value: number;
  share_bps: number;
}

export interface ValidatorNode {
  node_id: string;
  public_key_hex: string;
  label: string;
  weight: number;
  active: boolean;
  joined_at_ms: number;
}

export interface EventAttestation {
  event_hash: string;
  validator_id: string;
  validator_pubkey: string;
  vote_accept: boolean;
  state_root_hash: string;
  signature: string;
  timestamp_ms: number;
}

export interface ConsensusRound {
  event_hash: string;
  total_weight: number;
  approving_weight: number;
  quorum_threshold_bps: number;
  finalized: boolean;
  attestations: EventAttestation[];
}

export function vectorMagnitude(components: number[]): number {
  return components.reduce((acc, v) => acc + v, 0);
}

export function computeDirectionShares(
  components: number[],
  dimensionLabels?: string[],
): DirectionShare[] {
  const mag = vectorMagnitude(components);
  return components.map((value, index) => ({
    index,
    label: dimensionLabels?.[index]?.trim() || `D${index}`,
    value,
    share_bps: mag > 0 ? Math.round((value * 10_000) / mag) : 0,
  }));
}

export function computeVectorAuthRatio(
  state: Pick<VectorStateV1, "components" | "ownerPubkey" | "vectorId" | "spaceId">,
  ownershipVerified: boolean,
  structureVerified: boolean,
): number {
  const mag = vectorMagnitude(state.components);
  const magnitudeScore = mag === 0 ? 100 : 400;
  const directionScore = state.components.length === 0 ? 0 : 200;
  const ownershipScore = ownershipVerified ? 300 : 0;
  const structureScore = structureVerified ? 100 : 0;
  return Math.min(1000, magnitudeScore + directionScore + ownershipScore + structureScore);
}

export function buildCertificationState(
  state: Pick<VectorStateV1, "components" | "ownerPubkey" | "vectorId" | "spaceId">,
  ownershipVerified: boolean,
  structureVerified: boolean,
  threshold = DEFAULT_AUTH_RATIO_THRESHOLD,
): CertificationState {
  const authRatio = computeVectorAuthRatio(state, ownershipVerified, structureVerified);
  const certified = authRatio >= threshold;
  return {
    certified,
    authRatio,
    threshold,
    lastCheckedAtMs: Date.now(),
    reason: certified ? null : `auth_ratio ${authRatio} below threshold ${threshold}`,
  };
}

export function computeMultidimensionalDrainDistribution(
  amounts: number[],
  baseBps = DEFAULT_TRANSFER_DRAIN_BPS,
  authRatio = 1000,
  threshold = DEFAULT_AUTH_RATIO_THRESHOLD,
): {
  baseBps: number;
  effectiveBps: number;
  discounted: boolean;
  totalFees: number[];
  netReceived: number[];
  regionRewards: number[];
  walletRewards: number[];
  tokenRewards: number[];
  networkRewards: number[];
} {
  let effectiveBps = baseBps;
  let discounted = authRatio >= threshold;
  const totalFees: number[] = [];
  const netReceived: number[] = [];
  const regionRewards: number[] = [];
  const walletRewards: number[] = [];
  const tokenRewards: number[] = [];
  const networkRewards: number[] = [];

  for (const val of amounts) {
    if (!Number.isInteger(val) || val < 0) {
      throw new Error("multidimensional transfer components must be non-negative integers");
    }
    const dist = computeDrainDistribution(BigInt(val), baseBps, authRatio, threshold);
    effectiveBps = dist.effectiveBps;
    discounted = dist.discounted;
    totalFees.push(Number(dist.totalFee));
    netReceived.push(Number(dist.netReceived));
    regionRewards.push(Number(dist.regionReward));
    walletRewards.push(Number(dist.walletReward));
    tokenRewards.push(Number(dist.tokenReward));
    networkRewards.push(Number(dist.networkReward));
  }

  return {
    baseBps,
    effectiveBps,
    discounted,
    totalFees,
    netReceived,
    regionRewards,
    walletRewards,
    tokenRewards,
    networkRewards,
  };
}

export function canonicalVectorOpSigningBytes(
  operation: string,
  requestId: string,
  actorPublicKey: string,
  params: Record<string, unknown>,
): Buffer {
  const payload = sortedJsonStringify({
    actor_public_key: actorPublicKey,
    operation,
    params: sortedJsonStringify(params),
    request_id: requestId,
  });
  return Buffer.from(payload, "utf8");
}

export function canonicalAttestationSigningBytes(params: {
  event_hash: string;
  validator_id: string;
  validator_pubkey: string;
  vote_accept: boolean;
  state_root_hash: string;
  timestamp_ms: number;
}): Buffer {
  return Buffer.from(
    sortedJsonStringify({
      event_hash: params.event_hash,
      state_root_hash: params.state_root_hash,
      timestamp_ms: params.timestamp_ms,
      validator_id: params.validator_id,
      validator_pubkey: params.validator_pubkey,
      vote_accept: params.vote_accept,
    }),
    "utf8",
  );
}
