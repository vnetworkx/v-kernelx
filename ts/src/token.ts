import { blake3Hex } from "./crypto.ts";
import { sortedJsonStringify } from "./serialization.ts";

export const U128_MAX = (1n << 128n) - 1n;

export const TOKEN_CREATE_OP = "TOKEN_CREATE";
export const TOKEN_TRANSPORT_OP = "TOKEN_TRANSPORT";
/** @deprecated Historical replay compatibility alias only. Use TOKEN_TRANSPORT_OP for all new operations. */
export const TOKEN_MINT_OP = "TOKEN_MINT";
export const TOKEN_BURN_OP = "TOKEN_BURN";
export const TOKEN_TRANSFER_OP = "TOKEN_TRANSFER";

export const DEFAULT_TRANSFER_DRAIN_BPS = 200; // 2.00% base transfer drain (halved to 1.00% when auth_ratio >= 700)
export const DEFAULT_AUTH_RATIO_THRESHOLD = 700;

export interface TokenDefinition {
  token_id: string;
  name: string;
  symbol: string;
  region_id: string;
  decimals: number;
  max_supply: string; // u128 decimal string (reserve capacity)
  total_supply: string; // u128 decimal string (circulating)
  minted_supply: string; // legacy alias synced with transported_supply
  transported_supply?: string; // u128 decimal string
  burned_supply: string; // u128 decimal string
  drained_fees_collected?: string; // u128 cumulative drain fees routed to creators/network
  drain_bps?: number; // base drain bps (default 200)
  authority_pubkey: string;
  supply_policy: string;
  token_type: string;
  created_at_ms: number;
  updated_at_ms: number;
  version: number;
}

export interface TokenBalance {
  token_id: string;
  wallet_id: string;
  owner_pubkey: string;
  balance: string; // u128 decimal string
  updated_at_ms: number;
  version: number;
}

export type BeneficiaryRole =
  | "region_creator"
  | "wallet_creator"
  | "token_creator"
  | "network_pool";

export interface DrainRewardRecord {
  reward_id: string;
  tx_request_id: string;
  token_id: string | null;
  vector_id: string | null;
  beneficiary_role: BeneficiaryRole;
  wallet_id: string;
  amount: string;
  dimension_amounts?: string[];
  timestamp_ms: number;
}

export interface DrainFeeBreakdown {
  base_bps: number;
  effective_bps: number;
  auth_ratio: number;
  threshold: number;
  discounted: boolean;
  total_fee: string;
  net_received: string;
  region_creator_reward: string;
  wallet_creator_reward: string;
  token_creator_reward: string;
  network_reward: string;
}

export interface TokenCreateRequest {
  request_id: string;
  name: string;
  symbol: string;
  region_id: string;
  decimals: number;
  max_supply: string;
  supply_policy: string;
  token_type?: string;
  drain_bps?: number;
  authority_pubkey: string;
  signature: string;
}

export interface TokenTransportRequest {
  request_id: string;
  token_id: string;
  to_wallet_id: string;
  amount: string;
  actor_public_key: string;
  signature: string;
}

export type TokenMintRequest = TokenTransportRequest;

export interface TokenBurnRequest {
  request_id: string;
  token_id: string;
  from_wallet_id: string;
  amount: string;
  actor_public_key: string;
  signature: string;
}

export interface TokenTransferRequest {
  request_id: string;
  token_id: string;
  from_wallet_id: string;
  to_wallet_id: string;
  amount: string;
  actor_public_key: string;
  signature: string;
}

export function parseU128(raw: string | number | bigint, label = "amount"): bigint {
  const str = String(raw).trim();
  if (!/^\d+$/.test(str)) {
    throw new Error(`${label} must be an unsigned integer string`);
  }
  const value = BigInt(str);
  if (value < 0n || value > U128_MAX) {
    throw new Error(`${label} out of u128 bounds`);
  }
  return value;
}

export function checkedAddU128(a: bigint, b: bigint, label = "value"): bigint {
  const sum = a + b;
  if (sum > U128_MAX) {
    throw new Error(`${label} u128 addition overflow`);
  }
  return sum;
}

export function checkedSubU128(a: bigint, b: bigint, label = "value"): bigint {
  if (b > a) {
    throw new Error(`${label}: insufficient balance`);
  }
  return a - b;
}

export function deriveTokenId(
  regionId: string,
  symbol: string,
  authorityPubkey: string,
): string {
  const payload = sortedJsonStringify({
    authority_pubkey: authorityPubkey,
    region_id: regionId,
    symbol: symbol.trim().toUpperCase(),
  });
  const digest = blake3Hex(
    Buffer.concat([Buffer.from("v-kernelx/token-v1:", "utf8"), Buffer.from(payload, "utf8")]),
  );
  return `tkn_${digest.slice(0, 24)}`;
}

export function canonicalTokenRequestSigningBytes(
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

export function computeDrainDistribution(
  amount: bigint,
  baseBps = DEFAULT_TRANSFER_DRAIN_BPS,
  authRatio = 1000,
  threshold = DEFAULT_AUTH_RATIO_THRESHOLD,
): {
  baseBps: number;
  effectiveBps: number;
  discounted: boolean;
  totalFee: bigint;
  netReceived: bigint;
  regionReward: bigint;
  walletReward: bigint;
  tokenReward: bigint;
  networkReward: bigint;
} {
  if (!Number.isInteger(baseBps) || baseBps < 0 || baseBps > 10_000) {
    throw new Error("drain_bps must be an integer between 0 and 10000");
  }
  const discounted = authRatio >= threshold;
  const effectiveBps = discounted ? Math.floor(baseBps / 2) : baseBps;
  const totalFee = (amount * BigInt(effectiveBps)) / 10_000n;
  const netReceived = amount - totalFee;
  const quarter = totalFee / 4n;
  const rem = totalFee - quarter * 3n;

  return {
    baseBps,
    effectiveBps,
    discounted,
    totalFee,
    netReceived,
    regionReward: quarter,
    walletReward: quarter,
    tokenReward: quarter,
    networkReward: rem,
  };
}

export function formatTokenUnits(amountStr: string, decimals: number): string {
  const amount = parseU128(amountStr, "amount");
  if (decimals === 0) return amount.toString();
  const base = 10n ** BigInt(decimals);
  const whole = amount / base;
  const frac = (amount % base).toString().padStart(decimals, "0").replace(/0+$/, "");
  return frac.length > 0 ? `${whole}.${frac}` : `${whole}`;
}
