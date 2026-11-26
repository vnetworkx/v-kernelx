import type { DrainPolicyDto, ScopeDrainRateDto, TransferScopeDto } from "@/lib/types";

export function formatTokenUnitsClient(
  rawAmount: string | bigint | null | undefined,
  decimals: number,
): string {
  if (rawAmount === null || rawAmount === undefined || rawAmount === "") return "—";
  try {
    const val = typeof rawAmount === "bigint" ? rawAmount : BigInt(rawAmount);
    if (decimals <= 0) return val.toLocaleString("en-US");
    const base = 10n ** BigInt(decimals);
    const whole = val / base;
    const frac = val % base;
    const fracStr = frac.toString().padStart(decimals, "0");
    return `${whole.toLocaleString("en-US")}.${fracStr}`;
  } catch {
    return String(rawAmount);
  }
}

export function parseDecimalToAtomic(input: string, decimals: number): string {
  const clean = input.trim().replace(/,/g, "");
  if (!clean) {
    throw new Error("Amount is required");
  }
  if (!/^\d+(\.\d+)?$/.test(clean)) {
    throw new Error("Enter a valid positive numeric amount");
  }
  const [wholePart, fracPart = ""] = clean.split(".");
  if (fracPart.length > decimals) {
    throw new Error(`Maximum decimal precision is ${decimals} places`);
  }
  const paddedFrac = fracPart.padEnd(decimals, "0");
  const atomic = BigInt(`${wholePart}${paddedFrac}`);
  if (atomic <= 0n) {
    throw new Error("Amount must be greater than zero");
  }
  return atomic.toString();
}

export function shortenHash(value: string, head = 10, tail = 8): string {
  if (!value || value.length <= head + tail + 3) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

export function formatTimestampMs(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return "—";
  return new Date(ms).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

export function extractOperationLabel(op: unknown): string {
  if (typeof op === "string") return op;
  if (op && typeof op === "object") {
    const typed = op as { type?: string; value?: string };
    if (typed.value) return `${typed.type ?? "Other"}:${typed.value}`;
    if (typed.type) return typed.type;
  }
  return "Unknown";
}

export function deriveTransferScopeClient(
  fromWallet?: { wallet_id: string; region_id?: string | null; space_id?: string | null } | null,
  toWallet?: { wallet_id: string; region_id?: string | null; space_id?: string | null } | null,
): TransferScopeDto | null {
  if (!fromWallet || !toWallet) return null;
  if (fromWallet.wallet_id === toWallet.wallet_id) return "SAME_WALLET";
  if (
    fromWallet.region_id &&
    toWallet.region_id &&
    fromWallet.region_id === toWallet.region_id
  ) {
    return "DIFFERENT_WALLETS_SAME_REGION";
  }
  if (
    fromWallet.space_id &&
    toWallet.space_id &&
    fromWallet.space_id === toWallet.space_id
  ) {
    return "DIFFERENT_REGIONS_SAME_SPACE";
  }
  return "DIFFERENT_SPACES";
}

export function resolveScopeDrainBps(
  policy: DrainPolicyDto | null | undefined,
  scope: TransferScopeDto | null | undefined,
): number | null {
  if (!policy || !scope) return null;
  let rate: ScopeDrainRateDto | undefined;
  switch (scope) {
    case "SAME_WALLET":
      rate = policy.same_wallet;
      break;
    case "DIFFERENT_WALLETS_SAME_REGION":
      rate = policy.different_wallets_same_region;
      break;
    case "DIFFERENT_REGIONS_SAME_SPACE":
      rate = policy.different_regions_same_space;
      break;
    case "DIFFERENT_SPACES":
      rate = policy.different_spaces;
      break;
  }
  if (!rate || rate.status !== "CONFIGURED_BPS") return null;
  return Number.isFinite(rate.bps) && rate.bps >= 0 && rate.bps <= 10_000 ? rate.bps : null;
}

export function previewDrainClient(
  atomicAmountStr: string,
  baseBps: number | null | undefined,
  authRatio: number | null | undefined,
  threshold = 700,
): {
  effectiveBps: number;
  discounted: boolean;
  totalFee: bigint;
  netReceived: bigint;
  regionReward: bigint;
  walletReward: bigint;
  tokenReward: bigint;
  networkReward: bigint;
} | null {
  if (
    baseBps == null ||
    !Number.isFinite(baseBps) ||
    baseBps < 0 ||
    baseBps > 10_000 ||
    authRatio == null ||
    !Number.isFinite(authRatio)
  ) {
    return null;
  }
  const amount = BigInt(atomicAmountStr || "0");
  const discounted = authRatio >= threshold;
  const effectiveBps = discounted ? Math.floor(baseBps / 2) : baseBps;
  const totalFee = (amount * BigInt(effectiveBps)) / 10_000n;
  const netReceived = amount - totalFee;
  const quarter = totalFee / 4n;
  const networkReward = totalFee - quarter * 3n;
  return {
    effectiveBps,
    discounted,
    totalFee,
    netReceived,
    regionReward: quarter,
    walletReward: quarter,
    tokenReward: quarter,
    networkReward,
  };
}
