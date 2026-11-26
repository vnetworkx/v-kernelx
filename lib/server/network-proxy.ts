import "server-only";
import type {
  CanonicalEventDto,
  ConsensusRoundDto,
  DrainPolicyDto,
  DrainRewardDto,
  NodeStatusDto,
  RegionDto,
  SnapshotDto,
  TokenBalanceDto,
  TokenDto,
  ValidatorNodeDto,
  VectorRecordDto,
  VectorStateDto,
  VerificationStatus,
  WalletDto,
  WalletReceivePolicyDto,
} from "@/lib/types";

export function getNetworkApiUrl(): string {
  const configured = process.env.VNETWORK_API_URL?.trim();
  if (!configured || configured === "null" || configured === "undefined") {
    return "http://127.0.0.1:8080";
  }
  return configured.replace(/\/+$/, "");
}

export async function fetchNetworkApiJson<T = Record<string, unknown>>(
  endpointPath: string,
): Promise<{ ok: boolean; status: number; data: T | null; error?: string }> {
  const endpoint = getNetworkApiUrl();
  try {
    const res = await fetch(`${endpoint}${endpointPath}`, {
      cache: "no-store",
      signal: AbortSignal.timeout(4000),
    });
    const data = (await res.json().catch(() => null)) as T | null;
    if (!res.ok) {
      return {
        ok: false,
        status: res.status,
        data,
        error:
          (data as Record<string, unknown> | null)?.error?.toString() ??
          `Upstream HTTP ${res.status}`,
      };
    }
    return { ok: true, status: res.status, data };
  } catch (err) {
    return {
      ok: false,
      status: 503,
      data: null,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function postNetworkApiJson<T = Record<string, unknown>>(
  endpointPath: string,
  payload: unknown,
): Promise<{ ok: boolean; status: number; data: T | null; error?: string }> {
  const endpoint = getNetworkApiUrl();
  try {
    const res = await fetch(`${endpoint}${endpointPath}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      cache: "no-store",
      signal: AbortSignal.timeout(8000),
    });
    const data = (await res.json().catch(() => null)) as T | null;
    if (!res.ok) {
      return {
        ok: false,
        status: res.status,
        data,
        error:
          (data as Record<string, unknown> | null)?.error?.toString() ??
          `Upstream HTTP ${res.status}`,
      };
    }
    return { ok: true, status: res.status, data };
  } catch (err) {
    return {
      ok: false,
      status: 503,
      data: null,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function fetchNetworkExplorerSnapshot(): Promise<{
  reachable: boolean;
  endpoint: string;
  data: Record<string, unknown> | null;
  error?: string;
}> {
  const endpoint = getNetworkApiUrl();
  const res = await fetchNetworkApiJson<Record<string, unknown>>("/v1/explorer/network");
  return {
    reachable: res.ok,
    endpoint,
    data: res.ok ? res.data : null,
    error: res.error,
  };
}

export function disconnectedStatusDto(endpoint: string): NodeStatusDto {
  return {
    kernel_version: "vector-network/1.0.0",
    network_name: `unreachable (${endpoint})`,
    network_mode: "disconnected",
    node_id: "offline",
    node_pubkey: "",
    storage_engine: "vnetwork-wal-json",
    db_path: endpoint,
    db_integrity_ok: false,
    wal_consistency_ok: false,
    equivocation_store_ok: false,
    equivocation_count: 0,
    verification_status: "UNKNOWN",
    replay_status: "UNKNOWN",
    key_storage_mode: "unknown",
    vector_count: 0,
    record_count: 0,
    event_count: 0,
    region_count: 0,
    wallet_count: 0,
    token_count: 0,
    validator_count: 0,
    finalized_event_count: 0,
    total_drain_rewards_count: 0,
    state_root: {
      root_hash: "0".repeat(64),
      event_count: 0,
      logical_clock: 0,
    },
    replay_hash: "0".repeat(64),
    replay_verified: false,
  };
}

export interface WorkbenchInitialProps {
  initialStatus: NodeStatusDto;
  initialRegions: RegionDto[];
  initialWallets: WalletDto[];
  initialTokens: TokenDto[];
  initialVectors: VectorStateDto[];
  initialRewards: DrainRewardDto[];
  initialValidators: ValidatorNodeDto[];
  initialRounds: ConsensusRoundDto[];
  initialEvents: CanonicalEventDto[];
  initialRecords: VectorRecordDto[];
  initialSnapshots: SnapshotDto[];
  drainPolicy?: DrainPolicyDto | null;
  coreEventHash: string;
}

function parseReceivePolicy(raw: unknown): WalletReceivePolicyDto | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const r = raw as Record<string, unknown>;
  const mode = String(r.mode ?? "").toUpperCase();
  if (mode === "FROZEN" || mode === "RESTRICTED" || mode === "OPEN") {
    return {
      mode,
      allowed_senders: Array.isArray(r.allowed_senders)
        ? r.allowed_senders.map((s) => String(s))
        : undefined,
    };
  }
  return undefined;
}

function parseVerificationStatus(raw: unknown): VerificationStatus | null {
  const upper = typeof raw === "string" ? raw.trim().toUpperCase() : "";
  if (
    upper === "VERIFIED" ||
    upper === "UNVERIFIED" ||
    upper === "INVALID" ||
    upper === "UNKNOWN" ||
    upper === "PENDING"
  ) {
    return upper;
  }
  return null;
}

function parseBigIntSafe(value: unknown): bigint | null {
  try {
    if (typeof value === "bigint") return value;
    if (typeof value === "number" && Number.isInteger(value) && value >= 0) {
      return BigInt(value);
    }
    if (typeof value === "string" && /^\d+$/.test(value.trim())) {
      return BigInt(value.trim());
    }
    return null;
  } catch {
    return null;
  }
}

export function mapNetworkSnapshotToWorkbenchProps(snapshot: {
  reachable: boolean;
  endpoint: string;
  data: Record<string, unknown> | null;
}): WorkbenchInitialProps {
  if (!snapshot.reachable || !snapshot.data) {
    return {
      initialStatus: disconnectedStatusDto(snapshot.endpoint),
      initialRegions: [],
      initialWallets: [],
      initialTokens: [],
      initialVectors: [],
      initialRewards: [],
      initialValidators: [],
      initialRounds: [],
      initialEvents: [],
      initialRecords: [],
      initialSnapshots: [],
      drainPolicy: null,
      coreEventHash: "",
    };
  }

  const d = snapshot.data;
  const rawStatus = (d.status ?? {}) as Record<string, unknown>;
  const rawHealth = (d.health ?? {}) as Record<string, unknown>;
  const rawProofs = (d.proofs ?? null) as Record<string, unknown> | null;
  const rawReplay = (d.replay ?? null) as Record<string, unknown> | null;
  const rawSupplyBreakdowns = (d.supply_breakdowns ?? {}) as Record<
    string,
    Record<string, unknown>
  >;
  const rawEquivocations = Array.isArray(d.equivocations)
    ? (d.equivocations as Array<Record<string, unknown>>)
    : [];
  const rawDrainPolicy = (d.drain_policy as DrainPolicyDto | null | undefined) ?? null;

  const rawRegions = Array.isArray(d.regions) ? (d.regions as Array<Record<string, unknown>>) : [];
  const rawWallets = Array.isArray(d.wallets) ? (d.wallets as Array<Record<string, unknown>>) : [];
  const rawTokens = Array.isArray(d.tokens) ? (d.tokens as Array<Record<string, unknown>>) : [];
  const rawBalances = Array.isArray(d.balances) ? (d.balances as Array<Record<string, unknown>>) : [];
  const rawEvents = Array.isArray(d.events) ? (d.events as Array<Record<string, unknown>>) : [];
  const rawCerts = Array.isArray(d.certificates) ? (d.certificates as Array<Record<string, unknown>>) : [];
  const rawConsensus = (d.consensus ?? {}) as Record<string, unknown>;
  const rawValidators = Array.isArray(rawConsensus.validators)
    ? (rawConsensus.validators as Array<Record<string, unknown>>)
    : [];

  const stateRoot = String(d.state_root ?? rawStatus.state_root ?? "");
  const replayHash = String(d.replay_hash ?? rawStatus.replay_hash ?? "");
  const eventCount = Number(rawStatus.committed_events ?? rawEvents.length ?? 0);
  const logicalClock = Number(rawStatus.logical_clock ?? 0);

  const storageEngine = String(
    d.storage_engine ?? rawStatus.storage_engine ?? "vnetwork-wal-json",
  );
  const storageOk =
    typeof rawHealth.storage_ok === "boolean"
      ? rawHealth.storage_ok
      : typeof rawStatus.storage_ok === "boolean"
        ? rawStatus.storage_ok
        : false;
  const walConsistencyOk =
    typeof rawHealth.wal_consistency_ok === "boolean"
      ? rawHealth.wal_consistency_ok
      : typeof rawStatus.wal_consistency_ok === "boolean"
        ? rawStatus.wal_consistency_ok
        : false;
  const equivocationStoreOk =
    typeof rawHealth.equivocation_store_ok === "boolean"
      ? rawHealth.equivocation_store_ok
      : typeof rawStatus.equivocation_store_ok === "boolean"
        ? rawStatus.equivocation_store_ok
        : false;
  const equivocationCount =
    typeof rawHealth.equivocation_count === "number"
      ? rawHealth.equivocation_count
      : typeof rawConsensus.equivocation_count === "number"
        ? rawConsensus.equivocation_count
        : rawEquivocations.length;

  const dbIntegrityOk = storageOk && walConsistencyOk && equivocationStoreOk;

  let replayVerified = false;
  let replayStatus: VerificationStatus = "UNVERIFIED";
  if (rawReplay && typeof rawReplay.valid === "boolean") {
    const stateMatch =
      rawReplay.replayed_state_root === rawReplay.live_state_root &&
      rawReplay.replayed_replay_hash === rawReplay.live_replay_hash;
    const chainOk = rawProofs ? rawProofs.chain_valid === true : true;
    replayVerified = rawReplay.valid === true && stateMatch && chainOk;
    replayStatus = replayVerified ? "VERIFIED" : "INVALID";
  } else if (rawProofs && typeof rawProofs.chain_valid === "boolean") {
    replayStatus = rawProofs.chain_valid ? "UNVERIFIED" : "INVALID";
  }

  let verificationStatus: VerificationStatus =
    parseVerificationStatus(rawHealth.verification_status) ?? "UNVERIFIED";
  if (!dbIntegrityOk || replayStatus === "INVALID" || equivocationCount > 0) {
    verificationStatus =
      !storageOk || !walConsistencyOk || !equivocationStoreOk || replayStatus === "INVALID" || equivocationCount > 0
        ? "INVALID"
        : "UNVERIFIED";
  } else if (dbIntegrityOk && replayVerified && equivocationCount === 0) {
    verificationStatus = "VERIFIED";
  } else if (verificationStatus === "VERIFIED" && !replayVerified) {
    verificationStatus = "UNVERIFIED";
  }

  const initialStatus: NodeStatusDto = {
    kernel_version: "vector-network/1.0.0",
    network_name: String(rawStatus.network_id ?? "vector-network"),
    network_mode: String(rawStatus.profile ?? "DEVELOPMENT"),
    node_id: String(rawStatus.node_id ?? ""),
    node_pubkey: String(rawHealth.node_pubkey ?? ""),
    storage_engine: storageEngine,
    db_path: snapshot.endpoint,
    db_integrity_ok: dbIntegrityOk,
    wal_consistency_ok: walConsistencyOk,
    equivocation_store_ok: equivocationStoreOk,
    equivocation_count: equivocationCount,
    verification_status: verificationStatus,
    replay_status: replayStatus,
    key_storage_mode:
      typeof rawHealth.key_storage_mode === "string" ? rawHealth.key_storage_mode : undefined,
    vector_count: rawTokens.length,
    record_count: rawEvents.length,
    event_count: eventCount,
    region_count: rawRegions.length,
    wallet_count: rawWallets.length,
    token_count: rawTokens.length,
    validator_count: rawValidators.length || Number(rawStatus.active_validators ?? 0),
    finalized_event_count: rawCerts.length,
    total_drain_rewards_count: 0,
    state_root: {
      root_hash: stateRoot,
      event_count: eventCount,
      logical_clock: logicalClock,
    },
    replay_hash: replayHash,
    replay_verified: replayVerified,
  };

  const initialRegions: RegionDto[] = rawRegions.map((r) => ({
    region_id: String(r.region_id ?? ""),
    region_root: String(r.space_id ?? ""),
    region_name: String(r.name ?? ""),
    normalized_name: String(r.name ?? "").toLowerCase(),
    region_prefix: (r.prefix as string | null) ?? null,
    suggested_title: (r.title as string | null) ?? null,
    visibility: String(r.visibility ?? "PUBLIC").toLowerCase() === "private" ? "private" : "public",
    section: Number(r.section ?? 1),
    auth_ratio_bps: Number(r.auth_ratio_bps ?? 10000),
    creator_public_key: String(r.creator_pubkey ?? ""),
    trigger_event_hash: String(rawEvents[0]?.event_hash ?? ""),
    creation_proof_hash: "",
    access_key_hash: null,
    created_at_ms: Number(r.created_at_ms ?? 0),
    updated_at_ms: Number(r.created_at_ms ?? 0),
    version: Number(r.version ?? 1),
    metadata: { space_id: String(r.space_id ?? "") },
  }));

  const initialWallets: WalletDto[] = rawWallets.map((w) => {
    const wid = String(w.wallet_id ?? "");
    const wBals = rawBalances
      .filter((b) => String(b.wallet_id ?? "") === wid)
      .map((b) => ({
        token_id: String(b.token_id ?? ""),
        wallet_id: wid,
        owner_pubkey: String(w.owner_pubkey ?? ""),
        balance: String((b.vector as Record<string, unknown> | undefined)?.token ?? "0"),
        updated_at_ms: Number(b.updated_at_ms ?? 0),
        version: Number(b.version ?? 1),
      }));
    return {
      wallet_id: wid,
      public_key_hex: String(w.owner_pubkey ?? ""),
      label: String(w.name ?? wid),
      region_id: (w.region_id as string | null) ?? null,
      space_id: (w.space_id as string | null) ?? null,
      creator_wallet_id: null,
      receive_policy: parseReceivePolicy(w.receive_policy),
      created_at_ms: Number(w.created_at_ms ?? 0),
      auth_ratio: 1000,
      balances: wBals,
      rewards: [],
    };
  });

  const walletIdSet = new Set(initialWallets.map((w) => w.wallet_id));
  const initialTokens: TokenDto[] = rawTokens.map((t) => {
    const tid = String(t.token_id ?? "");
    const tBals: TokenBalanceDto[] = rawBalances
      .filter((b) => String(b.token_id ?? "") === tid)
      .map((b) => ({
        token_id: tid,
        wallet_id: String(b.wallet_id ?? ""),
        owner_pubkey: "",
        balance: String((b.vector as Record<string, unknown> | undefined)?.token ?? "0"),
        updated_at_ms: Number(b.updated_at_ms ?? 0),
        version: Number(b.version ?? 1),
      }));

    const totalSupplyStr = String(t.total_supply ?? "0");
    const initialTokenVal = (t.initial_vector as Record<string, unknown> | undefined)?.token;
    const mintedSupplyStr = String(t.minted_supply ?? initialTokenVal ?? totalSupplyStr);

    let walletSum = 0n;
    let escrowSum = 0n;
    let unknownSum = 0n;
    let balanceParseFailed = false;
    for (const b of tBals) {
      const parsed = parseBigIntSafe(b.balance);
      if (parsed === null) {
        balanceParseFailed = true;
        continue;
      }
      if (b.wallet_id.startsWith("escrow::")) {
        escrowSum += parsed;
      } else if (walletIdSet.size === 0 || walletIdSet.has(b.wallet_id)) {
        walletSum += parsed;
      } else {
        unknownSum += parsed;
      }
    }
    const localSumAll = walletSum + escrowSum + unknownSum;
    const totalSupplyBig = parseBigIntSafe(totalSupplyStr);
    const maxSupplyBig = parseBigIntSafe(t.max_supply);
    const initialBig = parseBigIntSafe(initialTokenVal ?? mintedSupplyStr);
    const burnedFromInitial =
      initialBig !== null && totalSupplyBig !== null && initialBig >= totalSupplyBig
        ? (initialBig - totalSupplyBig).toString()
        : String(t.drained_supply ?? "0");

    const breakdown = rawSupplyBreakdowns[tid];
    let conserved = false;
    let conservationStatus: VerificationStatus = "UNVERIFIED";
    let sumOfBalancesStr = localSumAll.toString();
    let escrowBalancesStr = escrowSum.toString();
    let unknownBalancesStr = unknownSum.toString();
    let burnedSupplyStr = burnedFromInitial;

    if (breakdown) {
      sumOfBalancesStr = String(
        breakdown.circulating_and_escrow_total ?? breakdown.wallet_balances_total ?? localSumAll.toString(),
      );
      escrowBalancesStr = String(breakdown.escrow_balances_total ?? escrowSum.toString());
      unknownBalancesStr = String(breakdown.unknown_account_balances_total ?? unknownSum.toString());
      burnedSupplyStr = String(breakdown.burned_or_drained_total ?? burnedFromInitial);
      const upstreamSumBig = parseBigIntSafe(sumOfBalancesStr);
      const localMatchesUpstream = !balanceParseFailed && upstreamSumBig === localSumAll;
      conserved =
        breakdown.conserved === true &&
        localMatchesUpstream &&
        totalSupplyBig !== null &&
        upstreamSumBig === totalSupplyBig;
      conservationStatus = conserved ? "VERIFIED" : "INVALID";
    } else if (totalSupplyBig !== null && !balanceParseFailed) {
      const capOk = t.unlimited_supply === true || (maxSupplyBig !== null && totalSupplyBig <= maxSupplyBig);
      const balancesPresent = Array.isArray(d.balances);
      if (!balancesPresent && totalSupplyBig > 0n) {
        conserved = false;
        conservationStatus = "UNVERIFIED";
      } else {
        conserved = localSumAll === totalSupplyBig && unknownSum === 0n && capOk;
        conservationStatus = conserved ? "VERIFIED" : "INVALID";
      }
    }

    return {
      token_id: tid,
      name: String(t.name ?? ""),
      symbol: String(t.symbol ?? ""),
      region_id: String(t.region_id ?? ""),
      decimals: 0,
      max_supply: String(t.max_supply ?? "0"),
      total_supply: totalSupplyStr,
      minted_supply: mintedSupplyStr,
      burned_supply: burnedSupplyStr,
      drained_fees_collected: burnedSupplyStr,
      drain_bps:
        t.drain_bps != null && Number.isFinite(Number(t.drain_bps)) ? Number(t.drain_bps) : null,
      drain_policy: rawDrainPolicy,
      authority_pubkey: String(t.creator_pubkey ?? t.authority_pubkey ?? ""),
      supply_policy: String(t.purpose ?? "Bounded vector token"),
      token_type: "3D Vector [token, authratio(au), energy]",
      created_at_ms: Number(t.created_at_ms ?? 0),
      updated_at_ms: Number(t.created_at_ms ?? 0),
      version: Number(t.version ?? 1),
      balances: tBals,
      conservation: {
        conserved,
        verification_status: conservationStatus,
        total_supply: totalSupplyStr,
        sum_of_balances: sumOfBalancesStr,
        escrow_balances_total: escrowBalancesStr,
        unknown_account_balances_total: unknownBalancesStr,
        minted_minus_burned:
          initialBig !== null && parseBigIntSafe(burnedSupplyStr) !== null
            ? (initialBig - parseBigIntSafe(burnedSupplyStr)!).toString()
            : totalSupplyStr,
      },
    };
  });

  const initialValidators: ValidatorNodeDto[] = rawValidators.map((v) => ({
    node_id: String(v.validator_id ?? v.node_id ?? ""),
    public_key_hex: String(v.validator_pubkey_hex ?? v.pubkey_hex ?? v.public_key_hex ?? ""),
    label: String(v.validator_id ?? "validator"),
    weight: Number(v.weight ?? 1),
    active: v.active !== false,
    joined_at_ms: Number(v.joined_epoch ?? 0),
  }));

  const certifiedEventHashes = new Set<string>();
  const certifiedEventIds = new Set<string>();
  for (const cert of rawCerts) {
    const hasVotes = Array.isArray(cert.votes) && cert.votes.length > 0;
    const certValid =
      typeof cert.certificate_id === "string" &&
      cert.certificate_id.length > 0 &&
      typeof cert.proposal_digest === "string" &&
      cert.proposal_digest.length === 64 &&
      hasVotes;
    if (!certValid) continue;
    if (Array.isArray(cert.event_hashes)) {
      for (const h of cert.event_hashes) {
        if (typeof h === "string" && h) certifiedEventHashes.add(h);
      }
    }
    if (Array.isArray(cert.ordered_event_ids)) {
      for (const id of cert.ordered_event_ids) {
        if (typeof id === "string" && id) certifiedEventIds.add(id);
      }
    }
  }

  const initialEvents: CanonicalEventDto[] = rawEvents.map((e) => {
    const eventHash = String(e.event_hash ?? "");
    const eventId = String(e.event_id ?? "");
    const isCertified =
      typeof e.certified === "boolean"
        ? e.certified
        : certifiedEventHashes.has(eventHash) || certifiedEventIds.has(eventId);
    return {
      event_id: eventId,
      parent_hashes: Array.isArray(e.parent_hashes) ? (e.parent_hashes as string[]) : [],
      region_id: String(e.entity_kind ?? ""),
      entity_id: String(e.entity_id ?? ""),
      operation: { type: String(e.operation ?? e.operation_name ?? "EVENT") },
      vector_before: { components: [], owner_public_key: "", type_tag: "vector3", metadata: {} },
      vector_after: { components: [], owner_public_key: "", type_tag: "vector3", metadata: {} },
      auth_ratio: 1000,
      certified: isCertified,
      actor_public_key: String(e.actor_pubkey ?? ""),
      logical_clock: Number(e.logical_clock ?? 0),
      timestamp: Number(e.timestamp_ms ?? 0),
      payload_hash: String(e.payload_hash ?? e.after_state_hash ?? ""),
      event_hash: eventHash,
      signature: "",
    };
  });

  const initialSnapshots: SnapshotDto[] = rawCerts.map((c) => ({
    snapshot_id: String(c.certificate_id ?? ""),
    state_root: {
      root_hash: String(c.post_state_root ?? stateRoot),
      event_count: Array.isArray(c.event_hashes) ? c.event_hashes.length : 0,
      logical_clock: Number(c.height ?? logicalClock),
    },
    event_root: String(c.proposal_digest ?? ""),
    replay_hash: replayHash,
    event_count: Array.isArray(c.event_hashes) ? c.event_hashes.length : 0,
    logical_clock: Number(c.height ?? 0),
    dag_heads: Array.isArray(c.event_hashes) ? (c.event_hashes as string[]) : [],
    created_at: Number(c.finalized_at_ms ?? 0),
  }));

  return {
    initialStatus,
    initialRegions,
    initialWallets,
    initialTokens,
    initialVectors: [],
    initialRewards: [],
    initialValidators,
    initialRounds: [],
    initialEvents,
    initialRecords: [],
    initialSnapshots,
    drainPolicy: rawDrainPolicy,
    coreEventHash: String(rawEvents[0]?.event_hash ?? ""),
  };
}
