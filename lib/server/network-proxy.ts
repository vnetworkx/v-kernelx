import "server-only";
import type {
  CanonicalEventDto,
  ConsensusRoundDto,
  DrainRewardDto,
  NodeStatusDto,
  RegionDto,
  SnapshotDto,
  TokenDto,
  ValidatorNodeDto,
  VectorRecordDto,
  VectorStateDto,
  WalletDto,
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
    storage_engine: "rust-wal-sqlite",
    db_path: endpoint,
    db_integrity_ok: false,
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
  coreEventHash: string;
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
      coreEventHash: "",
    };
  }

  const d = snapshot.data;
  const rawStatus = (d.status ?? {}) as Record<string, unknown>;
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

  const initialStatus: NodeStatusDto = {
    kernel_version: "vector-network/1.0.0",
    network_name: String(rawStatus.network_id ?? "vector-network"),
    network_mode: String(rawStatus.profile ?? "DEVELOPMENT"),
    node_id: String(rawStatus.node_id ?? ""),
    node_pubkey: "",
    storage_engine: "rust-wal-sqlite",
    db_path: snapshot.endpoint,
    db_integrity_ok: true,
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
    replay_verified: Boolean(replayHash),
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
    auth_ratio_bps: 10000,
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
      creator_wallet_id: null,
      created_at_ms: Number(w.created_at_ms ?? 0),
      auth_ratio: 1000,
      balances: wBals,
      rewards: [],
    };
  });

  const initialTokens: TokenDto[] = rawTokens.map((t) => {
    const tid = String(t.token_id ?? "");
    const tBals = rawBalances
      .filter((b) => String(b.token_id ?? "") === tid)
      .map((b) => ({
        token_id: tid,
        wallet_id: String(b.wallet_id ?? ""),
        owner_pubkey: "",
        balance: String((b.vector as Record<string, unknown> | undefined)?.token ?? "0"),
        updated_at_ms: Number(b.updated_at_ms ?? 0),
        version: Number(b.version ?? 1),
      }));
    const totalSupply = String(t.total_supply ?? "0");
    const mintedSupply = String(t.minted_supply ?? totalSupply);
    const burnedSupply = String(t.drained_supply ?? "0");
    return {
      token_id: tid,
      name: String(t.name ?? ""),
      symbol: String(t.symbol ?? ""),
      region_id: String(t.region_id ?? ""),
      decimals: 0,
      max_supply: String(t.max_supply ?? "0"),
      total_supply: totalSupply,
      minted_supply: mintedSupply,
      burned_supply: burnedSupply,
      drained_fees_collected: burnedSupply,
      drain_bps: Number(t.drain_bps ?? 0),
      authority_pubkey: String(t.creator_pubkey ?? ""),
      supply_policy: String(t.purpose ?? "Development/bootstrap"),
      token_type: "3D Vector [token, authratio(au), energy]",
      created_at_ms: Number(t.created_at_ms ?? 0),
      updated_at_ms: Number(t.created_at_ms ?? 0),
      version: Number(t.version ?? 1),
      balances: tBals,
      conservation: {
        conserved: true,
        total_supply: totalSupply,
        sum_of_balances: totalSupply,
        minted_minus_burned: totalSupply,
      },
    };
  });

  const initialValidators: ValidatorNodeDto[] = rawValidators.map((v) => ({
    node_id: String(v.validator_id ?? v.node_id ?? ""),
    public_key_hex: String(v.pubkey_hex ?? v.public_key_hex ?? ""),
    label: String(v.validator_id ?? "validator"),
    weight: Number(v.weight ?? 1),
    active: v.active !== false,
    joined_at_ms: 0,
  }));

  const initialEvents: CanonicalEventDto[] = rawEvents.map((e) => ({
    event_id: String(e.event_id ?? ""),
    parent_hashes: Array.isArray(e.parent_hashes) ? (e.parent_hashes as string[]) : [],
    region_id: String(e.entity_kind ?? ""),
    entity_id: String(e.entity_id ?? ""),
    operation: { type: String(e.operation_name ?? "EVENT") },
    vector_before: { components: [], owner_public_key: "", type_tag: "vector3", metadata: {} },
    vector_after: { components: [], owner_public_key: "", type_tag: "vector3", metadata: {} },
    auth_ratio: 1000,
    certified: true,
    actor_public_key: String(e.actor_pubkey ?? ""),
    logical_clock: Number(e.logical_clock ?? 0),
    timestamp: Number(e.timestamp_ms ?? 0),
    payload_hash: String(e.after_state_hash ?? ""),
    event_hash: String(e.event_hash ?? ""),
    signature: "",
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
    initialSnapshots: [],
    coreEventHash: String(rawEvents[0]?.event_hash ?? ""),
  };
}
