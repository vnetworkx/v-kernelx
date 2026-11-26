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

export function disconnectedStatusDto(endpoint: string): NodeStatusDto {
  return {
    kernel_version: "unknown",
    protocol_version: "unknown",
    network_name: `unreachable (${endpoint})`,
    network_mode: "disconnected",
    node_id: "offline",
    node_pubkey: "",
    storage_engine: "unknown",
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
    certificate_count: 0,
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

export function parseVerificationStatus(raw: unknown): VerificationStatus | null {
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

function parseOptionalNumber(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function parseOptionalString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
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
  const rawInfo = (d.network_info ?? {}) as Record<string, unknown>;
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
  const rawBalances = Array.isArray(d.balances) ? (d.balances as Array<Record<string, unknown>>) : null;
  const rawEvents = Array.isArray(d.events) ? (d.events as Array<Record<string, unknown>>) : [];
  const rawCerts = Array.isArray(d.certificates) ? (d.certificates as Array<Record<string, unknown>>) : [];
  const rawConsensus = (d.consensus ?? {}) as Record<string, unknown>;
  const rawValidators = Array.isArray(rawConsensus.validators)
    ? (rawConsensus.validators as Array<Record<string, unknown>>)
    : [];

  const kernelVersion =
    parseOptionalString(d.kernel_version) ??
    parseOptionalString(rawHealth.kernel_version) ??
    parseOptionalString(rawStatus.kernel_version) ??
    parseOptionalString(rawInfo.kernel_version) ??
    "unknown";

  const protocolVersion =
    parseOptionalString(d.protocol_version) ??
    parseOptionalString(rawProofs?.protocol_version) ??
    parseOptionalString(rawHealth.protocol_version) ??
    parseOptionalString(rawStatus.protocol_version) ??
    parseOptionalString(rawInfo.protocol_version) ??
    "unknown";

  const stateRoot = String(d.state_root ?? rawStatus.state_root ?? "");
  const replayHash = String(d.replay_hash ?? rawStatus.replay_hash ?? "");
  const eventHistoryRoot =
    parseOptionalString(d.event_history_root) ??
    parseOptionalString(rawStatus.event_history_root) ??
    parseOptionalString(rawProofs?.event_history_root);
  const eventCount = Number(rawStatus.committed_events ?? rawEvents.length ?? 0);
  const logicalClock = Number(rawStatus.logical_clock ?? 0);

  const storageEngine =
    parseOptionalString(d.storage_engine) ??
    parseOptionalString(rawStatus.storage_engine) ??
    "unknown";

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

  // Authoritative Rust certificate verification summaries (NEVER trust client heuristics or raw votes.length)
  const rawCertVerifications = Array.isArray(rawProofs?.certificate_verifications)
    ? (rawProofs!.certificate_verifications as Array<Record<string, unknown>>)
    : null;
  const certStatusById = new Map<string, VerificationStatus>();
  const verifiedCertForEventHash = new Map<string, string>();
  const verifiedCertForEventId = new Map<string, string>();
  let anyInvalidCert = false;
  let anyUnverifiedCert = rawCerts.length > 0 && rawCertVerifications === null;

  if (rawCertVerifications) {
    for (const cv of rawCertVerifications) {
      const cid = String(cv.certificate_id ?? "");
      const st = parseVerificationStatus(cv.verification_status) ?? "UNVERIFIED";
      if (cid) certStatusById.set(cid, st);
      if (st === "INVALID") {
        anyInvalidCert = true;
      } else if (st === "VERIFIED") {
        if (Array.isArray(cv.event_hashes)) {
          for (const h of cv.event_hashes) {
            if (typeof h === "string" && h) verifiedCertForEventHash.set(h, cid);
          }
        }
        if (Array.isArray(cv.ordered_event_ids)) {
          for (const eid of cv.ordered_event_ids) {
            if (typeof eid === "string" && eid) verifiedCertForEventId.set(eid, cid);
          }
        }
      } else {
        anyUnverifiedCert = true;
      }
    }
    for (const cert of rawCerts) {
      const cid = String(cert.certificate_id ?? "");
      if (!cid || !certStatusById.has(cid)) {
        anyUnverifiedCert = true;
      }
    }
  }

  const proofsChainValid = rawProofs ? rawProofs.chain_valid === true : null;
  const proofsNetworkMismatch =
    rawProofs?.network_id != null &&
    rawStatus.network_id != null &&
    String(rawProofs.network_id) !== String(rawStatus.network_id);
  const proofsProtocolMismatch =
    rawProofs?.protocol_version != null &&
    protocolVersion !== "unknown" &&
    String(rawProofs.protocol_version) !== protocolVersion;

  let replayVerified = false;
  let replayStatus: VerificationStatus = "UNVERIFIED";
  if (rawReplay && typeof rawReplay.valid === "boolean") {
    const stateMatch =
      Boolean(rawReplay.replayed_state_root) &&
      rawReplay.replayed_state_root === rawReplay.live_state_root &&
      (!stateRoot || rawReplay.live_state_root === stateRoot) &&
      Boolean(rawReplay.replayed_replay_hash) &&
      rawReplay.replayed_replay_hash === rawReplay.live_replay_hash;
    const replayValidFlag = rawReplay.valid === true;
    if (!replayValidFlag || !stateMatch || proofsChainValid === false || proofsNetworkMismatch || proofsProtocolMismatch) {
      replayStatus = "INVALID";
      replayVerified = false;
    } else if (proofsChainValid === true) {
      replayStatus = "VERIFIED";
      replayVerified = true;
    } else {
      // Missing ledger proof report MUST remain UNVERIFIED, never default to true
      replayStatus = "UNVERIFIED";
      replayVerified = false;
    }
  } else if (proofsChainValid === false || d.replay_error != null) {
    replayStatus = "INVALID";
  } else {
    replayStatus = "UNVERIFIED";
  }

  const initialEvents: CanonicalEventDto[] = rawEvents.map((e) => {
    const eventHash = String(e.event_hash ?? "");
    const eventId = String(e.event_id ?? "");
    const payloadObj =
      e.payload && typeof e.payload === "object" ? (e.payload as Record<string, unknown>) : null;
    const coveringVerifiedCert =
      verifiedCertForEventHash.get(eventHash) ?? verifiedCertForEventId.get(eventId) ?? null;
    const eventVerified = proofsChainValid === true && coveringVerifiedCert !== null;
    const evStatus: VerificationStatus =
      proofsChainValid === false || anyInvalidCert
        ? "INVALID"
        : eventVerified
          ? "VERIFIED"
          : "UNVERIFIED";
    return {
      event_id: eventId,
      parent_hashes: Array.isArray(e.parent_hashes) ? (e.parent_hashes as string[]) : [],
      region_id: String(e.entity_kind ?? ""),
      entity_id: String(e.entity_id ?? ""),
      operation: { type: String(e.operation ?? e.operation_name ?? "EVENT") },
      vector_before: { components: [], owner_public_key: "", type_tag: "vector3", metadata: {} },
      vector_after: { components: [], owner_public_key: "", type_tag: "vector3", metadata: {} },
      auth_ratio:
        parseOptionalNumber(e.auth_ratio) ??
        parseOptionalNumber(payloadObj?.auth_ratio) ??
        null,
      certified: eventVerified,
      verification_status: evStatus,
      actor_public_key: String(e.actor_pubkey ?? ""),
      logical_clock: Number(e.logical_clock ?? 0),
      timestamp: Number(e.timestamp_ms ?? 0),
      payload_hash: String(e.payload_hash ?? e.after_state_hash ?? ""),
      event_hash: eventHash,
      signature:
        parseOptionalString(e.signature) ?? parseOptionalString(payloadObj?.signature) ?? null,
    };
  });

  const initialRegions: RegionDto[] = rawRegions.map((r) => {
    const regionId = String(r.region_id ?? "");
    const matchingCreateEvent = rawEvents.find((e) => {
      const eid = String(e.entity_id ?? "");
      const op = String(e.operation ?? e.operation_name ?? "").toUpperCase();
      return (
        eid === regionId &&
        (op === "REGION_CREATE" || op === "GHOST_REGION_CREATE" || String(e.entity_kind ?? "") === "region")
      );
    });
    const matchedHash = matchingCreateEvent ? parseOptionalString(matchingCreateEvent.event_hash) : null;
    const matchedId = matchingCreateEvent ? parseOptionalString(matchingCreateEvent.event_id) : null;
    const creationProofCertId =
      (matchedHash && verifiedCertForEventHash.get(matchedHash)) ??
      (matchedId && verifiedCertForEventId.get(matchedId)) ??
      null;
    return {
      region_id: regionId,
      region_root: String(r.space_id ?? ""),
      region_name: String(r.name ?? ""),
      normalized_name: String(r.name ?? "").toLowerCase(),
      region_prefix: (r.prefix as string | null) ?? null,
      suggested_title: (r.title as string | null) ?? null,
      visibility: String(r.visibility ?? "PUBLIC").toLowerCase() === "private" ? "private" : "public",
      section: parseOptionalNumber(r.section),
      auth_ratio_bps: parseOptionalNumber(r.auth_ratio_bps),
      creator_public_key: String(r.creator_pubkey ?? ""),
      trigger_event_hash: matchedHash,
      creation_proof_hash: creationProofCertId,
      access_key_hash: null,
      created_at_ms: Number(r.created_at_ms ?? 0),
      updated_at_ms: Number(r.created_at_ms ?? 0),
      version: Number(r.version ?? 1),
      metadata: { space_id: String(r.space_id ?? "") },
    };
  });

  const initialWallets: WalletDto[] = rawWallets.map((w) => {
    const wid = String(w.wallet_id ?? "");
    const wBals = (rawBalances ?? [])
      .filter((b) => String(b.wallet_id ?? "") === wid)
      .map((b) => ({
        token_id: String(b.token_id ?? ""),
        wallet_id: wid,
        owner_pubkey: String(w.owner_pubkey ?? ""),
        balance: String((b.vector as Record<string, unknown> | undefined)?.token ?? "0"),
        updated_at_ms: Number(b.updated_at_ms ?? 0),
        version: Number(b.version ?? 1),
      }));
    const firstVectorBalance = (rawBalances ?? []).find((b) => String(b.wallet_id ?? "") === wid);
    const derivedAuthRatio =
      parseOptionalNumber(w.auth_ratio) ??
      parseOptionalNumber((firstVectorBalance?.vector as Record<string, unknown> | undefined)?.auth_ratio_au) ??
      null;
    return {
      wallet_id: wid,
      public_key_hex: String(w.owner_pubkey ?? ""),
      label: String(w.name ?? wid),
      region_id: (w.region_id as string | null) ?? null,
      space_id: (w.space_id as string | null) ?? null,
      creator_wallet_id: null,
      receive_policy: parseReceivePolicy(w.receive_policy),
      created_at_ms: Number(w.created_at_ms ?? 0),
      auth_ratio: derivedAuthRatio,
      balances: wBals,
      rewards: [],
    };
  });

  const walletIdSet = new Set(initialWallets.map((w) => w.wallet_id));
  let anyTokenInvalid = false;
  let anyTokenUnverified = false;

  const initialTokens: TokenDto[] = rawTokens.map((t) => {
    const tid = String(t.token_id ?? "");
    const tBals: TokenBalanceDto[] = (rawBalances ?? [])
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
    let lockedCollateralSum = 0n;
    let reserveSum = 0n;
    let unknownSum = 0n;
    let balanceParseFailed = false;
    for (const b of tBals) {
      const parsed = parseBigIntSafe(b.balance);
      if (parsed === null) {
        balanceParseFailed = true;
        continue;
      }
      if (b.wallet_id.startsWith("escrow::loan_")) {
        lockedCollateralSum += parsed;
      } else if (b.wallet_id.startsWith("escrow::")) {
        escrowSum += parsed;
      } else if (b.wallet_id.startsWith("reserve::")) {
        reserveSum += parsed;
      } else if (walletIdSet.has(b.wallet_id)) {
        walletSum += parsed;
      } else {
        unknownSum += parsed;
      }
    }
    const localSumAll = walletSum + escrowSum + lockedCollateralSum + reserveSum + unknownSum;
    const totalSupplyBig = parseBigIntSafe(totalSupplyStr);
    const maxSupplyBig = parseBigIntSafe(t.max_supply);
    const initialBig = parseBigIntSafe(initialTokenVal ?? mintedSupplyStr);
    const capOk =
      t.unlimited_supply === true ||
      (totalSupplyBig !== null && maxSupplyBig !== null && totalSupplyBig <= maxSupplyBig);

    const breakdown = rawSupplyBreakdowns[tid];
    let conserved = false;
    let conservationStatus: VerificationStatus = "UNVERIFIED";
    let verificationReason: string | null = null;
    let sumOfBalancesStr = localSumAll.toString();
    let walletBalancesStr = walletSum.toString();
    let escrowBalancesStr = escrowSum.toString();
    let lockedCollateralStr = lockedCollateralSum.toString();
    let reserveBalancesStr = reserveSum.toString();
    let unknownBalancesStr = unknownSum.toString();
    let burnedSupplyStr: string | null = null;
    let drainedFeesStr: string | null = null;

    if (breakdown) {
      sumOfBalancesStr = String(
        breakdown.circulating_and_escrow_total ?? localSumAll.toString(),
      );
      walletBalancesStr = String(breakdown.wallet_balances_total ?? walletSum.toString());
      escrowBalancesStr = String(breakdown.escrow_balances_total ?? escrowSum.toString());
      lockedCollateralStr = String(breakdown.locked_collateral_total ?? lockedCollateralSum.toString());
      reserveBalancesStr = String(breakdown.reserve_balances_total ?? reserveSum.toString());
      unknownBalancesStr = String(breakdown.unknown_account_balances_total ?? unknownSum.toString());
      burnedSupplyStr =
        breakdown.burned_supply != null ? String(breakdown.burned_supply) : null;
      drainedFeesStr =
        breakdown.drained_fees_total != null ? String(breakdown.drained_fees_total) : null;
      verificationReason =
        typeof breakdown.verification_reason === "string" ? breakdown.verification_reason : null;

      const upstreamStatus = parseVerificationStatus(breakdown.verification_status);
      const upstreamSumBig = parseBigIntSafe(sumOfBalancesStr);
      const upstreamUnknownBig = parseBigIntSafe(unknownBalancesStr) ?? unknownSum;

      if (
        upstreamStatus === "INVALID" ||
        !capOk ||
        totalSupplyBig === null ||
        upstreamSumBig === null ||
        upstreamSumBig !== totalSupplyBig ||
        (rawBalances !== null && !balanceParseFailed && upstreamSumBig !== localSumAll)
      ) {
        conservationStatus = "INVALID";
        conserved = false;
        anyTokenInvalid = true;
      } else if (
        rawBalances === null ||
        balanceParseFailed ||
        unknownSum > 0n ||
        upstreamUnknownBig > 0n ||
        upstreamStatus === "UNVERIFIED"
      ) {
        conservationStatus = "UNVERIFIED";
        conserved = false;
        anyTokenUnverified = true;
      } else if (breakdown.conserved === true && upstreamStatus === "VERIFIED") {
        conservationStatus = "VERIFIED";
        conserved = true;
      } else {
        conservationStatus = "UNVERIFIED";
        conserved = false;
        anyTokenUnverified = true;
      }
    } else {
      // Missing authoritative kernel breakdown: partial balances or missing proof MUST be UNVERIFIED (or INVALID if arithmetically inconsistent)
      if (rawBalances !== null && !balanceParseFailed && totalSupplyBig !== null) {
        if (!capOk || (unknownSum === 0n && localSumAll > totalSupplyBig)) {
          conservationStatus = "INVALID";
          anyTokenInvalid = true;
          verificationReason = "Balances or total supply violate token bounds";
        } else {
          conservationStatus = "UNVERIFIED";
          anyTokenUnverified = true;
          verificationReason = "Authoritative Rust kernel supply breakdown missing";
        }
      } else {
        conservationStatus = "UNVERIFIED";
        anyTokenUnverified = true;
        verificationReason = "Partial or unavailable balance dataset";
      }
    }

    const burnedNum = burnedSupplyStr ? parseBigIntSafe(burnedSupplyStr) : null;
    return {
      token_id: tid,
      name: String(t.name ?? ""),
      symbol: String(t.symbol ?? ""),
      region_id: String(t.region_id ?? ""),
      decimals: Number(t.decimals ?? 0),
      max_supply: String(t.max_supply ?? "0"),
      total_supply: totalSupplyStr,
      minted_supply: mintedSupplyStr,
      burned_supply: burnedSupplyStr,
      drained_fees_collected: drainedFeesStr,
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
        verification_reason: verificationReason,
        total_supply: totalSupplyStr,
        sum_of_balances: sumOfBalancesStr,
        wallet_balances_total: walletBalancesStr,
        escrow_balances_total: escrowBalancesStr,
        locked_collateral_total: lockedCollateralStr,
        reserve_balances_total: reserveBalancesStr,
        unknown_account_balances_total: unknownBalancesStr,
        burned_supply: burnedSupplyStr,
        drained_fees_total: drainedFeesStr,
        minted_minus_burned:
          initialBig !== null && burnedNum !== null
            ? (initialBig - burnedNum).toString()
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

  const initialSnapshots: SnapshotDto[] = rawCerts.map((c) => {
    const cid = String(c.certificate_id ?? "");
    const cStatus =
      (cid ? certStatusById.get(cid) : undefined) ??
      (rawCertVerifications ? "UNVERIFIED" : "UNVERIFIED");
    return {
      snapshot_id: cid,
      state_root: {
        root_hash: String(c.post_state_root ?? stateRoot),
        event_count: Array.isArray(c.event_hashes) ? c.event_hashes.length : 0,
        logical_clock: Number(c.height ?? logicalClock),
      },
      // NEVER display proposal_digest as event_root
      event_root: eventHistoryRoot ?? null,
      proposal_digest: String(c.proposal_digest ?? ""),
      verification_status: cStatus,
      replay_hash: replayHash,
      event_count: Array.isArray(c.event_hashes) ? c.event_hashes.length : 0,
      logical_clock: Number(c.height ?? 0),
      dag_heads: Array.isArray(c.event_hashes) ? (c.event_hashes as string[]) : [],
      created_at: Number(c.finalized_at_ms ?? 0),
    };
  });

  const verifiedEventCount =
    typeof rawProofs?.certified_event_count === "number"
      ? rawProofs.certified_event_count
      : initialEvents.filter((ev) => ev.certified).length;

  let verificationStatus: VerificationStatus;
  if (
    !dbIntegrityOk ||
    replayStatus === "INVALID" ||
    equivocationCount > 0 ||
    anyInvalidCert ||
    anyTokenInvalid ||
    proofsChainValid === false ||
    proofsNetworkMismatch ||
    proofsProtocolMismatch ||
    d.proofs_error != null ||
    d.state_root_error != null
  ) {
    verificationStatus = "INVALID";
  } else if (
    rawProofs === null ||
    replayStatus !== "VERIFIED" ||
    anyUnverifiedCert ||
    anyTokenUnverified ||
    parseVerificationStatus(rawHealth.verification_status) !== "VERIFIED"
  ) {
    verificationStatus = "UNVERIFIED";
  } else {
    verificationStatus = "VERIFIED";
  }

  const initialStatus: NodeStatusDto = {
    kernel_version: kernelVersion,
    protocol_version: protocolVersion,
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
    certificate_count: rawCerts.length,
    finalized_event_count: verifiedEventCount,
    total_drain_rewards_count: 0,
    state_root: {
      root_hash: stateRoot,
      event_count: eventCount,
      logical_clock: logicalClock,
    },
    replay_hash: replayHash,
    replay_verified: replayVerified,
  };

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
    coreEventHash: String(initialEvents[0]?.event_hash ?? ""),
  };
}
