"use client";

import { useState } from "react";
import { AlertTriangle, Check, Copy, Database, Layers, RefreshCw, ShieldCheck } from "lucide-react";
import {
  extractOperationLabel,
  formatTimestampMs,
  formatTokenUnitsClient,
  shortenHash,
} from "@/lib/format";
import type {
  CanonicalEventDto,
  ContractDto,
  GhostAssessmentDto,
  HierarchyCommitmentsDto,
  LoanDto,
  NodeDto,
  NodeStatusDto,
  ParticipantDto,
  RegionDto,
  ReplayDto,
  SnapshotDto,
  SpaceDto,
  TokenDto,
  WalletDto,
} from "@/lib/types";

interface OverviewPanelProps {
  status: NodeStatusDto;
  spaces: SpaceDto[];
  regions: RegionDto[];
  wallets: WalletDto[];
  tokens: TokenDto[];
  participants: ParticipantDto[];
  nodes: NodeDto[];
  contracts: ContractDto[];
  loans: LoanDto[];
  ghostAssessment: GhostAssessmentDto | null;
  hierarchyCommitments: HierarchyCommitmentsDto | null;
  events: CanonicalEventDto[];
  snapshots: SnapshotDto[];
  hasSession: boolean;
  onRunReplay: () => Promise<ReplayDto | null>;
  onCreateSnapshot: () => Promise<void>;
  onCreateBackup: () => Promise<void>;
  onNavigate: (tab: "regions" | "wallets" | "tokens" | "vectors" | "dag") => void;
  onOpenAuth: () => void;
}

function statusTextClass(st: string): string {
  if (st === "VERIFIED") return "text-emerald-700";
  if (st === "INVALID") return "text-red-700";
  if (st === "UNAVAILABLE") return "text-slate-500";
  return "text-amber-700";
}

export function OverviewPanel({
  status,
  spaces,
  regions,
  wallets,
  tokens,
  participants,
  nodes,
  contracts,
  loans,
  ghostAssessment,
  hierarchyCommitments,
  events,
  snapshots,
  hasSession,
  onRunReplay,
  onCreateSnapshot,
  onCreateBackup,
  onNavigate,
  onOpenAuth,
}: OverviewPanelProps) {
  const [replayResult, setReplayResult] = useState<ReplayDto | null>(null);
  const [replaying, setReplaying] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [busyOp, setBusyOp] = useState<string | null>(null);

  async function copyValue(key: string, val: string) {
    try {
      await navigator.clipboard?.writeText(val);
    } catch {
      // Clipboard API may be restricted in sandboxed iframes
    }
    setCopiedField(key);
    setTimeout(() => setCopiedField((prev) => (prev === key ? null : prev)), 1500);
  }

  async function handleReplay() {
    setReplaying(true);
    try {
      const res = await onRunReplay();
      if (res) setReplayResult(res);
    } finally {
      setReplaying(false);
    }
  }

  async function handleSnapshot() {
    if (!hasSession) {
      onOpenAuth();
      return;
    }
    setBusyOp("snapshot");
    try {
      await onCreateSnapshot();
    } finally {
      setBusyOp(null);
    }
  }

  async function handleBackup() {
    if (!hasSession) {
      onOpenAuth();
      return;
    }
    setBusyOp("backup");
    try {
      await onCreateBackup();
    } finally {
      setBusyOp(null);
    }
  }

  const primaryToken = tokens[0] ?? null;
  const recentEvents = [...events].reverse().slice(0, 6);

  return (
    <div className="space-y-6">
      {/* KPI Metric Strip — Flat 1px grid */}
      <div className="grid grid-cols-2 border border-slate-200 bg-white lg:grid-cols-4">
        <button
          type="button"
          onClick={() => onNavigate("regions")}
          className="border-b border-r border-slate-200 p-4 text-left transition-colors hover:bg-slate-50 lg:border-b-0"
        >
          <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
            Spaces / Regions
          </div>
          <div className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-slate-900">
            {spaces.length}
            <span className="ml-1.5 text-sm font-normal text-slate-400">/ {status.region_count}</span>
          </div>
          <div className="mt-1 font-mono text-[11px] text-slate-500">
            {regions[0] ? `${regions[0].region_name} · ${regions[0].region_prefix ?? "—"}` : "No regions"}
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate("wallets")}
          className="border-b border-slate-200 p-4 text-left transition-colors hover:bg-slate-50 lg:border-b-0 lg:border-r"
        >
          <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
            Wallets / Participants
          </div>
          <div className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-slate-900">
            {status.wallet_count}
            <span className="ml-1.5 text-sm font-normal text-slate-400">/ {participants.length}</span>
          </div>
          <div className="mt-1 font-mono text-[11px] text-slate-500">
            {nodes.length} nodes · {contracts.length} contracts · {loans.length} loans
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate("dag")}
          className="border-r border-slate-200 p-4 text-left transition-colors hover:bg-slate-50"
        >
          <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
            Event DAG / Balance Vectors
          </div>
          <div className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-slate-900">
            {status.event_count}
            <span className="ml-1.5 text-sm font-normal text-slate-400">/ {status.vector_count}</span>
          </div>
          <div className="mt-1 font-mono text-[11px] text-slate-500">
            Clock {status.state_root.logical_clock} · {snapshots.length} certs
          </div>
        </button>

        <div className="p-4">
          <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
            Deterministic Replay & State
          </div>
          <div
            className={`mt-1.5 font-mono text-2xl font-semibold tabular-nums ${statusTextClass(status.verification_status)}`}
          >
            {status.verification_status}
          </div>
          <div className="mt-1 font-mono text-[11px] text-slate-500">
            {status.storage_engine} · wal {status.wal_consistency_ok ? "ok" : "unverified"} · eq{" "}
            {status.equivocation_count}
          </div>
        </div>
      </div>

      {/* Node Cryptographic Identity & Primary Token Conservation */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <section className="border border-slate-200 bg-white xl:col-span-2">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 px-5 py-3.5">
            <div>
              <h2 className="text-sm font-semibold text-slate-900">Node Identity & State Root</h2>
              <p className="text-xs text-slate-500">
                {status.network_name} · {status.network_mode}
              </p>
            </div>
            <button
              type="button"
              onClick={handleReplay}
              disabled={replaying}
              className="inline-flex items-center gap-1.5 whitespace-nowrap border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition-colors hover:bg-slate-50 disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${replaying ? "animate-spin" : ""}`} />
              {replaying ? "Replaying DAG..." : "Verify Deterministic Replay"}
            </button>
          </div>

          <div className="divide-y divide-slate-100">
            {[
              { key: "node_id", label: "Node Identifier", value: status.node_id || "—" },
              {
                key: "node_pubkey",
                label: "Node Ed25519 Pubkey",
                value: status.node_pubkey || "—",
              },
              {
                key: "root_hash",
                label: "Canonical State Root",
                value: status.state_root.root_hash,
              },
              { key: "replay_hash", label: "DAG Replay Digest", value: status.replay_hash },
              {
                key: "storage",
                label: "Storage Engine",
                value: `${status.storage_engine} (replay: ${status.replay_status}, equivocations: ${status.equivocation_count})`,
              },
            ].map((item) => (
              <div
                key={item.key}
                className="flex flex-col gap-1 px-5 py-3 sm:flex-row sm:items-center sm:justify-between"
              >
                <span className="text-xs font-medium text-slate-500">{item.label}</span>
                <div className="flex items-center gap-2">
                  <code className="break-all font-mono text-xs text-slate-800">{item.value}</code>
                  <button
                    type="button"
                    onClick={() => copyValue(item.key, item.value)}
                    className="shrink-0 p-1 text-slate-400 hover:text-slate-700"
                    title="Copy value"
                  >
                    {copiedField === item.key ? (
                      <Check className="h-3.5 w-3.5 text-emerald-600" />
                    ) : (
                      <Copy className="h-3.5 w-3.5" />
                    )}
                  </button>
                </div>
              </div>
            ))}
          </div>

          {replayResult && (
            <div className="border-t border-slate-200 bg-slate-50 px-5 py-3 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-medium text-slate-700">
                  Last Replay Check:{" "}
                  <span
                    className={`font-mono ${statusTextClass(
                      replayResult.verification_status ??
                        (replayResult.matches_stored_state ? "VERIFIED" : "INVALID"),
                    )}`}
                  >
                    {replayResult.matches_stored_state
                      ? `VERIFIED (${replayResult.events_replayed ?? replayResult.applied_event_hashes.length} events replayed)`
                      : `${replayResult.verification_status ?? "INVALID"} (${replayResult.mismatch_reasons.join("; ")})`}
                  </span>
                </span>
                <span className="font-mono text-slate-500">
                  clock={replayResult.state_root.logical_clock}
                </span>
              </div>
            </div>
          )}
        </section>

        {/* Primary Token & Persistence Controls */}
        <section className="flex flex-col justify-between border border-slate-200 bg-white">
          <div>
            <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3.5">
              <h2 className="text-sm font-semibold text-slate-900">
                {primaryToken ? `${primaryToken.name} (${primaryToken.symbol})` : "Token Supply"}
              </h2>
              <button
                type="button"
                onClick={() => onNavigate("tokens")}
                className="text-xs font-medium text-blue-600 hover:text-blue-700"
              >
                Manage Ledger
              </button>
            </div>

            {primaryToken ? (
              <div className="divide-y divide-slate-100 px-5">
                <div className="flex items-center justify-between py-3 text-xs">
                  <span className="text-slate-500">Circulating Supply</span>
                  <span className="font-mono font-semibold tabular-nums text-slate-900">
                    {formatTokenUnitsClient(primaryToken.total_supply, primaryToken.decimals)}{" "}
                    {primaryToken.symbol}
                  </span>
                </div>
                <div className="flex items-center justify-between py-3 text-xs">
                  <span className="text-slate-500">Minted / Burned</span>
                  <span className="font-mono tabular-nums text-slate-700">
                    {formatTokenUnitsClient(primaryToken.minted_supply, primaryToken.decimals)} /{" "}
                    {formatTokenUnitsClient(primaryToken.burned_supply, primaryToken.decimals)}
                  </span>
                </div>
                <div className="flex items-center justify-between py-3 text-xs">
                  <span className="text-slate-500">Max Cap</span>
                  <span className="font-mono tabular-nums text-slate-700">
                    {formatTokenUnitsClient(primaryToken.max_supply, primaryToken.decimals)}
                  </span>
                </div>
                <div className="flex items-center justify-between py-3 text-xs">
                  <span className="text-slate-500">Supply Conservation</span>
                  <span
                    className={`font-mono font-medium ${statusTextClass(primaryToken.conservation.verification_status)}`}
                  >
                    {primaryToken.conservation.verification_status === "VERIFIED"
                      ? "CONSERVED (VERIFIED)"
                      : primaryToken.conservation.verification_status === "INVALID"
                        ? "VIOLATION (INVALID)"
                        : primaryToken.conservation.verification_status}
                  </span>
                </div>
                <div className="flex items-center justify-between py-3 text-xs">
                  <span className="text-slate-500">Active Holders</span>
                  <span className="font-mono tabular-nums text-slate-700">
                    {primaryToken.balances.length} accounts ({wallets.length} wallets)
                  </span>
                </div>
              </div>
            ) : (
              <div className="p-5 text-xs text-slate-500">
                No vector tokens registered yet. Issue a token in Tokens &amp; Drain.
              </div>
            )}
          </div>

          <div className="border-t border-slate-200 bg-slate-50/70 p-4">
            <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-slate-500">
              Durability &amp; Checkpoints
            </div>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={handleSnapshot}
                disabled={busyOp !== null}
                className="inline-flex items-center justify-center gap-1.5 border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-800 transition-colors hover:bg-slate-50 disabled:opacity-50"
              >
                <ShieldCheck className="h-3.5 w-3.5 text-blue-600" />
                {busyOp === "snapshot" ? "Saving..." : "Check Certs"}
              </button>
              <button
                type="button"
                onClick={handleBackup}
                disabled={busyOp !== null}
                className="inline-flex items-center justify-center gap-1.5 border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-800 transition-colors hover:bg-slate-50 disabled:opacity-50"
              >
                <Database className="h-3.5 w-3.5 text-slate-600" />
                {busyOp === "backup" ? "Backing up..." : "Hot Backup"}
              </button>
            </div>
          </div>
        </section>
      </div>

      {/* Hierarchy Commitments & Ghost Entity Risk Assessment */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <section className="border border-slate-200 bg-white">
          <div className="flex items-center gap-2 border-b border-slate-200 px-5 py-3.5">
            <Layers className="h-4 w-4 text-blue-600" />
            <div>
              <h2 className="text-sm font-semibold text-slate-900">Hierarchy Commitments</h2>
              <p className="text-xs text-slate-500">
                Network -&gt; Space -&gt; Region -&gt; Wallet -&gt; Token BLAKE3 commitment chain
              </p>
            </div>
          </div>
          {hierarchyCommitments ? (
            <div className="divide-y divide-slate-100 px-5 text-xs">
              <div className="flex items-center justify-between py-2.5">
                <span className="text-slate-500">Network Commitment</span>
                <code className="font-mono text-slate-800">
                  {shortenHash(hierarchyCommitments.network_commitment, 14, 10)}
                </code>
              </div>
              <div className="flex items-center justify-between py-2.5">
                <span className="text-slate-500">Ghost Ledger Commitment</span>
                <code className="font-mono text-slate-800">
                  {shortenHash(hierarchyCommitments.ghost_commitment, 14, 10)}
                </code>
              </div>
              <div className="grid grid-cols-4 gap-2 py-3 text-center font-mono">
                <div className="border border-slate-100 bg-slate-50 p-2">
                  <div className="text-[10px] text-slate-400">Spaces</div>
                  <div className="font-semibold text-slate-800">
                    {Object.keys(hierarchyCommitments.space_commitments ?? {}).length}
                  </div>
                </div>
                <div className="border border-slate-100 bg-slate-50 p-2">
                  <div className="text-[10px] text-slate-400">Regions</div>
                  <div className="font-semibold text-slate-800">
                    {Object.keys(hierarchyCommitments.region_commitments ?? {}).length}
                  </div>
                </div>
                <div className="border border-slate-100 bg-slate-50 p-2">
                  <div className="text-[10px] text-slate-400">Wallets</div>
                  <div className="font-semibold text-slate-800">
                    {Object.keys(hierarchyCommitments.wallet_commitments ?? {}).length}
                  </div>
                </div>
                <div className="border border-slate-100 bg-slate-50 p-2">
                  <div className="text-[10px] text-slate-400">Tokens</div>
                  <div className="font-semibold text-slate-800">
                    {Object.keys(hierarchyCommitments.token_commitments ?? {}).length}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="px-5 py-6 text-xs text-slate-500">
              Hierarchy commitments unavailable while node proofs are missing or disconnected.
            </div>
          )}
        </section>

        <section className="border border-slate-200 bg-white">
          <div className="flex items-center gap-2 border-b border-slate-200 px-5 py-3.5">
            <AlertTriangle className="h-4 w-4 text-amber-600" />
            <div>
              <h2 className="text-sm font-semibold text-slate-900">Ghost Entity Risk Inspection</h2>
              <p className="text-xs text-slate-500">
                Authoritative tracking of parentless &amp; ghost-flagged entities under Network scope
              </p>
            </div>
          </div>
          {ghostAssessment ? (
            <div className="space-y-3 p-5 text-xs">
              <div className="grid grid-cols-2 gap-3 font-mono sm:grid-cols-4">
                <div className="border border-slate-200 bg-slate-50 p-2">
                  <div className="text-[10px] text-slate-500">Total Ghost</div>
                  <div className="font-semibold text-slate-900">{ghostAssessment.total_ghost_entities}</div>
                </div>
                <div className="border border-slate-200 bg-slate-50 p-2">
                  <div className="text-[10px] text-slate-500">Parentless Reg</div>
                  <div className="font-semibold text-slate-900">{ghostAssessment.parentless_regions.length}</div>
                </div>
                <div className="border border-slate-200 bg-slate-50 p-2">
                  <div className="text-[10px] text-slate-500">Parentless Wlt</div>
                  <div className="font-semibold text-slate-900">{ghostAssessment.parentless_wallets.length}</div>
                </div>
                <div className="border border-slate-200 bg-slate-50 p-2">
                  <div className="text-[10px] text-slate-500">Parentless Tok</div>
                  <div className="font-semibold text-slate-900">{ghostAssessment.parentless_tokens.length}</div>
                </div>
              </div>
              <div className="font-mono text-[11px] text-slate-600">
                Risk Flags:{" "}
                {ghostAssessment.risk_flags.length > 0
                  ? ghostAssessment.risk_flags.join(", ")
                  : "NONE"}
              </div>
            </div>
          ) : (
            <div className="px-5 py-6 text-xs text-slate-500">
              No Ghost Entity risk assessment available (node disconnected or proofs absent).
            </div>
          )}
        </section>
      </div>

      {/* Recent Canonical Events Table */}
      <section className="border border-slate-200 bg-white">
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3.5">
          <div>
            <h2 className="text-sm font-semibold text-slate-900">Recent Canonical Events</h2>
            <p className="text-xs text-slate-500">
              BLAKE3-hashed transitions ordered by logical clock
            </p>
          </div>
          <button
            type="button"
            onClick={() => onNavigate("dag")}
            className="text-xs font-medium text-blue-600 hover:text-blue-700"
          >
            Inspect Full DAG
          </button>
        </div>

        {recentEvents.length === 0 ? (
          <div className="px-5 py-8 text-center text-xs text-slate-500">
            No canonical events recorded yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                  <th className="px-5 py-2.5">Clock</th>
                  <th className="px-4 py-2.5">Operation</th>
                  <th className="px-4 py-2.5">Entity</th>
                  <th className="px-4 py-2.5">Event Hash</th>
                  <th className="px-4 py-2.5">Region / Kind</th>
                  <th className="px-5 py-2.5 text-right">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {recentEvents.map((ev) => (
                  <tr key={ev.event_hash} className="hover:bg-slate-50/80">
                    <td className="px-5 py-2.5 font-mono tabular-nums text-slate-600">
                      #{ev.logical_clock}
                    </td>
                    <td className="px-4 py-2.5 font-mono font-medium text-slate-900">
                      {extractOperationLabel(ev.operation)}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-slate-600">
                      {shortenHash(ev.entity_id, 12, 8)}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-slate-700">
                      {shortenHash(ev.event_hash, 12, 8)}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-slate-500">
                      {ev.region_id
                        ? shortenHash(ev.region_id, 10, 6)
                        : ev.entity_kind ?? "—"}
                    </td>
                    <td className="px-5 py-2.5 text-right font-mono tabular-nums text-slate-500">
                      {formatTimestampMs(ev.timestamp)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
