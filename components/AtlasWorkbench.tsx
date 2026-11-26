"use client";

import { useCallback, useState } from "react";
import {
  Activity,
  Coins,
  Cpu,
  GitBranch,
  Globe,
  KeyRound,
  Network,
  ShieldCheck,
  Terminal,
  Wallet,
  Menu,
  RefreshCw,
  X,
} from "lucide-react";
import { shortenHash } from "@/lib/format";
import type {
  BrowserSignerKey,
  CanonicalEventDto,
  ConsensusRoundDto,
  DrainPolicyDto,
  DrainRewardDto,
  NodeStatusDto,
  RegionDto,
  ReplayDto,
  SnapshotDto,
  TokenDto,
  ValidatorNodeDto,
  VectorRecordDto,
  VectorStateDto,
  WalletDto,
} from "@/lib/types";
import { DagInspectorPanel } from "./DagInspectorPanel";
import { OverviewPanel } from "./OverviewPanel";
import { RegionsPanel } from "./RegionsPanel";
import { SandboxPanel } from "./SandboxPanel";
import { TokensPanel } from "./TokensPanel";
import { VectorsPanel } from "./VectorsPanel";
import { WalletsPanel } from "./WalletsPanel";

type NavTab = "overview" | "regions" | "wallets" | "tokens" | "vectors" | "dag" | "sandbox";

interface AtlasWorkbenchProps {
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

const NAV_ITEMS: Array<{ id: NavTab; label: string; icon: typeof Activity }> = [
  { id: "overview", label: "Overview", icon: Activity },
  { id: "regions", label: "Regions", icon: Globe },
  { id: "wallets", label: "Wallets & Signers", icon: Wallet },
  { id: "tokens", label: "Tokens & Drain", icon: Coins },
  { id: "vectors", label: "Multidimensional Vectors", icon: Network },
  { id: "dag", label: "DAG & Consensus", icon: GitBranch },
  { id: "sandbox", label: "Opcode Sandbox", icon: Terminal },
];

export function AtlasWorkbench({
  initialStatus,
  initialRegions,
  initialWallets,
  initialTokens,
  initialVectors,
  initialRewards,
  initialValidators,
  initialRounds,
  initialEvents,
  initialRecords,
  initialSnapshots,
  drainPolicy,
  coreEventHash,
}: AtlasWorkbenchProps) {
  const [activeTab, setActiveTab] = useState<NavTab>("overview");
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const [status, setStatus] = useState<NodeStatusDto>(initialStatus);
  const [regions, setRegions] = useState<RegionDto[]>(initialRegions);
  const [wallets, setWallets] = useState<WalletDto[]>(initialWallets);
  const [tokens, setTokens] = useState<TokenDto[]>(initialTokens);
  const [vectors, setVectors] = useState<VectorStateDto[]>(initialVectors);
  const [rewards, setRewards] = useState<DrainRewardDto[]>(initialRewards);
  const [validators, setValidators] = useState<ValidatorNodeDto[]>(initialValidators);
  const [rounds, setRounds] = useState<ConsensusRoundDto[]>(initialRounds);
  const [events, setEvents] = useState<CanonicalEventDto[]>(initialEvents);
  const [records, setRecords] = useState<VectorRecordDto[]>(initialRecords);
  const [snapshots, setSnapshots] = useState<SnapshotDto[]>(initialSnapshots);

  // Client-side browser signer keyring
  const [signerKeys, setSignerKeys] = useState<Record<string, BrowserSignerKey>>({});
  const [activeSignerId, setActiveSignerId] = useState<string | null>(null);

  const [refreshing, setRefreshing] = useState(false);
  const [toast, setToast] = useState<{ kind: "success" | "error"; message: string } | null>(null);

  const notify = useCallback((kind: "success" | "error", message: string) => {
    setToast({ kind, message });
    setTimeout(() => {
      setToast((prev) => (prev?.message === message ? null : prev));
    }, 5000);
  }, []);

  const refreshAll = useCallback(async () => {
    setRefreshing(true);
    try {
      const [statusRes, regionsRes, walletsRes, tokensRes, vectorsRes, consensusRes, eventsRes, recordsRes, snapsRes] =
        await Promise.all([
          fetch("/api/status"),
          fetch("/api/regions"),
          fetch("/api/wallets"),
          fetch("/api/tokens"),
          fetch("/api/vectors"),
          fetch("/api/consensus"),
          fetch("/api/events"),
          fetch("/api/records"),
          fetch("/api/snapshot"),
        ]);

      if (statusRes.ok) setStatus((await statusRes.json()) as NodeStatusDto);
      if (regionsRes.ok) {
        const d = (await regionsRes.json()) as { regions: RegionDto[] };
        setRegions(d.regions);
      }
      if (walletsRes.ok) {
        const d = (await walletsRes.json()) as { wallets: WalletDto[] };
        setWallets(d.wallets);
      }
      if (tokensRes.ok) {
        const d = (await tokensRes.json()) as { tokens: TokenDto[] };
        setTokens(d.tokens);
      }
      if (vectorsRes.ok) {
        const d = (await vectorsRes.json()) as { vectors: VectorStateDto[]; rewards?: DrainRewardDto[] };
        setVectors(d.vectors ?? []);
        if (d.rewards) setRewards(d.rewards);
      }
      if (consensusRes.ok) {
        const d = (await consensusRes.json()) as { validators?: ValidatorNodeDto[]; rounds?: ConsensusRoundDto[] };
        if (d.validators) setValidators(d.validators);
        if (d.rounds) setRounds(d.rounds);
      }
      if (eventsRes.ok) {
        const d = (await eventsRes.json()) as { events: CanonicalEventDto[] };
        setEvents(d.events);
      }
      if (recordsRes.ok) {
        const d = (await recordsRes.json()) as { records: VectorRecordDto[] };
        setRecords(d.records);
      }
      if (snapsRes.ok) {
        const d = (await snapsRes.json()) as { snapshots: SnapshotDto[] };
        setSnapshots(d.snapshots);
      }
    } catch (err) {
      notify("error", err instanceof Error ? err.message : "Failed to refresh node state");
    } finally {
      setRefreshing(false);
    }
  }, [notify]);

  async function handleRunReplay(): Promise<ReplayDto | null> {
    const res = await fetch("/api/replay");
    const data = (await res.json()) as ReplayDto & { error?: string };
    if (!res.ok) {
      notify("error", data.error ?? "Replay verification failed");
      return null;
    }
    await refreshAll();
    notify(
      data.matches_stored_state ? "success" : "error",
      data.matches_stored_state
        ? `Replay verified (${data.applied_event_hashes.length} canonical events)`
        : `Replay mismatch: ${data.mismatch_reasons.join("; ")}`,
    );
    return data;
  }

  async function handleCreateSnapshot() {
    const res = await fetch("/api/snapshot", { method: "POST" });
    const data = (await res.json()) as { snapshot?: SnapshotDto; verified?: boolean; error?: string };
    if (!res.ok || !data.snapshot) {
      notify("error", data.error ?? "Snapshot creation failed");
      return;
    }
    await refreshAll();
    notify("success", `Snapshot ${shortenHash(data.snapshot.snapshot_id, 10, 6)} stored & verified`);
  }

  async function handleCreateBackup(filename?: string) {
    const res = await fetch("/api/backup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(filename ? { filename } : {}),
    });
    const data = (await res.json()) as { backup_path?: string; error?: string };
    if (!res.ok) {
      notify("error", data.error ?? "Backup failed");
      return;
    }
    notify("success", `Storage backup prepared at ${data.backup_path}`);
  }

  const activeSigner = activeSignerId ? signerKeys[activeSignerId] : null;
  const activeNav = NAV_ITEMS.find((i) => i.id === activeTab)!;

  return (
    <div className="flex min-h-screen bg-slate-50 text-slate-900">
      {/* Desktop Sidebar */}
      <aside className="hidden w-64 shrink-0 flex-col justify-between border-r border-slate-200 bg-white lg:flex">
        <div>
          <div className="border-b border-slate-200 px-5 py-4">
            <div className="flex items-center gap-2">
              <Cpu className="h-4 w-4 text-blue-600" />
              <span className="text-xs font-bold tracking-wide text-slate-900">
                ATLAS VECTOR NETWORK
              </span>
            </div>
            <div className="mt-1 font-mono text-[11px] text-slate-500">
              v-kernelx · {status.kernel_version}
            </div>
          </div>

          <nav className="space-y-0.5 p-3" aria-label="Primary Navigation">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              const active = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveTab(item.id)}
                  className={`flex w-full items-center gap-2.5 px-3 py-2 text-left text-xs font-medium transition-colors ${
                    active
                      ? "bg-slate-900 text-white"
                      : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
                  }`}
                >
                  <Icon className="h-3.5 w-3.5 shrink-0" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        <div className="border-t border-slate-200 p-4">
          <div className="mb-1 text-[10px] font-medium uppercase text-slate-400">Active Signer</div>
          <div className="font-mono text-xs font-semibold text-slate-800 truncate">
            {activeSigner ? activeSigner.label : "None Selected"}
          </div>
          <button
            type="button"
            onClick={() => setActiveTab("wallets")}
            className="mt-2.5 flex w-full items-center justify-center gap-1.5 border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-800 hover:bg-slate-50"
          >
            <KeyRound className="h-3.5 w-3.5 text-blue-600" />
            <span>Manage Keyrings</span>
          </button>
        </div>
      </aside>

      {/* Mobile Sidebar Drawer */}
      {sidebarOpen && (
        <div className="fixed inset-0 z-40 flex lg:hidden">
          <div
            className="fixed inset-0 bg-slate-900/40"
            onClick={() => setSidebarOpen(false)}
          />
          <aside className="relative z-50 flex w-64 flex-col justify-between bg-white">
            <div>
              <div className="flex items-center justify-between border-b border-slate-200 px-4 py-3.5">
                <span className="text-xs font-bold tracking-wide text-slate-900">
                  ATLAS VECTOR NETWORK
                </span>
                <button
                  type="button"
                  onClick={() => setSidebarOpen(false)}
                  className="p-1 text-slate-500"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
              <nav className="space-y-0.5 p-3">
                {NAV_ITEMS.map((item) => {
                  const Icon = item.icon;
                  const active = activeTab === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => {
                        setActiveTab(item.id);
                        setSidebarOpen(false);
                      }}
                      className={`flex w-full items-center gap-2.5 px-3 py-2 text-left text-xs font-medium ${
                        active ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-100"
                      }`}
                    >
                      <Icon className="h-3.5 w-3.5" />
                      <span>{item.label}</span>
                    </button>
                  );
                })}
              </nav>
            </div>
            <div className="border-t border-slate-200 p-4">
              <button
                type="button"
                onClick={() => {
                  setSidebarOpen(false);
                  setActiveTab("wallets");
                }}
                className="w-full border border-slate-300 bg-white px-3 py-2 text-xs font-medium text-slate-800"
              >
                {activeSigner ? `Signer: ${activeSigner.label}` : "Unlock Signer"}
              </button>
            </div>
          </aside>
        </div>
      )}

      {/* Main Content Shell */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* 3-Zone Top Bar */}
        <header className="sticky top-0 z-20 flex h-14 items-center justify-between gap-4 border-b border-slate-200 bg-white px-4 sm:px-6">
          <div className="flex min-w-0 items-center gap-3">
            <button
              type="button"
              onClick={() => setSidebarOpen(true)}
              className="p-1.5 text-slate-600 hover:bg-slate-100 lg:hidden"
              aria-label="Open navigation"
            >
              <Menu className="h-4 w-4" />
            </button>
            <div className="truncate text-xs">
              <span className="text-slate-400">ATLAS VECTOR NETWORK</span>
              <span className="mx-2 text-slate-300">/</span>
              <span className="font-semibold text-slate-900">{activeNav.label}</span>
            </div>
          </div>

          <div className="hidden items-center gap-2 font-mono text-[11px] text-slate-500 md:flex">
            <span>{regions[0]?.region_prefix ?? "ATL"}</span>
            <span>·</span>
            <span>{status.event_count} events</span>
            <span>·</span>
            <span
              className={
                status.replay_status === "VERIFIED"
                  ? "text-emerald-700"
                  : status.replay_status === "INVALID"
                    ? "text-red-700"
                    : "text-amber-700"
              }
            >
              replay {status.replay_status.toLowerCase()}
            </span>
          </div>

          <div className="flex shrink-0 items-center gap-2">
            <button
              type="button"
              onClick={() => void refreshAll()}
              disabled={refreshing}
              className="inline-flex items-center gap-1.5 whitespace-nowrap border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition-colors hover:bg-slate-50 disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
              <span>Refresh</span>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("wallets")}
              className={`inline-flex items-center gap-1.5 whitespace-nowrap px-3 py-1.5 text-xs font-medium transition-colors ${
                activeSigner
                  ? "border border-emerald-200 bg-emerald-50 text-emerald-800 hover:bg-emerald-100"
                  : "bg-blue-600 text-white hover:bg-blue-700"
              }`}
            >
              <KeyRound className="h-3.5 w-3.5" />
              <span>{activeSigner ? `Signer: ${activeSigner.label}` : "Unlock Signer"}</span>
            </button>
          </div>
        </header>

        {toast && (
          <div
            className={`border-b px-6 py-2.5 text-xs font-medium ${
              toast.kind === "success"
                ? "border-emerald-200 bg-emerald-50 text-emerald-900"
                : "border-red-200 bg-red-50 text-red-900"
            }`}
          >
            {toast.message}
          </div>
        )}

        <main className="mx-auto w-full max-w-7xl flex-1 p-4 sm:p-6">
          {activeTab === "overview" && (
            <OverviewPanel
              status={status}
              regions={regions}
              wallets={wallets}
              tokens={tokens}
              events={events}
              snapshots={snapshots}
              hasSession={true}
              onRunReplay={handleRunReplay}
              onCreateSnapshot={handleCreateSnapshot}
              onCreateBackup={() => handleCreateBackup()}
              onNavigate={(tab) => setActiveTab(tab)}
              onOpenAuth={() => setActiveTab("wallets")}
            />
          )}
          {activeTab === "regions" && (
            <RegionsPanel
              regions={regions}
              wallets={wallets}
              coreEventHash={coreEventHash}
              signerKeys={signerKeys}
              activeSignerId={activeSignerId}
              onOpenWallets={() => setActiveTab("wallets")}
              onRefresh={refreshAll}
              onNotify={notify}
            />
          )}
          {activeTab === "wallets" && (
            <WalletsPanel
              wallets={wallets}
              regions={regions}
              signerKeys={signerKeys}
              activeSignerId={activeSignerId}
              onSelectSigner={(id) => {
                setActiveSignerId(id);
                notify("success", "Active signer updated for signed ledger transactions.");
              }}
              onAddSigner={(key) => {
                setSignerKeys((prev) => ({ ...prev, [key.wallet_id]: key }));
                setActiveSignerId(key.wallet_id);
              }}
              onRefresh={refreshAll}
              onNotify={notify}
            />
          )}
          {activeTab === "tokens" && (
            <TokensPanel
              tokens={tokens}
              wallets={wallets}
              regions={regions}
              rewards={rewards}
              drainPolicy={drainPolicy}
              signerKeys={signerKeys}
              activeSignerId={activeSignerId}
              onOpenWallets={() => setActiveTab("wallets")}
              onRefresh={refreshAll}
              onNotify={notify}
            />
          )}
          {activeTab === "vectors" && (
            <VectorsPanel
              regions={regions}
              wallets={wallets}
              signerKeys={signerKeys}
              activeSignerId={activeSignerId}
              onOpenWallets={() => setActiveTab("wallets")}
              onRefresh={refreshAll}
              onNotify={notify}
            />
          )}
          {activeTab === "dag" && (
            <DagInspectorPanel
              events={events}
              records={records}
              snapshots={snapshots}
              hasSession={true}
              adminToken={null}
              onOpenAuth={() => setActiveTab("wallets")}
              onCreateSnapshot={handleCreateSnapshot}
              onCreateBackup={handleCreateBackup}
            />
          )}
          {activeTab === "sandbox" && <SandboxPanel />}
        </main>
      </div>
    </div>
  );
}
