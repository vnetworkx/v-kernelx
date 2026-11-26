"use client";

import { useState, type FormEvent } from "react";
import { Database, Search, ShieldCheck } from "lucide-react";
import {
  extractOperationLabel,
  formatTimestampMs,
  shortenHash,
} from "@/lib/format";
import type {
  CanonicalEventDto,
  SnapshotDto,
  VectorRecordDto,
} from "@/lib/types";

interface DagInspectorPanelProps {
  events: CanonicalEventDto[];
  records: VectorRecordDto[];
  snapshots: SnapshotDto[];
  hasSession: boolean;
  adminToken: string | null;
  onOpenAuth: () => void;
  onCreateSnapshot: () => Promise<void>;
  onCreateBackup: (filename?: string) => Promise<void>;
}

export function DagInspectorPanel({
  events,
  records,
  snapshots,
  hasSession,
  onOpenAuth,
  onCreateSnapshot,
  onCreateBackup,
}: DagInspectorPanelProps) {
  const [filterQuery, setFilterQuery] = useState("");
  const [lookupId, setLookupId] = useState("");
  const [lookupResult, setLookupResult] = useState<{
    record: VectorRecordDto | null;
    event: CanonicalEventDto | null;
  } | null>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [selectedPayload, setSelectedPayload] = useState<unknown>(
    events[events.length - 1] ?? records[records.length - 1] ?? null,
  );
  const [selectedTitle, setSelectedTitle] = useState<string>(
    events.length > 0 ? "Latest Canonical Event" : "Inspection Output",
  );
  const [backupFilename, setBackupFilename] = useState("");
  const [busyAction, setBusyAction] = useState<string | null>(null);

  const orderedEvents = [...events].reverse();
  const filteredEvents = orderedEvents.filter((ev) => {
    const q = filterQuery.trim().toLowerCase();
    if (!q) return true;
    return (
      ev.event_hash.toLowerCase().includes(q) ||
      ev.event_id.toLowerCase().includes(q) ||
      ev.entity_id.toLowerCase().includes(q) ||
      extractOperationLabel(ev.operation).toLowerCase().includes(q)
    );
  });

  const orderedRecords = [...records].reverse();
  const filteredRecords = orderedRecords.filter((rec) => {
    const q = filterQuery.trim().toLowerCase();
    if (!q) return true;
    const reqId = String((rec.parameters as Record<string, unknown> | undefined)?.request_id ?? "");
    return (
      rec.recordId.toLowerCase().includes(q) ||
      rec.vectorId.toLowerCase().includes(q) ||
      rec.operation.toLowerCase().includes(q) ||
      reqId.toLowerCase().includes(q)
    );
  });

  async function handleLookup(e: FormEvent) {
    e.preventDefault();
    const id = lookupId.trim();
    if (!id) return;
    setLookupError(null);
    try {
      const res = await fetch(`/api/transactions/${encodeURIComponent(id)}`);
      const data = (await res.json()) as {
        record?: VectorRecordDto | null;
        event?: CanonicalEventDto | null;
        error?: string;
      };
      if (!res.ok) {
        setLookupError(data.error ?? "Not found");
        setLookupResult(null);
        return;
      }
      const result = { record: data.record ?? null, event: data.event ?? null };
      setLookupResult(result);
      setSelectedTitle(`Transaction Lookup: ${shortenHash(id, 12, 8)}`);
      setSelectedPayload(result);
    } catch (err) {
      setLookupError(err instanceof Error ? err.message : "Lookup failed");
    }
  }

  async function handleSnapshot() {
    if (!hasSession) {
      onOpenAuth();
      return;
    }
    setBusyAction("snapshot");
    try {
      await onCreateSnapshot();
    } finally {
      setBusyAction(null);
    }
  }

  async function handleBackup(e: FormEvent) {
    e.preventDefault();
    if (!hasSession) {
      onOpenAuth();
      return;
    }
    setBusyAction("backup");
    try {
      await onCreateBackup(backupFilename || undefined);
      setBackupFilename("");
    } finally {
      setBusyAction(null);
    }
  }

  return (
    <div className="space-y-6">
      {/* Lookup & Filter Strip */}
      <div className="grid grid-cols-1 gap-4 border border-slate-200 bg-white p-4 lg:grid-cols-2">
        <form onSubmit={handleLookup} className="flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
            <input
              type="text"
              value={lookupId}
              onChange={(e) => setLookupId(e.target.value)}
              placeholder="Inspect by recordId, event_hash, event_id, or request_id..."
              className="w-full border border-slate-300 bg-white py-2 pl-8 pr-3 font-mono text-xs text-slate-900 focus:border-blue-600 focus:outline-none"
            />
          </div>
          <button
            type="submit"
            className="whitespace-nowrap bg-slate-900 px-3.5 py-2 text-xs font-medium text-white hover:bg-slate-800"
          >
            Inspect ID
          </button>
        </form>

        <div className="flex items-center gap-2">
          <input
            type="search"
            value={filterQuery}
            onChange={(e) => setFilterQuery(e.target.value)}
            placeholder="Filter visible DAG events & vector records..."
            className="w-full border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-900 focus:border-blue-600 focus:bg-white focus:outline-none"
          />
        </div>

        {lookupError && (
          <div className="text-xs text-red-700 lg:col-span-2">{lookupError}</div>
        )}
        {lookupResult && !lookupError && (
          <div className="font-mono text-xs text-emerald-700 lg:col-span-2">
            Match loaded in inspector ({lookupResult.record ? "VectorRecord" : ""}{" "}
            {lookupResult.event ? "CanonicalEvent" : ""})
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        {/* Events & Records Tables */}
        <div className="space-y-6 xl:col-span-2">
          <section className="border border-slate-200 bg-white">
            <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3.5">
              <h2 className="text-sm font-semibold text-slate-900">
                Canonical Event DAG ({filteredEvents.length})
              </h2>
              <span className="font-mono text-[11px] text-slate-500">
                Click any row to inspect payload & signature
              </span>
            </div>
            <div className="max-h-80 overflow-auto">
              <table className="w-full border-collapse text-left text-xs">
                <thead className="sticky top-0 bg-slate-50">
                  <tr className="border-b border-slate-200 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                    <th className="px-5 py-2.5">Clock</th>
                    <th className="px-4 py-2.5">Operation</th>
                    <th className="px-4 py-2.5">Event Hash</th>
                    <th className="px-4 py-2.5">Parents</th>
                    <th className="px-5 py-2.5 text-right">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filteredEvents.map((ev) => (
                    <tr
                      key={ev.event_hash}
                      onClick={() => {
                        setSelectedTitle(`Event #${ev.logical_clock} · ${extractOperationLabel(ev.operation)}`);
                        setSelectedPayload(ev);
                      }}
                      className="cursor-pointer hover:bg-blue-50/50"
                    >
                      <td className="px-5 py-2.5 font-mono tabular-nums text-slate-700">
                        #{ev.logical_clock}
                      </td>
                      <td className="px-4 py-2.5 font-mono font-medium text-slate-900">
                        {extractOperationLabel(ev.operation)}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-slate-600">
                        {shortenHash(ev.event_hash, 12, 8)}
                      </td>
                      <td className="px-4 py-2.5 font-mono tabular-nums text-slate-500">
                        {ev.parent_hashes.length === 0
                          ? "genesis"
                          : shortenHash(ev.parent_hashes[0], 8, 6)}
                      </td>
                      <td className="px-5 py-2.5 text-right font-mono tabular-nums text-slate-500">
                        {formatTimestampMs(ev.timestamp)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="border border-slate-200 bg-white">
            <div className="border-b border-slate-200 px-5 py-3.5">
              <h2 className="text-sm font-semibold text-slate-900">
                Vector Transition Records ({filteredRecords.length})
              </h2>
            </div>
            <div className="max-h-72 overflow-auto">
              <table className="w-full border-collapse text-left text-xs">
                <thead className="sticky top-0 bg-slate-50">
                  <tr className="border-b border-slate-200 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                    <th className="px-5 py-2.5">Record ID</th>
                    <th className="px-4 py-2.5">Operation</th>
                    <th className="px-4 py-2.5">Vector ID</th>
                    <th className="px-5 py-2.5 text-right">Proof</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filteredRecords.map((rec) => (
                    <tr
                      key={rec.recordId}
                      onClick={() => {
                        setSelectedTitle(`Record ${shortenHash(rec.recordId, 10, 6)}`);
                        setSelectedPayload(rec);
                      }}
                      className="cursor-pointer hover:bg-blue-50/50"
                    >
                      <td className="px-5 py-2.5 font-mono text-slate-700">
                        {shortenHash(rec.recordId, 12, 8)}
                      </td>
                      <td className="px-4 py-2.5 font-mono font-medium text-slate-900">
                        {String(
                          (rec.parameters as Record<string, unknown> | undefined)?.custom_operation ??
                            rec.operation,
                        )}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-slate-600">
                        {shortenHash(rec.vectorId, 10, 6)}
                      </td>
                      <td className="px-5 py-2.5 text-right font-mono text-slate-500">
                        {shortenHash(rec.proof, 8, 6)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>

        {/* Right Detail & Snapshots Column */}
        <div className="space-y-6">
          <section className="border border-slate-200 bg-white">
            <div className="border-b border-slate-200 px-5 py-3.5">
              <h3 className="text-sm font-semibold text-slate-900">{selectedTitle}</h3>
            </div>
            <pre className="max-h-96 overflow-auto bg-slate-950 p-4 font-mono text-[11px] leading-relaxed text-slate-200">
              {selectedPayload ? JSON.stringify(selectedPayload, null, 2) : "Select an event or record"}
            </pre>
          </section>

          <section className="border border-slate-200 bg-white">
            <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3.5">
              <div>
                <h3 className="text-sm font-semibold text-slate-900">
                  Snapshots ({snapshots.length})
                </h3>
                <p className="text-[11px] text-slate-500">Canonical state checkpoints</p>
              </div>
              <button
                type="button"
                onClick={handleSnapshot}
                disabled={busyAction !== null}
                className="inline-flex items-center gap-1 border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-xs font-medium text-slate-800 hover:bg-slate-100"
              >
                <ShieldCheck className="h-3.5 w-3.5 text-blue-600" />
                {busyAction === "snapshot" ? "Saving..." : "Create"}
              </button>
            </div>
            {snapshots.length === 0 ? (
              <div className="px-5 py-4 text-xs text-slate-500">No snapshots saved yet.</div>
            ) : (
              <div className="max-h-48 divide-y divide-slate-100 overflow-auto px-5 text-xs">
                {snapshots.map((snap) => (
                  <div
                    key={snap.snapshot_id}
                    onClick={() => {
                      setSelectedTitle(`Snapshot ${shortenHash(snap.snapshot_id, 10, 6)}`);
                      setSelectedPayload(snap);
                    }}
                    className="cursor-pointer py-2.5 hover:text-blue-600"
                  >
                    <div className="font-mono font-medium text-slate-800">
                      {shortenHash(snap.snapshot_id, 14, 10)}
                    </div>
                    <div className="font-mono text-[11px] text-slate-500">
                      events={snap.event_count} · clock={snap.logical_clock} ·{" "}
                      {formatTimestampMs(snap.created_at)}
                    </div>
                  </div>
                ))}
              </div>
            )}

            <form
              onSubmit={handleBackup}
              className="space-y-2 border-t border-slate-200 bg-slate-50/70 p-4 text-xs"
            >
              <label className="block text-[11px] font-medium uppercase tracking-wider text-slate-500">
                WAL &amp; Checkpoint Backup
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={backupFilename}
                  onChange={(e) => setBackupFilename(e.target.value)}
                  placeholder="atlas-backup.db (optional)"
                  className="min-w-0 flex-1 border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs focus:border-blue-600 focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={busyAction !== null}
                  className="inline-flex items-center gap-1 whitespace-nowrap border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-800 hover:bg-slate-100"
                >
                  <Database className="h-3.5 w-3.5" />
                  {busyAction === "backup" ? "Writing..." : "Backup"}
                </button>
              </div>
            </form>
          </section>
        </div>
      </div>
    </div>
  );
}
