"use client";

import { useState, type FormEvent } from "react";
import { Ghost, Globe, Lock, Plus } from "lucide-react";
import { formatTimestampMs, shortenHash } from "@/lib/format";
import { signTransactionEnvelopeClient } from "@/lib/client-crypto";
import type { BrowserSignerKey, RegionDto, SpaceDto } from "@/lib/types";

interface RegionsPanelProps {
  networkId: string;
  spaces: SpaceDto[];
  regions: RegionDto[];
  signerKeys: Record<string, BrowserSignerKey>;
  activeSignerId: string | null;
  onOpenWallets: () => void;
  onRefresh: () => Promise<void>;
  onNotify: (kind: "success" | "error", msg: string) => void;
}

export function RegionsPanel({
  networkId,
  spaces,
  regions,
  signerKeys,
  activeSignerId,
  onOpenWallets,
  onRefresh,
  onNotify,
}: RegionsPanelProps) {
  const [formKind, setFormKind] = useState<"region" | "space">("region");
  const [spaceId, setSpaceId] = useState(spaces[0]?.space_id ?? "");
  const [regionName, setRegionName] = useState("");
  const [regionPrefix, setRegionPrefix] = useState("");
  const [suggestedTitle, setSuggestedTitle] = useState("");
  const [visibility, setVisibility] = useState<"public" | "private">("public");
  const [section, setSection] = useState("1");
  const [ghostMode, setGhostMode] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const [selectedRegion, setSelectedRegion] = useState<RegionDto | null>(regions[0] ?? null);
  const [liveCheckResult, setLiveCheckResult] = useState<string | null>(null);

  const activeSigner = activeSignerId ? signerKeys[activeSignerId] : null;

  async function handleCreateSignedEntity(e: FormEvent) {
    e.preventDefault();
    if (!activeSigner) {
      onNotify("error", "No active signer keypair unlocked. Generate or import one in Wallets.");
      onOpenWallets();
      return;
    }

    setSubmitting(true);
    try {
      const cleanName = regionName.trim();
      const requestId = `req_${formKind}_${Date.now()}`;
      const nonce = Date.now();
      const timestampMs = Date.now();

      const operation =
        formKind === "space"
          ? {
              op: "CreateSpace",
              payload: {
                name: cleanName,
                visibility: visibility.toUpperCase(),
                ghost: ghostMode,
              },
            }
          : {
              op: "CreateRegion",
              payload: {
                space_id: ghostMode ? "" : spaceId.trim(),
                name: cleanName,
                prefix: regionPrefix.trim() || null,
                title: suggestedTitle.trim() || null,
                visibility: visibility.toUpperCase(),
                section: Number(section) || 1,
                ghost: ghostMode,
              },
            };

      const envelope = await signTransactionEnvelopeClient({
        privateKeyHex: activeSigner.private_key_hex,
        actorPubkey: activeSigner.public_key_hex,
        networkId,
        requestId,
        nonce,
        timestampMs,
        operation,
      });

      const res = await fetch("/api/regions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(envelope),
      });
      const data = (await res.json()) as {
        entity_id?: string;
        event_id?: string;
        error?: string;
      };
      if (!res.ok) {
        onNotify("error", data.error ?? `Failed to create ${formKind}`);
        return;
      }

      setRegionName("");
      setRegionPrefix("");
      setSuggestedTitle("");
      await onRefresh();
      onNotify(
        "success",
        `Committed ${formKind} transaction (${data.entity_id ?? data.event_id ?? "ok"})`,
      );
    } catch (err) {
      onNotify("error", err instanceof Error ? err.message : "Signed submission failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function inspectLiveRegion(region: RegionDto) {
    const res = await fetch(`/api/regions/${encodeURIComponent(region.region_id)}`);
    const data = (await res.json()) as { region?: RegionDto; error?: string };
    if (!res.ok || !data.region) {
      setLiveCheckResult(data.error ?? "Region lookup failed");
      return;
    }
    setLiveCheckResult(
      `Confirmed on node: space=${data.region.space_id || "NETWORK (Ghost)"} · version=${data.region.version}`,
    );
  }

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
      <div className="space-y-6 xl:col-span-2">
        <section className="border border-slate-200 bg-white">
          <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3.5">
            <div>
              <h2 className="text-sm font-semibold text-slate-900">Hierarchical Spaces ({spaces.length})</h2>
              <p className="text-xs text-slate-500">Top-level containers below Network governance</p>
            </div>
          </div>
          {spaces.length === 0 ? (
            <div className="px-5 py-6 text-xs text-slate-500">No Spaces registered yet.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                    <th className="px-5 py-2.5">Space</th>
                    <th className="px-4 py-2.5">Space ID</th>
                    <th className="px-4 py-2.5">Visibility / Ghost</th>
                    <th className="px-5 py-2.5 text-right">Owner</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {spaces.map((sp) => (
                    <tr key={sp.space_id} className="hover:bg-slate-50">
                      <td className="px-5 py-2.5 font-semibold text-slate-900">{sp.name}</td>
                      <td className="px-4 py-2.5 font-mono text-slate-700">{sp.space_id}</td>
                      <td className="px-4 py-2.5 font-mono uppercase text-slate-600">
                        {sp.visibility} {sp.ghost ? "· GHOST" : ""}
                      </td>
                      <td className="px-5 py-2.5 text-right font-mono text-slate-500">
                        {shortenHash(sp.owner_pubkey, 10, 6)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="border border-slate-200 bg-white">
          <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3.5">
            <div>
              <h2 className="text-sm font-semibold text-slate-900">Canonical Region Registry</h2>
              <p className="text-xs text-slate-500">
                {regions.length} registered {regions.length === 1 ? "region" : "regions"} · BFT finalized
              </p>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                  <th className="px-5 py-2.5">Region</th>
                  <th className="px-4 py-2.5">Canonical ID</th>
                  <th className="px-4 py-2.5">Scope / Ghost</th>
                  <th className="px-4 py-2.5 text-right">Section</th>
                  <th className="px-5 py-2.5 text-right">Created</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {regions.map((region) => {
                  const isSelected = selectedRegion?.region_id === region.region_id;
                  return (
                    <tr
                      key={region.region_id}
                      onClick={() => {
                        setSelectedRegion(region);
                        setLiveCheckResult(null);
                      }}
                      className={`cursor-pointer transition-colors ${
                        isSelected ? "bg-blue-50/60" : "hover:bg-slate-50"
                      }`}
                    >
                      <td className="px-5 py-3">
                        <div className="font-semibold text-slate-900">{region.region_name}</div>
                        <div className="text-[11px] text-slate-500">
                          {region.suggested_title ?? "Untitled"}
                          {region.region_prefix ? ` · ${region.region_prefix}` : ""}
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-700">{region.region_id}</td>
                      <td className="px-4 py-3 font-mono text-slate-700">
                        <span className="inline-flex items-center gap-1 uppercase">
                          {region.ghost ? (
                            <Ghost className="h-3 w-3 text-purple-600" />
                          ) : region.visibility === "private" ? (
                            <Lock className="h-3 w-3 text-amber-600" />
                          ) : (
                            <Globe className="h-3 w-3 text-emerald-600" />
                          )}
                          {region.visibility}
                          {region.ghost ? " · GHOST" : ""}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right font-mono tabular-nums text-slate-700">
                        {region.section ?? "—"}
                      </td>
                      <td className="px-5 py-3 text-right font-mono tabular-nums text-slate-500">
                        {formatTimestampMs(region.created_at_ms)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>

        {selectedRegion && (
          <section className="border border-slate-200 bg-white">
            <div className="border-b border-slate-200 px-5 py-3.5">
              <h3 className="text-sm font-semibold text-slate-900">
                Region Inspection · {selectedRegion.region_name}
              </h3>
            </div>
            <div className="divide-y divide-slate-100 px-5 text-xs">
              <div className="flex flex-col justify-between gap-1 py-2.5 sm:flex-row">
                <span className="text-slate-500">Canonical ID</span>
                <code className="font-mono text-slate-900">{selectedRegion.region_id}</code>
              </div>
              <div className="flex flex-col justify-between gap-1 py-2.5 sm:flex-row">
                <span className="text-slate-500">Parent Space</span>
                <code className="font-mono text-slate-700">
                  {selectedRegion.space_id || "NETWORK (Parentless Ghost)"}
                </code>
              </div>
              <div className="flex flex-col justify-between gap-1 py-2.5 sm:flex-row">
                <span className="text-slate-500">Creator Public Key</span>
                <code className="break-all font-mono text-slate-700">
                  {selectedRegion.creator_public_key}
                </code>
              </div>
              <div className="flex flex-col justify-between gap-1 py-2.5 sm:flex-row">
                <span className="text-slate-500">Creation Event</span>
                <code className="break-all font-mono text-slate-700">
                  {selectedRegion.trigger_event_hash ?? "Unavailable"}
                </code>
              </div>
              <div className="flex flex-col justify-between gap-1 py-2.5 sm:flex-row">
                <span className="text-slate-500">Certified Quorum Certificate</span>
                <code className="break-all font-mono text-slate-700">
                  {selectedRegion.creation_proof_hash ?? "Unverified / Unavailable"}
                </code>
              </div>
              <div className="flex flex-col justify-between gap-1 py-2.5 sm:flex-row">
                <span className="text-slate-500">Auth Ratio</span>
                <code className="font-mono text-slate-700">
                  {selectedRegion.auth_ratio_bps != null
                    ? `${selectedRegion.auth_ratio_bps} bps`
                    : "Unavailable"}
                </code>
              </div>
              <div className="flex flex-wrap items-center justify-between gap-2 py-3">
                <button
                  type="button"
                  onClick={() => void inspectLiveRegion(selectedRegion)}
                  className="border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-800 hover:bg-slate-100"
                >
                  Confirm Live Node State
                </button>
                {liveCheckResult && (
                  <span className="font-mono text-xs text-slate-700">{liveCheckResult}</span>
                )}
              </div>
            </div>
          </section>
        )}
      </div>

      <section className="h-fit border border-slate-200 bg-white">
        <div className="border-b border-slate-200 px-5 py-3.5">
          <h2 className="text-sm font-semibold text-slate-900">Register Signed Space / Region</h2>
          <p className="text-xs text-slate-500">
            Signed client-side as a Rust SignedOperationHttpRequest
          </p>
        </div>
        <div className="grid grid-cols-2 border-b border-slate-200 bg-slate-50 text-xs font-medium">
          <button
            type="button"
            onClick={() => setFormKind("region")}
            className={`border-r border-slate-200 py-2 ${formKind === "region" ? "bg-white font-semibold text-blue-600" : "text-slate-600"}`}
          >
            Create Region
          </button>
          <button
            type="button"
            onClick={() => setFormKind("space")}
            className={`py-2 ${formKind === "space" ? "bg-white font-semibold text-blue-600" : "text-slate-600"}`}
          >
            Create Space
          </button>
        </div>

        <form onSubmit={handleCreateSignedEntity} className="space-y-3.5 p-5 text-xs">
          <div>
            <label className="mb-1 block font-medium text-slate-700">Active Signer</label>
            <div className="rounded border border-slate-200 bg-slate-50 p-2.5 font-mono text-xs text-slate-800">
              {activeSigner ? (
                <div>
                  <div className="font-semibold text-slate-900">{activeSigner.label}</div>
                  <div className="text-[11px] text-slate-500">{shortenHash(activeSigner.public_key_hex, 12, 8)}</div>
                </div>
              ) : (
                <div className="flex items-center justify-between text-amber-700">
                  <span>No signer unlocked</span>
                  <button
                    type="button"
                    onClick={onOpenWallets}
                    className="text-blue-600 underline"
                  >
                    Unlock in Wallets
                  </button>
                </div>
              )}
            </div>
          </div>

          {formKind === "region" && !ghostMode && (
            <div>
              <label className="mb-1 block font-medium text-slate-700">Parent Space</label>
              <select
                value={spaceId}
                onChange={(e) => setSpaceId(e.target.value)}
                required={!ghostMode}
                className="w-full border border-slate-300 bg-white px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
              >
                <option value="">Select parent Space...</option>
                {spaces.map((sp) => (
                  <option key={sp.space_id} value={sp.space_id}>
                    {sp.name} ({sp.space_id})
                  </option>
                ))}
              </select>
            </div>
          )}

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="mb-1 block font-medium text-slate-700">
                {formKind === "space" ? "Space Name" : "Region Name"}
              </label>
              <input
                type="text"
                required
                value={regionName}
                onChange={(e) => setRegionName(e.target.value)}
                placeholder={formKind === "space" ? "core-space" : "NEXUS"}
                className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
              />
            </div>
            {formKind === "region" && (
              <div>
                <label className="mb-1 block font-medium text-slate-700">Prefix</label>
                <input
                  type="text"
                  value={regionPrefix}
                  onChange={(e) => setRegionPrefix(e.target.value)}
                  placeholder="NXS"
                  className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>
            )}
          </div>

          {formKind === "region" && (
            <div>
              <label className="mb-1 block font-medium text-slate-700">Title</label>
              <input
                type="text"
                value={suggestedTitle}
                onChange={(e) => setSuggestedTitle(e.target.value)}
                placeholder="Nexus Vector Region"
                className="w-full border border-slate-300 px-2.5 py-2 text-xs focus:border-blue-600 focus:outline-none"
              />
            </div>
          )}

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="mb-1 block font-medium text-slate-700">Visibility</label>
              <select
                value={visibility}
                onChange={(e) => setVisibility(e.target.value as "public" | "private")}
                className="w-full border border-slate-300 bg-white px-2.5 py-2 text-xs focus:border-blue-600 focus:outline-none"
              >
                <option value="public">public</option>
                <option value="private">private</option>
              </select>
            </div>
            {formKind === "region" && (
              <div>
                <label className="mb-1 block font-medium text-slate-700">Section</label>
                <input
                  type="number"
                  min={1}
                  value={section}
                  onChange={(e) => setSection(e.target.value)}
                  className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>
            )}
          </div>

          <label className="flex cursor-pointer items-center gap-2 text-xs text-slate-700">
            <input
              type="checkbox"
              checked={ghostMode}
              onChange={(e) => setGhostMode(e.target.checked)}
              className="h-3.5 w-3.5 accent-purple-600"
            />
            Ghost Entity (requires Network-level participant scope; parentless when Ghost Region)
          </label>

          <button
            type="submit"
            disabled={submitting || !activeSigner}
            className="inline-flex w-full items-center justify-center gap-1.5 bg-blue-600 px-4 py-2.5 text-xs font-medium text-white transition-colors hover:bg-blue-700 disabled:opacity-50"
          >
            <Plus className="h-3.5 w-3.5" />
            {submitting ? "Submitting Signed Tx..." : `Submit Signed ${formKind === "space" ? "CreateSpace" : "CreateRegion"}`}
          </button>
        </form>
      </section>
    </div>
  );
}
