"use client";

import { useState, type FormEvent } from "react";
import { Globe, Lock, Plus } from "lucide-react";
import { formatTimestampMs, shortenHash } from "@/lib/format";
import {
  canonicalRegionRequestSignatureBytesClient,
  findBlake3NonceClient,
  signBytesWithPrivateKey,
} from "@/lib/client-crypto";
import type { BrowserSignerKey, RegionDto, WalletDto } from "@/lib/types";

interface RegionsPanelProps {
  regions: RegionDto[];
  wallets: WalletDto[];
  coreEventHash: string;
  signerKeys: Record<string, BrowserSignerKey>;
  activeSignerId: string | null;
  onOpenWallets: () => void;
  onRefresh: () => Promise<void>;
  onNotify: (kind: "success" | "error", msg: string) => void;
}

export function RegionsPanel({
  regions,
  wallets,
  coreEventHash,
  signerKeys,
  activeSignerId,
  onOpenWallets,
  onRefresh,
  onNotify,
}: RegionsPanelProps) {
  const [regionName, setRegionName] = useState("");
  const [regionPrefix, setRegionPrefix] = useState("");
  const [suggestedTitle, setSuggestedTitle] = useState("");
  const [visibility, setVisibility] = useState<"public" | "private">("public");
  const [section, setSection] = useState("1");
  const [accessKey, setAccessKey] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const [selectedRegion, setSelectedRegion] = useState<RegionDto | null>(regions[0] ?? null);
  const [verifyKeyInput, setVerifyKeyInput] = useState("");
  const [authCheckResult, setAuthCheckResult] = useState<string | null>(null);

  const activeSigner = activeSignerId ? signerKeys[activeSignerId] : null;

  async function handleCreateSignedRegion(e: FormEvent) {
    e.preventDefault();
    if (!activeSigner) {
      onNotify("error", "No active signer wallet unlocked. Unlock or create one in Wallets.");
      onOpenWallets();
      return;
    }

    setSubmitting(true);
    try {
      const name = regionName.trim();
      const prefix = regionPrefix.trim() || null;
      const title = suggestedTitle.trim() || null;
      const sec = Number(section) || 1;

      const proofSeed = `${name}:${prefix ?? ""}:${coreEventHash}`;
      const { nonce, proofHash } = findBlake3NonceClient(proofSeed, 1);
      const creationProof = `${proofSeed}:${nonce}:${proofHash}`;

      const unsignedRequest = {
        access_key: visibility === "private" && accessKey ? accessKey : null,
        creation_proof: creationProof,
        metadata: {},
        region_name: name,
        region_prefix: prefix,
        section: sec,
        suggested_title: title,
        trigger_event_hash: coreEventHash,
        visibility,
        request_signature: "",
      };

      const signBytes = canonicalRegionRequestSignatureBytesClient(unsignedRequest);
      const signature = await signBytesWithPrivateKey(activeSigner.private_key_hex, signBytes);

      const signedRequest = {
        ...unsignedRequest,
        request_signature: signature,
      };

      const res = await fetch("/api/regions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          signed_request: signedRequest,
          actor_public_key: activeSigner.public_key_hex,
        }),
      });
      const data = (await res.json()) as { region?: RegionDto; error?: string };
      if (!res.ok || !data.region) {
        onNotify("error", data.error ?? "Failed to create region");
        return;
      }

      setRegionName("");
      setRegionPrefix("");
      setSuggestedTitle("");
      setAccessKey("");
      setSelectedRegion(data.region);
      await onRefresh();
      onNotify("success", `Registered region ${data.region.region_name} (${data.region.region_id})`);
    } catch (err) {
      onNotify("error", err instanceof Error ? err.message : "Request failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function checkRegionAuthorization(region: RegionDto) {
    const query = verifyKeyInput ? `?access_key=${encodeURIComponent(verifyKeyInput)}` : "";
    const res = await fetch(`/api/regions/${encodeURIComponent(region.region_id)}${query}`);
    const data = (await res.json()) as { authorized?: boolean; error?: string };
    if (!res.ok) {
      setAuthCheckResult(data.error ?? "Check failed");
      return;
    }
    setAuthCheckResult(
      data.authorized ? "Authorized (access granted)" : "Denied (invalid or missing access key)",
    );
  }

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
      <div className="space-y-6 xl:col-span-2">
        <section className="border border-slate-200 bg-white">
          <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3.5">
            <div>
              <h2 className="text-sm font-semibold text-slate-900">Canonical Region Registry</h2>
              <p className="text-xs text-slate-500">
                {regions.length} registered {regions.length === 1 ? "region" : "regions"} · decentralized BFT genesis
              </p>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                  <th className="px-5 py-2.5">Region</th>
                  <th className="px-4 py-2.5">Canonical ID</th>
                  <th className="px-4 py-2.5">Visibility</th>
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
                        setAuthCheckResult(null);
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
                          {region.visibility === "private" ? (
                            <Lock className="h-3 w-3 text-amber-600" />
                          ) : (
                            <Globe className="h-3 w-3 text-emerald-600" />
                          )}
                          {region.visibility}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right font-mono tabular-nums text-slate-700">
                        {region.section}
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
                <span className="text-slate-500">Creator Public Key</span>
                <code className="break-all font-mono text-slate-700">
                  {selectedRegion.creator_public_key}
                </code>
              </div>
              <div className="flex flex-col justify-between gap-1 py-2.5 sm:flex-row">
                <span className="text-slate-500">Genesis Region Root</span>
                <code className="break-all font-mono text-slate-700">
                  {selectedRegion.region_root}
                </code>
              </div>
              <div className="flex flex-col justify-between gap-2 py-3 sm:flex-row sm:items-center">
                <span className="text-slate-500">Authorization Verification</span>
                <div className="flex flex-wrap items-center gap-2">
                  {selectedRegion.visibility === "private" && (
                    <input
                      type="password"
                      value={verifyKeyInput}
                      onChange={(e) => setVerifyKeyInput(e.target.value)}
                      placeholder="Region access key"
                      className="border border-slate-300 px-2.5 py-1.5 font-mono text-xs focus:border-blue-600 focus:outline-none"
                    />
                  )}
                  <button
                    type="button"
                    onClick={() => void checkRegionAuthorization(selectedRegion)}
                    className="border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-800 hover:bg-slate-100"
                  >
                    Verify Access
                  </button>
                  {authCheckResult && (
                    <span className="font-mono text-xs text-slate-700">{authCheckResult}</span>
                  )}
                </div>
              </div>
            </div>
          </section>
        )}
      </div>

      <section className="h-fit border border-slate-200 bg-white">
        <div className="border-b border-slate-200 px-5 py-3.5">
          <h2 className="text-sm font-semibold text-slate-900">Register Signed Region</h2>
          <p className="text-xs text-slate-500">
            Signed client-side via active Ed25519 signer wallet
          </p>
        </div>
        <form onSubmit={handleCreateSignedRegion} className="space-y-3.5 p-5 text-xs">
          <div>
            <label className="mb-1 block font-medium text-slate-700">Active Signer</label>
            <div className="rounded border border-slate-200 bg-slate-50 p-2.5 font-mono text-xs text-slate-800">
              {activeSigner ? (
                <div>
                  <div className="font-semibold text-slate-900">{activeSigner.label}</div>
                  <div className="text-[11px] text-slate-500">{shortenHash(activeSigner.wallet_id, 10, 6)}</div>
                </div>
              ) : (
                <div className="flex items-center justify-between text-amber-700">
                  <span>No signer selected</span>
                  <button
                    type="button"
                    onClick={onOpenWallets}
                    className="text-blue-600 underline"
                  >
                    Select in Wallets
                  </button>
                </div>
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="mb-1 block font-medium text-slate-700">Region Name</label>
              <input
                type="text"
                required
                value={regionName}
                onChange={(e) => setRegionName(e.target.value)}
                placeholder="NEXUS"
                className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
              />
            </div>
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
          </div>

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
          </div>

          {visibility === "private" && (
            <div>
              <label className="mb-1 block font-medium text-slate-700">Private Access Key</label>
              <input
                type="password"
                required
                value={accessKey}
                onChange={(e) => setAccessKey(e.target.value)}
                placeholder="Secret access key"
                className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
              />
            </div>
          )}

          <button
            type="submit"
            disabled={submitting || !activeSigner}
            className="inline-flex w-full items-center justify-center gap-1.5 bg-blue-600 px-4 py-2.5 text-xs font-medium text-white transition-colors hover:bg-blue-700 disabled:opacity-50"
          >
            <Plus className="h-3.5 w-3.5" />
            {submitting ? "Signing Genesis Event..." : "Create Signed Region"}
          </button>
        </form>
      </section>
    </div>
  );
}
