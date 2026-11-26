"use client";

import { useEffect, useState, type FormEvent } from "react";
import { Check, Copy, Network, Plus, ShieldCheck } from "lucide-react";
import { formatTimestampMs, shortenHash } from "@/lib/format";
import {
  canonicalVectorOpSigningBytes,
  findBlake3NonceClient,
  signBytesWithPrivateKey,
} from "@/lib/client-crypto";
import type {
  BrowserSignerKey,
  ConsensusRoundDto,
  RegionDto,
  SyncBundle,
  ValidatorNodeDto,
  VectorStateDto,
  WalletDto,
} from "@/lib/types";

interface VectorsPanelProps {
  regions: RegionDto[];
  wallets: WalletDto[];
  signerKeys: Record<string, BrowserSignerKey>;
  activeSignerId: string | null;
  onOpenWallets: () => void;
  onRefresh: () => Promise<void>;
  onNotify: (kind: "success" | "error", msg: string) => void;
}

type VecOpMode = "origin" | "transport" | "transfer" | "project" | "reconstruct" | "certify" | "drain";

export function VectorsPanel({
  regions,
  wallets,
  signerKeys,
  activeSignerId,
  onOpenWallets,
  onRefresh,
  onNotify,
}: VectorsPanelProps) {
  const [vectors, setVectors] = useState<VectorStateDto[]>([]);
  const [loading, setLoading] = useState(true);
  const [mode, setMode] = useState<VecOpMode>("origin");
  const [selectedVectorId, setSelectedVectorId] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Form fields
  const [vectorIdInput, setVectorIdInput] = useState("");
  const [spaceIdInput, setSpaceIdInput] = useState(regions[0]?.region_id ?? "");
  const [componentsInput, setComponentsInput] = useState("1000,2000");
  const [labelsInput, setLabelsInput] = useState("Compute,Storage");

  // Transport & Transfer fields
  const [targetVectorId, setTargetVectorId] = useState("");
  const [amountInput, setAmountInput] = useState("100,200");

  // Escrow / Projection / Reconstruct
  const [escrowIdInput, setEscrowIdInput] = useState("escrow-1");
  const [gainsInput, setGainsInput] = useState("10,10");
  const [lossesInput, setLossesInput] = useState("0,0");
  const [outcomeTagInput, setOutcomeTagInput] = useState("settled");
  const [drainBpsInput, setDrainBpsInput] = useState("");

  const activeSigner = activeSignerId ? signerKeys[activeSignerId] : null;
  const activeVector = vectors.find((v) => v.vectorId === selectedVectorId) ?? vectors[0] ?? null;

  async function loadVectors() {
    try {
      const res = await fetch("/api/vectors");
      if (res.ok) {
        const data = (await res.json()) as { vectors?: VectorStateDto[] };
        setVectors(data.vectors ?? []);
        if (!selectedVectorId && data.vectors?.[0]) {
          setSelectedVectorId(data.vectors[0].vectorId);
        }
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadVectors();
  }, []);

  async function handleVectorOp(e: FormEvent) {
    e.preventDefault();
    if (!activeSigner) {
      onNotify("error", "No active signer wallet unlocked. Unlock or create one in Wallets.");
      onOpenWallets();
      return;
    }

    setSubmitting(true);
    try {
      const requestId = `vec_op_${Date.now()}`;
      let body: Record<string, unknown> = {};

      if (mode === "origin") {
        const vId = vectorIdInput.trim();
        const space = spaceIdInput.trim();
        const comps = componentsInput.split(",").map((s) => Number(s.trim())).filter(Number.isInteger);
        const labels = labelsInput.split(",").map((s) => s.trim()).filter(Boolean);

        const seed = `vector-origin-${vId}`;
        const { nonce } = findBlake3NonceClient(seed, 1);

        const params = {
          components: comps,
          difficulty: 1,
          nonce,
          seed,
          space_id: space,
          vector_id: vId,
        };
        const signingBytes = canonicalVectorOpSigningBytes("VECTOR_ORIGIN_CREATE", requestId, activeSigner.public_key_hex, params);
        const signature = await signBytesWithPrivateKey(activeSigner.private_key_hex, signingBytes);

        body = {
          action: "origin",
          request_id: requestId,
          vector_id: vId,
          space_id: space,
          components: comps,
          dimension_labels: labels,
          seed,
          nonce,
          difficulty: 1,
          actor_public_key: activeSigner.public_key_hex,
          signature,
        };
      } else if (mode === "transfer") {
        const comps = amountInput.split(",").map((s) => Number(s.trim())).filter(Number.isInteger);
        const params = {
          amount: comps,
          from_vector_id: activeVector?.vectorId,
          to_vector_id: targetVectorId,
        };
        const signingBytes = canonicalVectorOpSigningBytes("VECTOR_TRANSFER", requestId, activeSigner.public_key_hex, params);
        const signature = await signBytesWithPrivateKey(activeSigner.private_key_hex, signingBytes);

        body = {
          action: "transfer",
          request_id: requestId,
          from_vector_id: activeVector?.vectorId,
          to_vector_id: targetVectorId,
          amount: comps,
          actor_public_key: activeSigner.public_key_hex,
          signature,
        };
      } else if (mode === "project") {
        const comps = amountInput.split(",").map((s) => Number(s.trim())).filter(Number.isInteger);
        const params = {
          escrow_id: escrowIdInput,
          projected_components: comps,
          vector_id: activeVector?.vectorId,
        };
        const signingBytes = canonicalVectorOpSigningBytes("VECTOR_PROJECT", requestId, activeSigner.public_key_hex, params);
        const signature = await signBytesWithPrivateKey(activeSigner.private_key_hex, signingBytes);

        body = {
          action: "project",
          request_id: requestId,
          vector_id: activeVector?.vectorId,
          projected_components: comps,
          escrow_id: escrowIdInput,
          actor_public_key: activeSigner.public_key_hex,
          signature,
        };
      } else if (mode === "reconstruct") {
        const gains = gainsInput.split(",").map((s) => Number(s.trim())).filter(Number.isInteger);
        const losses = lossesInput.split(",").map((s) => Number(s.trim())).filter(Number.isInteger);
        const params = {
          gains,
          losses,
          outcome_tag: outcomeTagInput,
          vector_id: activeVector?.vectorId,
        };
        const signingBytes = canonicalVectorOpSigningBytes("VECTOR_RECONSTRUCT", requestId, activeSigner.public_key_hex, params);
        const signature = await signBytesWithPrivateKey(activeSigner.private_key_hex, signingBytes);

        body = {
          action: "reconstruct",
          request_id: requestId,
          vector_id: activeVector?.vectorId,
          gains,
          losses,
          outcome_tag: outcomeTagInput,
          actor_public_key: activeSigner.public_key_hex,
          signature,
        };
      } else if (mode === "certify") {
        const params = { vector_id: activeVector?.vectorId };
        const signingBytes = canonicalVectorOpSigningBytes("VECTOR_CERTIFY", requestId, activeSigner.public_key_hex, params);
        const signature = await signBytesWithPrivateKey(activeSigner.private_key_hex, signingBytes);

        body = {
          action: "certify",
          request_id: requestId,
          vector_id: activeVector?.vectorId,
          actor_public_key: activeSigner.public_key_hex,
          signature,
        };
      } else if (mode === "drain") {
        const bps = Number(drainBpsInput);
        if (!Number.isInteger(bps) || bps <= 0 || bps > 10_000) {
          onNotify("error", "Enter an explicit drain rate between 1 and 10000 bps");
          return;
        }
        const params = { basis_points: bps, vector_id: activeVector?.vectorId };
        const signingBytes = canonicalVectorOpSigningBytes("VECTOR_DRAIN", requestId, activeSigner.public_key_hex, params);
        const signature = await signBytesWithPrivateKey(activeSigner.private_key_hex, signingBytes);

        body = {
          action: "drain",
          request_id: requestId,
          vector_id: activeVector?.vectorId,
          basis_points: bps,
          actor_public_key: activeSigner.public_key_hex,
          signature,
        };
      }

      const res = await fetch("/api/vectors/action", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = (await res.json()) as { error?: string };
      if (!res.ok) {
        onNotify("error", data.error ?? "Vector operation failed");
        return;
      }

      await loadVectors();
      await onRefresh();
      onNotify("success", `Executed multidimensional vector operation (${mode})`);
    } catch (err) {
      onNotify("error", err instanceof Error ? err.message : "Request failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
      <div className="space-y-6 xl:col-span-2">
        <section className="border border-slate-200 bg-white">
          <div className="border-b border-slate-200 px-5 py-3.5">
            <h2 className="text-sm font-semibold text-slate-900">Multidimensional Vector States</h2>
            <p className="text-xs text-slate-500">
              Persistent N-dimensional balances, auth ratios, escrow projections & settlements
            </p>
          </div>

          {loading ? (
            <div className="px-5 py-8 text-xs text-slate-500">Loading vectors...</div>
          ) : vectors.length === 0 ? (
            <div className="px-5 py-8 text-center text-xs text-slate-500">
              No vectors created yet. Use the action console to create an origin vector.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                    <th className="px-5 py-2.5">Vector ID / Space</th>
                    <th className="px-4 py-2.5">Type & Status</th>
                    <th className="px-4 py-2.5">Auth Ratio</th>
                    <th className="px-5 py-2.5 text-right">Components [D0, D1, ...]</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {vectors.map((vec) => {
                    const isSelected = activeVector?.vectorId === vec.vectorId;
                    return (
                      <tr
                        key={vec.vectorId}
                        onClick={() => setSelectedVectorId(vec.vectorId)}
                        className={`cursor-pointer transition-colors ${
                          isSelected ? "bg-blue-50/60" : "hover:bg-slate-50"
                        }`}
                      >
                        <td className="px-5 py-3">
                          <div className="font-semibold text-slate-900">{vec.vectorId}</div>
                          <div className="font-mono text-[11px] text-slate-400">
                            space={shortenHash(vec.spaceId, 10, 6)} · owner={shortenHash(vec.ownerPubkey, 8, 6)}
                          </div>
                        </td>
                        <td className="px-4 py-3 font-mono text-slate-700">
                          <div>{vec.vectorType}</div>
                          <div className="text-[10px] text-slate-400">{vec.status}</div>
                        </td>
                        <td className="px-4 py-3 font-mono tabular-nums">
                          <span className={vec.certification.certified ? "text-emerald-700 font-semibold" : "text-amber-700"}>
                            {vec.certification.authRatio} / 1000
                          </span>
                          <div className="text-[10px] text-slate-400">
                            {vec.certification.certified ? "Certified" : "Uncertified"}
                          </div>
                        </td>
                        <td className="px-5 py-3 text-right font-mono font-semibold tabular-nums text-slate-900">
                          [{vec.components.join(", ")}]
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      <section className="h-fit border border-slate-200 bg-white">
        <div className="border-b border-slate-200 px-5 py-3.5">
          <h2 className="text-sm font-semibold text-slate-900">Multidimensional Vector Action Console</h2>
          <p className="text-xs text-slate-500">Signed with active Ed25519 signer wallet</p>
        </div>

        <div className="grid grid-cols-4 border-b border-slate-200 bg-slate-50 text-[10px] font-medium">
          {(
            [
              { id: "origin", label: "Origin" },
              { id: "transfer", label: "Transfer" },
              { id: "project", label: "Project" },
              { id: "reconstruct", label: "Reconstruct" },
              { id: "certify", label: "Certify" },
              { id: "drain", label: "Drain" },
            ] as const
          ).map((tab) => {
            const active = mode === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setMode(tab.id as VecOpMode)}
                className={`border-r border-b border-slate-200 py-2 text-center ${
                  active ? "bg-white font-semibold text-blue-600" : "text-slate-600 hover:bg-slate-100"
                }`}
              >
                {tab.label}
              </button>
            );
          })}
        </div>

        <form onSubmit={handleVectorOp} className="space-y-3.5 p-5 text-xs">
          <div>
            <label className="mb-1 block font-medium text-slate-700">Active Signer</label>
            <div className="rounded border border-slate-200 bg-slate-50 p-2 font-mono text-xs">
              {activeSigner ? activeSigner.label : "No signer selected"}
            </div>
          </div>

          {mode !== "origin" && (
            <div>
              <label className="mb-1 block font-medium text-slate-700">Target Vector</label>
              <select
                value={activeVector?.vectorId ?? ""}
                onChange={(e) => setSelectedVectorId(e.target.value)}
                className="w-full border border-slate-300 bg-white px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
              >
                {vectors.map((v) => (
                  <option key={v.vectorId} value={v.vectorId}>
                    {v.vectorId} ([{v.components.join(", ")}])
                  </option>
                ))}
              </select>
            </div>
          )}

          {mode === "origin" && (
            <>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Vector ID</label>
                <input
                  type="text"
                  required
                  value={vectorIdInput}
                  onChange={(e) => setVectorIdInput(e.target.value)}
                  placeholder="v-alpha"
                  className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Space / Region</label>
                <select
                  value={spaceIdInput}
                  onChange={(e) => setSpaceIdInput(e.target.value)}
                  className="w-full border border-slate-300 bg-white px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                >
                  {regions.map((r) => (
                    <option key={r.region_id} value={r.region_id}>
                      {r.region_name} ({r.region_id})
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Components (comma separated integers)</label>
                <input
                  type="text"
                  required
                  value={componentsInput}
                  onChange={(e) => setComponentsInput(e.target.value)}
                  placeholder="1000,2000"
                  className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Dimension Labels</label>
                <input
                  type="text"
                  value={labelsInput}
                  onChange={(e) => setLabelsInput(e.target.value)}
                  placeholder="Compute,Storage"
                  className="w-full border border-slate-300 px-2.5 py-2 text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>
            </>
          )}

          {mode === "transfer" && (
            <>
              <div>
                <label className="mb-1 block font-medium text-slate-700">To Vector ID</label>
                <input
                  type="text"
                  required
                  value={targetVectorId}
                  onChange={(e) => setTargetVectorId(e.target.value)}
                  placeholder="v-beta"
                  className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Transfer Amounts per Dimension</label>
                <input
                  type="text"
                  required
                  value={amountInput}
                  onChange={(e) => setAmountInput(e.target.value)}
                  placeholder="250,250"
                  className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>
            </>
          )}

          {mode === "project" && (
            <>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Escrow ID</label>
                <input
                  type="text"
                  required
                  value={escrowIdInput}
                  onChange={(e) => setEscrowIdInput(e.target.value)}
                  className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Projected Components</label>
                <input
                  type="text"
                  required
                  value={amountInput}
                  onChange={(e) => setAmountInput(e.target.value)}
                  placeholder="100,100"
                  className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>
            </>
          )}

          {mode === "reconstruct" && (
            <>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Gains per Dimension</label>
                <input
                  type="text"
                  required
                  value={gainsInput}
                  onChange={(e) => setGainsInput(e.target.value)}
                  placeholder="20,10"
                  className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Losses per Dimension</label>
                <input
                  type="text"
                  required
                  value={lossesInput}
                  onChange={(e) => setLossesInput(e.target.value)}
                  placeholder="5,2"
                  className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Outcome Tag</label>
                <input
                  type="text"
                  required
                  value={outcomeTagInput}
                  onChange={(e) => setOutcomeTagInput(e.target.value)}
                  className="w-full border border-slate-300 px-2.5 py-2 text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>
            </>
          )}

          {mode === "drain" && (
            <div>
              <label className="mb-1 block font-medium text-slate-700">Basis Points (bps)</label>
              <input
                type="number"
                min={1}
                max={10000}
                value={drainBpsInput}
                onChange={(e) => setDrainBpsInput(e.target.value)}
                className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
              />
            </div>
          )}

          <button
            type="submit"
            disabled={submitting || !activeSigner}
            className="w-full bg-blue-600 px-4 py-2.5 text-xs font-medium text-white transition-colors hover:bg-blue-700 disabled:opacity-50"
          >
            {submitting ? "Executing Signed Vector Op..." : `Execute ${mode.toUpperCase()}`}
          </button>
        </form>
      </section>
    </div>
  );
}
