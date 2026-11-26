"use client";

import { useState, type FormEvent } from "react";
import { KeyRound, Plus, ShieldCheck } from "lucide-react";
import { shortenHash } from "@/lib/format";
import {
  derivePublicKeyFromPrivateHex,
  deriveWalletIdClient,
  generateBrowserKeypair,
  signTransactionEnvelopeClient,
} from "@/lib/client-crypto";
import type { BrowserSignerKey, RegionDto, WalletDto } from "@/lib/types";

interface WalletsPanelProps {
  networkId: string;
  wallets: WalletDto[];
  regions: RegionDto[];
  signerKeys: Record<string, BrowserSignerKey>;
  activeSignerId: string | null;
  onSelectSigner: (walletId: string) => void;
  onAddSigner: (key: BrowserSignerKey) => void;
  onRefresh: () => Promise<void>;
  onNotify: (kind: "success" | "error", msg: string) => void;
}

export function WalletsPanel({
  networkId,
  wallets,
  regions,
  signerKeys,
  activeSignerId,
  onSelectSigner,
  onAddSigner,
  onRefresh,
  onNotify,
}: WalletsPanelProps) {
  const [label, setLabel] = useState("");
  const [regionId, setRegionId] = useState(regions[0]?.region_id ?? "");
  const [ghostWallet, setGhostWallet] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const [importLabel, setImportLabel] = useState("");
  const [importPrivateHex, setImportPrivateHex] = useState("");
  const [importing, setImporting] = useState(false);

  const [issuedCustody, setIssuedCustody] = useState<BrowserSignerKey | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const activeSigner = activeSignerId ? signerKeys[activeSignerId] : null;

  async function copyText(key: string, val: string) {
    try {
      await navigator.clipboard?.writeText(val);
    } catch {
      // ignore
    }
    setCopiedKey(key);
    setTimeout(() => setCopiedKey((prev) => (prev === key ? null : prev)), 1500);
  }

  async function handleGenerateKeypair() {
    const kp = await generateBrowserKeypair();
    const signerKey: BrowserSignerKey = {
      wallet_id: kp.wallet_id,
      public_key_hex: kp.public_key_hex,
      private_key_hex: kp.private_key_hex,
      label: label.trim() || "Ephemeral Ed25519 Keypair",
    };
    onAddSigner(signerKey);
    setIssuedCustody(signerKey);
    onNotify("success", `Generated in-memory Ed25519 signer (${shortenHash(kp.public_key_hex, 12, 8)})`);
  }

  async function handleCreateOnChainWallet(e: FormEvent) {
    e.preventDefault();
    const signerToUse = activeSigner;
    if (!signerToUse) {
      await handleGenerateKeypair();
      onNotify("error", "Unlocked a fresh signer keypair. Register participant scope if required, then click Submit CreateWallet.");
      return;
    }

    setSubmitting(true);
    try {
      const cleanName = label.trim() || "User Wallet";
      const envelope = await signTransactionEnvelopeClient({
        privateKeyHex: signerToUse.private_key_hex,
        actorPubkey: signerToUse.public_key_hex,
        networkId,
        requestId: `wlt_${Date.now()}`,
        nonce: Date.now(),
        timestampMs: Date.now(),
        operation: {
          op: "CreateWallet",
          payload: {
            region_id: ghostWallet ? "" : regionId.trim(),
            name: cleanName,
            ghost: ghostWallet,
          },
        },
      });

      const res = await fetch("/api/wallets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(envelope),
      });
      const data = (await res.json()) as { entity_id?: string; error?: string };
      if (!res.ok) {
        onNotify("error", data.error ?? "CreateWallet transaction rejected");
        return;
      }

      if (data.entity_id) {
        onAddSigner({
          ...signerToUse,
          wallet_id: data.entity_id,
          label: cleanName,
        });
      }
      setLabel("");
      await onRefresh();
      onNotify("success", `Created on-chain wallet ${cleanName} (${data.entity_id ?? "ok"})`);
    } catch (err) {
      onNotify("error", err instanceof Error ? err.message : "Failed to create wallet");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleImportWallet(e: FormEvent) {
    e.preventDefault();
    setImporting(true);
    try {
      const cleanHex = importPrivateHex.trim().toLowerCase();
      const pubkey = await derivePublicKeyFromPrivateHex(cleanHex);
      const matchingWallet = wallets.find((w) => w.public_key_hex.toLowerCase() === pubkey);
      const cleanLabel = importLabel.trim() || matchingWallet?.label || "Imported Keypair";

      const signerKey: BrowserSignerKey = {
        wallet_id: matchingWallet?.wallet_id ?? deriveWalletIdClient(pubkey),
        public_key_hex: pubkey,
        private_key_hex: cleanHex,
        label: cleanLabel,
      };

      onAddSigner(signerKey);
      setImportPrivateHex("");
      setImportLabel("");
      onNotify("success", `Loaded in-memory signer ${cleanLabel} (${shortenHash(pubkey, 10, 6)})`);
    } catch (err) {
      onNotify("error", err instanceof Error ? err.message : "Invalid private signing key");
    } finally {
      setImporting(false);
    }
  }

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
      <div className="space-y-6 xl:col-span-2">
        {issuedCustody && (
          <section className="border border-emerald-300 bg-emerald-50/70 p-5 text-xs">
            <div className="flex items-center justify-between border-b border-emerald-200 pb-3">
              <div className="flex items-center gap-2 font-semibold text-emerald-900">
                <ShieldCheck className="h-4 w-4 text-emerald-600" />
                <span>Ephemeral Browser Keypair Generated (Held in Memory Only)</span>
              </div>
              <button
                type="button"
                onClick={() => setIssuedCustody(null)}
                className="text-emerald-700 hover:text-emerald-900"
              >
                Dismiss
              </button>
            </div>
            <p className="mt-2 text-emerald-800">
              Private keys stay in browser memory only and are never written to localStorage or sent to the server.
            </p>
            <div className="mt-3 space-y-2 font-mono">
              <div className="flex items-center justify-between border border-emerald-200 bg-white p-2">
                <span>Derived ID: {issuedCustody.wallet_id}</span>
                <button
                  type="button"
                  onClick={() => copyText("wid", issuedCustody.wallet_id)}
                  className="text-blue-600 hover:underline"
                >
                  {copiedKey === "wid" ? "Copied!" : "Copy"}
                </button>
              </div>
              <div className="flex items-center justify-between border border-emerald-200 bg-white p-2">
                <span>Public Key: {shortenHash(issuedCustody.public_key_hex, 16, 12)}</span>
                <button
                  type="button"
                  onClick={() => copyText("pub", issuedCustody.public_key_hex)}
                  className="text-blue-600 hover:underline"
                >
                  {copiedKey === "pub" ? "Copied!" : "Copy Pubkey"}
                </button>
              </div>
              <div className="flex items-center justify-between border border-emerald-200 bg-white p-2">
                <span className="break-all">Private Key Hex: {issuedCustody.private_key_hex}</span>
                <button
                  type="button"
                  onClick={() => copyText("priv", issuedCustody.private_key_hex)}
                  className="ml-2 shrink-0 text-blue-600 hover:underline"
                >
                  {copiedKey === "priv" ? "Copied!" : "Copy Secret"}
                </button>
              </div>
            </div>
          </section>
        )}

        <section className="border border-slate-200 bg-white">
          <div className="border-b border-slate-200 px-5 py-3.5">
            <h2 className="text-sm font-semibold text-slate-900">Ledger Wallets &amp; Matching Signers</h2>
            <p className="text-xs text-slate-500">
              Wallets authorize keys on-chain via signed Ed25519 envelopes
            </p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                  <th className="px-5 py-2.5">Wallet / Label</th>
                  <th className="px-4 py-2.5">Wallet ID</th>
                  <th className="px-4 py-2.5">Auth Ratio</th>
                  <th className="px-4 py-2.5 text-right">Balances</th>
                  <th className="px-5 py-2.5 text-right">Signer Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {wallets.map((w) => {
                  const matchingKey = Object.values(signerKeys).find(
                    (k) => k.wallet_id === w.wallet_id || k.public_key_hex.toLowerCase() === w.public_key_hex.toLowerCase(),
                  );
                  const isSelected = Boolean(matchingKey && activeSignerId === matchingKey.wallet_id);
                  return (
                    <tr key={w.wallet_id} className="hover:bg-slate-50">
                      <td className="px-5 py-3">
                        <div className="font-semibold text-slate-900">
                          {w.label} {w.ghost ? "· GHOST" : ""}
                        </div>
                        <div className="font-mono text-[11px] text-slate-400">
                          {w.region_id ? shortenHash(w.region_id, 10, 6) : "NETWORK (Ghost)"}
                          {` · rx=${w.receive_policy?.mode ?? "OPEN"}`}
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-700">{w.wallet_id}</td>
                      <td className="px-4 py-3 font-mono tabular-nums text-slate-800">
                        {w.auth_ratio !== null ? (
                          <>
                            <span
                              className={
                                w.auth_ratio >= 700
                                  ? "font-semibold text-emerald-700"
                                  : "text-amber-700"
                              }
                            >
                              {w.auth_ratio} / 1000
                            </span>
                            <div className="text-[10px] text-slate-400">
                              {w.auth_ratio >= 700 ? "Discount tier (>=700)" : "Standard tier (<700)"}
                            </div>
                          </>
                        ) : (
                          <>
                            <span className="text-slate-500">Unavailable</span>
                            <div className="text-[10px] text-slate-400">No balance ratio recorded</div>
                          </>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right font-mono tabular-nums text-slate-700">
                        {w.balances.length} token(s)
                      </td>
                      <td className="px-5 py-3 text-right">
                        {matchingKey ? (
                          <button
                            type="button"
                            onClick={() => onSelectSigner(matchingKey.wallet_id)}
                            className={`border px-2.5 py-1 text-xs font-medium ${
                              isSelected
                                ? "border-emerald-600 bg-emerald-600 text-white"
                                : "border-emerald-200 bg-emerald-50 text-emerald-800 hover:bg-emerald-100"
                            }`}
                          >
                            {isSelected ? "Active Signer" : "Select Signer"}
                          </button>
                        ) : (
                          <span className="font-mono text-[11px] text-slate-400">Locked (Import Key)</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      <div className="space-y-6">
        <section className="border border-slate-200 bg-white">
          <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3.5">
            <div>
              <h2 className="text-sm font-semibold text-slate-900">Create On-Chain Wallet</h2>
              <p className="text-xs text-slate-500">Submit signed CreateWallet envelope</p>
            </div>
            <button
              type="button"
              onClick={() => void handleGenerateKeypair()}
              className="inline-flex items-center gap-1 border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] font-medium text-slate-700 hover:bg-slate-100"
            >
              <KeyRound className="h-3 w-3" />
              New Keypair
            </button>
          </div>
          <form onSubmit={handleCreateOnChainWallet} className="space-y-3.5 p-5 text-xs">
            <div>
              <label className="mb-1 block font-medium text-slate-700">Wallet Name</label>
              <input
                type="text"
                required
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="treasury-wallet"
                className="w-full border border-slate-300 px-2.5 py-2 text-xs focus:border-blue-600 focus:outline-none"
              />
            </div>
            {!ghostWallet && (
              <div>
                <label className="mb-1 block font-medium text-slate-700">Region Association</label>
                <select
                  value={regionId}
                  onChange={(e) => setRegionId(e.target.value)}
                  required={!ghostWallet}
                  className="w-full border border-slate-300 bg-white px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                >
                  <option value="">Select Region...</option>
                  {regions.map((r) => (
                    <option key={r.region_id} value={r.region_id}>
                      {r.region_name} ({r.region_prefix ?? r.region_id})
                    </option>
                  ))}
                </select>
              </div>
            )}
            <label className="flex cursor-pointer items-center gap-2 text-xs text-slate-700">
              <input
                type="checkbox"
                checked={ghostWallet}
                onChange={(e) => setGhostWallet(e.target.checked)}
                className="h-3.5 w-3.5 accent-purple-600"
              />
              Ghost Wallet (parentless under Network scope)
            </label>
            <button
              type="submit"
              disabled={submitting}
              className="inline-flex w-full items-center justify-center gap-1.5 bg-blue-600 px-4 py-2.5 text-xs font-medium text-white transition-colors hover:bg-blue-700 disabled:opacity-50"
            >
              <Plus className="h-3.5 w-3.5" />
              {submitting ? "Submitting CreateWallet..." : activeSigner ? "Sign & Create On-Chain Wallet" : "Generate Ephemeral Signer"}
            </button>
          </form>
        </section>

        <section className="border border-slate-200 bg-white">
          <div className="border-b border-slate-200 px-5 py-3.5">
            <h2 className="text-sm font-semibold text-slate-900">Import Ed25519 Private Key</h2>
            <p className="text-xs text-slate-500">Held in browser memory for current session only</p>
          </div>
          <form onSubmit={handleImportWallet} className="space-y-3.5 p-5 text-xs">
            <div>
              <label className="mb-1 block font-medium text-slate-700">Signer Label</label>
              <input
                type="text"
                required
                value={importLabel}
                onChange={(e) => setImportLabel(e.target.value)}
                placeholder="My Keypair"
                className="w-full border border-slate-300 px-2.5 py-2 text-xs focus:border-blue-600 focus:outline-none"
              />
            </div>
            <div>
              <label className="mb-1 block font-medium text-slate-700">Private Key Hex (32 bytes / 64 hex)</label>
              <input
                type="password"
                required
                value={importPrivateHex}
                onChange={(e) => setImportPrivateHex(e.target.value)}
                placeholder="64-character hex seed..."
                className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
              />
            </div>
            <button
              type="submit"
              disabled={importing}
              className="w-full bg-slate-900 px-4 py-2 text-xs font-medium text-white hover:bg-slate-800 disabled:opacity-50"
            >
              {importing ? "Importing..." : "Load In-Memory Signer"}
            </button>
          </form>
        </section>
      </div>
    </div>
  );
}
