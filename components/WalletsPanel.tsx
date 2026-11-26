"use client";

import { useState, type FormEvent } from "react";
import { Plus, ShieldCheck, Wallet } from "lucide-react";
import { formatTimestampMs, shortenHash } from "@/lib/format";
import { generateBrowserKeypair, derivePublicKeyFromPrivateHex, signBytesWithPrivateKey, canonicalRequestSigningBytesClient } from "@/lib/client-crypto";
import type { BrowserSignerKey, RegionDto, WalletDto } from "@/lib/types";

interface WalletsPanelProps {
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
  const [creatorWalletId, setCreatorWalletId] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Import existing keypair state
  const [importLabel, setImportLabel] = useState("");
  const [importPrivateHex, setImportPrivateHex] = useState("");
  const [importing, setImporting] = useState(false);

  // Newly issued custody card modal/banner state
  const [issuedCustody, setIssuedCustody] = useState<BrowserSignerKey | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  async function copyText(key: string, val: string) {
    try {
      await navigator.clipboard?.writeText(val);
    } catch {
      // ignore
    }
    setCopiedKey(key);
    setTimeout(() => setCopiedKey((prev) => (prev === key ? null : prev)), 1500);
  }

  async function handleCreateOpenWallet(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    try {
      const kp = await generateBrowserKeypair();
      const cleanLabel = label.trim() || "User Wallet";
      
      // Register public key with backend server
      const res = await fetch("/api/wallets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          mode: "register_pubkey",
          public_key_hex: kp.public_key_hex,
          label: cleanLabel,
          region_id: regionId || null,
          creator_wallet_id: creatorWalletId || null,
        }),
      });
      const data = (await res.json()) as { wallet?: WalletDto; error?: string };
      if (!res.ok || !data.wallet) {
        onNotify("error", data.error ?? "Wallet registration failed");
        return;
      }

      const signerKey: BrowserSignerKey = {
        wallet_id: data.wallet.wallet_id,
        public_key_hex: kp.public_key_hex,
        private_key_hex: kp.private_key_hex,
        label: cleanLabel,
      };

      onAddSigner(signerKey);
      setIssuedCustody(signerKey);
      setLabel("");
      await onRefresh();
      onNotify("success", `Created open wallet ${cleanLabel} (${data.wallet.wallet_id})`);
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
      const cleanLabel = importLabel.trim() || "Imported Keypair";

      const res = await fetch("/api/wallets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          mode: "register_pubkey",
          public_key_hex: pubkey,
          label: cleanLabel,
        }),
      });
      const data = (await res.json()) as { wallet?: WalletDto; error?: string };
      if (!res.ok || !data.wallet) {
        onNotify("error", data.error ?? "Failed to register imported pubkey");
        return;
      }

      const signerKey: BrowserSignerKey = {
        wallet_id: data.wallet.wallet_id,
        public_key_hex: pubkey,
        private_key_hex: cleanHex,
        label: cleanLabel,
      };

      onAddSigner(signerKey);
      setImportPrivateHex("");
      setImportLabel("");
      await onRefresh();
      onNotify("success", `Imported keypair for ${data.wallet.wallet_id}`);
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
                <span>Issued Keypair Custody (Save Your Private Key Securely)</span>
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
              Decentralized network rule: No admin holds your private key. It is issued exclusively on creation.
            </p>
            <div className="mt-3 space-y-2 font-mono">
              <div className="flex items-center justify-between bg-white p-2 border border-emerald-200">
                <span>Wallet ID: {issuedCustody.wallet_id}</span>
                <button
                  type="button"
                  onClick={() => copyText("wid", issuedCustody.wallet_id)}
                  className="text-blue-600 hover:underline"
                >
                  {copiedKey === "wid" ? "Copied!" : "Copy"}
                </button>
              </div>
              <div className="flex items-center justify-between bg-white p-2 border border-emerald-200">
                <span>Public Key: {shortenHash(issuedCustody.public_key_hex, 16, 12)}</span>
                <button
                  type="button"
                  onClick={() => copyText("pub", issuedCustody.public_key_hex)}
                  className="text-blue-600 hover:underline"
                >
                  {copiedKey === "pub" ? "Copied!" : "Copy Pubkey"}
                </button>
              </div>
              <div className="flex items-center justify-between bg-white p-2 border border-emerald-200">
                <span className="break-all">Private Key (Secret Hex): {issuedCustody.private_key_hex}</span>
                <button
                  type="button"
                  onClick={() => copyText("priv", issuedCustody.private_key_hex)}
                  className="shrink-0 ml-2 text-blue-600 hover:underline"
                >
                  {copiedKey === "priv" ? "Copied!" : "Copy Secret"}
                </button>
              </div>
            </div>
          </section>
        )}

        <section className="border border-slate-200 bg-white">
          <div className="border-b border-slate-200 px-5 py-3.5">
            <h2 className="text-sm font-semibold text-slate-900">Decentralized Wallets & Signers</h2>
            <p className="text-xs text-slate-500">
              Wallets carry public keys, auth ratios, and accumulated drain fee rewards
            </p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                  <th className="px-5 py-2.5">Wallet / Label</th>
                  <th className="px-4 py-2.5">Wallet ID</th>
                  <th className="px-4 py-2.5">Auth Ratio</th>
                  <th className="px-4 py-2.5 text-right">Drain Rewards</th>
                  <th className="px-5 py-2.5 text-right">Signer Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {wallets.map((w) => {
                  const isUnlocked = Boolean(signerKeys[w.wallet_id]);
                  const isSelected = activeSignerId === w.wallet_id;
                  const totalRewards = w.rewards.reduce((acc, r) => acc + BigInt(r.amount), 0n);
                  return (
                    <tr key={w.wallet_id} className="hover:bg-slate-50">
                      <td className="px-5 py-3">
                        <div className="font-semibold text-slate-900">{w.label}</div>
                        <div className="font-mono text-[11px] text-slate-400">
                          {w.region_id ? shortenHash(w.region_id, 10, 6) : "global"}
                          {` · rx=${w.receive_policy?.mode ?? "OPEN"}`}
                          {w.creator_wallet_id ? ` · creator=${shortenHash(w.creator_wallet_id, 8, 4)}` : ""}
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
                            <span className="text-slate-500">Unknown</span>
                            <div className="text-[10px] text-slate-400">Unverified / Unavailable</div>
                          </>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right font-mono tabular-nums text-emerald-700 font-semibold">
                        {totalRewards.toString()} units
                      </td>
                      <td className="px-5 py-3 text-right">
                        {isUnlocked ? (
                          <button
                            type="button"
                            onClick={() => onSelectSigner(w.wallet_id)}
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
          <div className="border-b border-slate-200 px-5 py-3.5">
            <h2 className="text-sm font-semibold text-slate-900">Create Open Wallet</h2>
            <p className="text-xs text-slate-500">No admin gates — issue new keys & earn drain rewards</p>
          </div>
          <form onSubmit={handleCreateOpenWallet} className="space-y-3.5 p-5 text-xs">
            <div>
              <label className="mb-1 block font-medium text-slate-700">Wallet Label</label>
              <input
                type="text"
                required
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="atlas-creator-wallet"
                className="w-full border border-slate-300 px-2.5 py-2 text-xs focus:border-blue-600 focus:outline-none"
              />
            </div>
            <div>
              <label className="mb-1 block font-medium text-slate-700">Region Association (Optional)</label>
              <select
                value={regionId}
                onChange={(e) => setRegionId(e.target.value)}
                className="w-full border border-slate-300 bg-white px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
              >
                <option value="">None (global)</option>
                {regions.map((r) => (
                  <option key={r.region_id} value={r.region_id}>
                    {r.region_name} ({r.region_prefix})
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block font-medium text-slate-700">Sponsor / Creator Wallet (Optional)</label>
              <select
                value={creatorWalletId}
                onChange={(e) => setCreatorWalletId(e.target.value)}
                className="w-full border border-slate-300 bg-white px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
              >
                <option value="">None (self-sponsored)</option>
                {wallets.map((w) => (
                  <option key={w.wallet_id} value={w.wallet_id}>
                    {w.label} ({shortenHash(w.wallet_id, 8, 6)})
                  </option>
                ))}
              </select>
            </div>
            <button
              type="submit"
              disabled={submitting}
              className="inline-flex w-full items-center justify-center gap-1.5 bg-blue-600 px-4 py-2.5 text-xs font-medium text-white transition-colors hover:bg-blue-700 disabled:opacity-50"
            >
              <Plus className="h-3.5 w-3.5" />
              {submitting ? "Generating Keypair..." : "Create Open Wallet & Keypair"}
            </button>
          </form>
        </section>

        <section className="border border-slate-200 bg-white">
          <div className="border-b border-slate-200 px-5 py-3.5">
            <h2 className="text-sm font-semibold text-slate-900">Unlock / Import Private Key</h2>
            <p className="text-xs text-slate-500">Paste your 64-char hex private signing key</p>
          </div>
          <form onSubmit={handleImportWallet} className="space-y-3.5 p-5 text-xs">
            <div>
              <label className="mb-1 block font-medium text-slate-700">Wallet Label</label>
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
              {importing ? "Importing..." : "Unlock & Register Signer"}
            </button>
          </form>
        </section>
      </div>
    </div>
  );
}
