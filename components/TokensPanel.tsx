"use client";

import { useState, type FormEvent } from "react";
import { ArrowRightLeft, Flame, Plus } from "lucide-react";
import {
  deriveTransferScopeClient,
  formatTimestampMs,
  formatTokenUnitsClient,
  parseDecimalToAtomic,
  previewDrainClient,
  resolveScopeDrainBps,
  shortenHash,
} from "@/lib/format";
import { signTransactionEnvelopeClient } from "@/lib/client-crypto";
import type {
  BrowserSignerKey,
  DrainPolicyDto,
  DrainRewardDto,
  TokenDto,
  WalletDto,
} from "@/lib/types";

interface TokensPanelProps {
  networkId: string;
  tokens: TokenDto[];
  wallets: WalletDto[];
  rewards: DrainRewardDto[];
  drainPolicy?: DrainPolicyDto | null;
  signerKeys: Record<string, BrowserSignerKey>;
  activeSignerId: string | null;
  onOpenWallets: () => void;
  onRefresh: () => Promise<void>;
  onNotify: (kind: "success" | "error", msg: string) => void;
}

type OpMode = "transfer" | "burn" | "create";

export function TokensPanel({
  networkId,
  tokens,
  wallets,
  rewards,
  drainPolicy,
  signerKeys,
  activeSignerId,
  onOpenWallets,
  onRefresh,
  onNotify,
}: TokensPanelProps) {
  const [mode, setMode] = useState<OpMode>("transfer");
  const [selectedTokenId, setSelectedTokenId] = useState(tokens[0]?.token_id ?? "");
  const [submitting, setSubmitting] = useState(false);

  const [fromWallet, setFromWallet] = useState(wallets[0]?.wallet_id ?? "");
  const [toWallet, setToWallet] = useState(wallets[1]?.wallet_id ?? wallets[0]?.wallet_id ?? "");
  const [amountInput, setAmountInput] = useState("100");
  const [useAtomicUnits, setUseAtomicUnits] = useState(false);

  const [newTokenName, setNewTokenName] = useState("");
  const [newTokenSymbol, setNewTokenSymbol] = useState("");
  const [newTokenWallet, setNewTokenWallet] = useState(wallets[0]?.wallet_id ?? "");
  const [newTokenInitialSupply, setNewTokenInitialSupply] = useState("1000000");
  const [newTokenMaxSupply, setNewTokenMaxSupply] = useState("10000000");
  const [newTokenPolicy, setNewTokenPolicy] = useState("Bounded vector token");
  const [newTokenDrainBps, setNewTokenDrainBps] = useState("100");
  const [ghostToken, setGhostToken] = useState(false);

  const activeToken =
    tokens.find((t) => t.token_id === selectedTokenId) ?? tokens[0] ?? null;

  const activeSigner = activeSignerId ? signerKeys[activeSignerId] : null;
  const fromWalletObj =
    wallets.find((w) => w.wallet_id === (fromWallet || activeSigner?.wallet_id)) ?? null;
  const toWalletObj = wallets.find((w) => w.wallet_id === toWallet) ?? null;
  const transferScope = deriveTransferScopeClient(fromWalletObj, toWalletObj);
  const authRatio = fromWalletObj?.auth_ratio ?? null;
  const effectivePolicy = drainPolicy ?? activeToken?.drain_policy ?? null;
  const baseDrainBps = resolveScopeDrainBps(effectivePolicy, transferScope);

  const drainPreview =
    activeToken && amountInput && baseDrainBps !== null
      ? (() => {
          try {
            const atomic = useAtomicUnits
              ? amountInput
              : parseDecimalToAtomic(amountInput, activeToken.decimals);
            return previewDrainClient(atomic, baseDrainBps, authRatio, 700);
          } catch {
            return null;
          }
        })()
      : null;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!activeSigner) {
      onNotify("error", "No active signer wallet unlocked. Unlock or create one in Wallets.");
      onOpenWallets();
      return;
    }

    setSubmitting(true);
    try {
      const requestId = `tok_${mode}_${Date.now()}`;
      const nonce = Date.now();
      const timestampMs = Date.now();

      if (mode === "create") {
        const drainBps = Number(newTokenDrainBps);
        const envelope = await signTransactionEnvelopeClient({
          privateKeyHex: activeSigner.private_key_hex,
          actorPubkey: activeSigner.public_key_hex,
          networkId,
          requestId,
          nonce,
          timestampMs,
          operation: {
            op: "CreateToken",
            payload: {
              wallet_id: ghostToken ? "" : newTokenWallet,
              name: newTokenName.trim(),
              symbol: newTokenSymbol.trim().toUpperCase(),
              initial_supply: Number(newTokenInitialSupply),
              max_supply: Number(newTokenMaxSupply),
              unlimited_supply: false,
              auth_ratio_au: 1000,
              energy: 0,
              drain_bps: Number.isFinite(drainBps) ? drainBps : 100,
              purpose: newTokenPolicy.trim() || "Bounded vector token",
              external_monetary_value: "0",
              ghost: ghostToken,
            },
          },
        });

        const res = await fetch("/api/tokens", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(envelope),
        });
        const data = (await res.json()) as { entity_id?: string; error?: string };
        if (!res.ok) {
          onNotify("error", data.error ?? "CreateToken rejected");
          return;
        }
        setNewTokenName("");
        setNewTokenSymbol("");
        await onRefresh();
        onNotify("success", `Issued token (${data.entity_id ?? "ok"})`);
        return;
      }

      if (!activeToken) {
        onNotify("error", "Select a token first");
        return;
      }

      const atomic = useAtomicUnits
        ? amountInput.trim()
        : parseDecimalToAtomic(amountInput, activeToken.decimals);
      const sourceWalletId = fromWallet || activeSigner.wallet_id;

      if (mode === "transfer") {
        const envelope = await signTransactionEnvelopeClient({
          privateKeyHex: activeSigner.private_key_hex,
          actorPubkey: activeSigner.public_key_hex,
          networkId,
          requestId,
          nonce,
          timestampMs,
          operation: {
            op: "TransferToken",
            payload: {
              token_id: activeToken.token_id,
              from_wallet_id: sourceWalletId,
              to_wallet_id: toWallet,
              amount: Number(atomic),
              cosignatures: [],
            },
          },
        });

        const res = await fetch("/api/tokens/transfer", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(envelope),
        });
        const data = (await res.json()) as { error?: string };
        if (!res.ok) {
          onNotify("error", data.error ?? "Transfer failed");
          return;
        }
        await onRefresh();
        onNotify("success", "Signed TransferToken committed");
      } else if (mode === "burn") {
        const envelope = await signTransactionEnvelopeClient({
          privateKeyHex: activeSigner.private_key_hex,
          actorPubkey: activeSigner.public_key_hex,
          networkId,
          requestId,
          nonce,
          timestampMs,
          operation: {
            op: "DrainToken",
            payload: {
              token_id: activeToken.token_id,
              wallet_id: sourceWalletId,
              amount: Number(atomic),
            },
          },
        });

        const res = await fetch("/api/tokens/burn", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(envelope),
        });
        const data = (await res.json()) as { error?: string };
        if (!res.ok) {
          onNotify("error", data.error ?? "DrainToken failed");
          return;
        }
        await onRefresh();
        onNotify("success", "Signed DrainToken committed");
      }
    } catch (err) {
      onNotify("error", err instanceof Error ? err.message : "Operation failed");
    } finally {
      setSubmitting(false);
    }
  }

  const walletMap = new Map(wallets.map((w) => [w.wallet_id, w]));

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
      <div className="space-y-6 xl:col-span-2">
        <section className="border border-slate-200 bg-white">
          <div className="border-b border-slate-200 px-5 py-3.5">
            <h2 className="text-sm font-semibold text-slate-900">Vector Token Definitions</h2>
            <p className="text-xs text-slate-500">
              Strict conservation accounting across wallet, escrow, loan collateral, and ghost custody accounts
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                  <th className="px-5 py-2.5">Token</th>
                  <th className="px-4 py-2.5">Token ID</th>
                  <th className="px-4 py-2.5 text-right">Circulating</th>
                  <th className="px-4 py-2.5 text-right">Ghost Custody / Burned</th>
                  <th className="px-5 py-2.5 text-right">Conservation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {tokens.map((tok) => {
                  const isSelected = activeToken?.token_id === tok.token_id;
                  return (
                    <tr
                      key={tok.token_id}
                      onClick={() => setSelectedTokenId(tok.token_id)}
                      className={`cursor-pointer transition-colors ${
                        isSelected ? "bg-blue-50/60" : "hover:bg-slate-50"
                      }`}
                    >
                      <td className="px-5 py-3">
                        <div className="font-semibold text-slate-900">
                          {tok.name} ({tok.symbol}) {tok.ghost ? "· GHOST" : ""}
                        </div>
                        <div className="font-mono text-[11px] text-slate-500">
                          {tok.decimals} decimals ·{" "}
                          {tok.drain_bps != null
                            ? `token policy=${tok.drain_bps} bps`
                            : "scope drain=UNCONFIGURED"}
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-700">{tok.token_id}</td>
                      <td className="px-4 py-3 text-right font-mono font-semibold tabular-nums text-slate-900">
                        {formatTokenUnitsClient(tok.total_supply, tok.decimals)}
                      </td>
                      <td className="px-4 py-3 text-right font-mono tabular-nums text-slate-600">
                        {formatTokenUnitsClient(tok.conservation.ghost_custody_balances_total ?? "0", tok.decimals)} /{" "}
                        {formatTokenUnitsClient(tok.burned_supply, tok.decimals)}
                      </td>
                      <td className="px-5 py-3 text-right font-mono font-medium">
                        <span
                          className={
                            tok.conservation.verification_status === "VERIFIED"
                              ? "text-emerald-700"
                              : tok.conservation.verification_status === "INVALID"
                                ? "text-red-700"
                                : tok.conservation.verification_status === "UNAVAILABLE"
                                  ? "text-slate-500"
                                  : "text-amber-700"
                          }
                        >
                          {tok.conservation.verification_status}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>

        {activeToken && (
          <section className="border border-slate-200 bg-white">
            <div className="border-b border-slate-200 px-5 py-3.5">
              <h3 className="text-sm font-semibold text-slate-900">
                Drain Fee Reward Ledger &amp; Split
              </h3>
              <p className="text-xs text-slate-500">
                Fees split across hierarchical creators and active validators
              </p>
            </div>
            {rewards.length === 0 ? (
              <div className="px-5 py-6 text-xs text-slate-500">
                No transfer drain reward records attached to current explorer snapshot.
              </div>
            ) : (
              <div className="max-h-56 overflow-auto">
                <table className="w-full border-collapse text-left text-xs">
                  <thead className="sticky top-0 bg-slate-50">
                    <tr className="border-b border-slate-200 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                      <th className="px-5 py-2">Role</th>
                      <th className="px-4 py-2">Beneficiary Wallet</th>
                      <th className="px-4 py-2 text-right">Reward Amount</th>
                      <th className="px-5 py-2 text-right">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {rewards.slice(0, 15).map((r) => {
                      const wlt = walletMap.get(r.wallet_id);
                      return (
                        <tr key={r.reward_id} className="hover:bg-slate-50">
                          <td className="px-5 py-2.5 font-mono font-medium text-emerald-800">
                            {r.beneficiary_role}
                          </td>
                          <td className="px-4 py-2.5 font-mono text-slate-700">
                            {wlt ? wlt.label : shortenHash(r.wallet_id, 10, 6)}
                          </td>
                          <td className="px-4 py-2.5 text-right font-mono font-semibold tabular-nums text-slate-900">
                            +{r.amount} units
                          </td>
                          <td className="px-5 py-2.5 text-right font-mono tabular-nums text-slate-500">
                            {formatTimestampMs(r.timestamp_ms)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}
      </div>

      <section className="h-fit border border-slate-200 bg-white">
        <div className="border-b border-slate-200 px-5 py-3.5">
          <h2 className="text-sm font-semibold text-slate-900">Signed Token Operations</h2>
          <p className="text-xs text-slate-500">Submitted via Rust SignedOperationHttpRequest</p>
        </div>

        <div className="grid grid-cols-3 border-b border-slate-200 bg-slate-50 text-[11px] font-medium">
          {(
            [
              { id: "transfer", label: "Transfer", icon: ArrowRightLeft },
              { id: "burn", label: "Drain", icon: Flame },
              { id: "create", label: "Issue", icon: Plus },
            ] as const
          ).map((tab) => {
            const Icon = tab.icon;
            const active = mode === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setMode(tab.id)}
                className={`flex items-center justify-center gap-1 border-r border-slate-200 py-2.5 last:border-r-0 ${
                  active ? "bg-white font-semibold text-blue-600" : "text-slate-600 hover:bg-slate-100"
                }`}
              >
                <Icon className="h-3 w-3" />
                {tab.label}
              </button>
            );
          })}
        </div>

        <form onSubmit={handleSubmit} className="space-y-3.5 p-5 text-xs">
          <div>
            <label className="mb-1 block font-medium text-slate-700">Active Signer</label>
            <div className="rounded border border-slate-200 bg-slate-50 p-2.5 font-mono text-xs">
              {activeSigner ? (
                <div className="flex items-center justify-between">
                  <div>
                    <div className="font-semibold text-slate-900">{activeSigner.label}</div>
                    <div className="text-[11px] text-slate-500">
                      auth_ratio = {authRatio !== null ? `${authRatio} / 1000` : "Unavailable"}
                    </div>
                  </div>
                  <span
                    className={
                      authRatio === null
                        ? "text-slate-500"
                        : authRatio >= 700
                          ? "font-bold text-emerald-700"
                          : "text-amber-700"
                    }
                  >
                    {authRatio === null
                      ? "Unavailable"
                      : authRatio >= 700
                        ? "50% Fee Discount"
                        : "Base Fee Rate"}
                  </span>
                </div>
              ) : (
                <div className="flex items-center justify-between text-amber-700">
                  <span>No signer unlocked</span>
                  <button type="button" onClick={onOpenWallets} className="underline">
                    Select in Wallets
                  </button>
                </div>
              )}
            </div>
          </div>

          {mode !== "create" && (
            <>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Token</label>
                <select
                  value={activeToken?.token_id ?? ""}
                  onChange={(e) => setSelectedTokenId(e.target.value)}
                  className="w-full border border-slate-300 bg-white px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                >
                  {tokens.map((t) => (
                    <option key={t.token_id} value={t.token_id}>
                      {t.symbol} — {t.name}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Source Wallet</label>
                <select
                  value={fromWallet}
                  onChange={(e) => setFromWallet(e.target.value)}
                  className="w-full border border-slate-300 bg-white px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                >
                  {wallets.map((w) => (
                    <option key={w.wallet_id} value={w.wallet_id}>
                      {w.label} ({shortenHash(w.wallet_id, 8, 6)})
                    </option>
                  ))}
                </select>
              </div>
            </>
          )}

          {mode === "transfer" && (
            <div>
              <label className="mb-1 block font-medium text-slate-700">Recipient Wallet</label>
              <select
                value={toWallet}
                onChange={(e) => setToWallet(e.target.value)}
                className="w-full border border-slate-300 bg-white px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
              >
                {wallets.map((w) => (
                  <option key={w.wallet_id} value={w.wallet_id}>
                    {w.label} ({shortenHash(w.wallet_id, 8, 6)})
                  </option>
                ))}
              </select>
            </div>
          )}

          {mode !== "create" && (
            <>
              <div>
                <div className="mb-1 flex items-center justify-between">
                  <label className="font-medium text-slate-700">
                    Amount ({useAtomicUnits ? "Atomic u128" : activeToken?.symbol ?? "Tokens"})
                  </label>
                  <label className="flex cursor-pointer items-center gap-1.5 text-[11px] text-slate-500">
                    <input
                      type="checkbox"
                      checked={useAtomicUnits}
                      onChange={(e) => setUseAtomicUnits(e.target.checked)}
                      className="h-3 w-3 accent-blue-600"
                    />
                    Atomic units
                  </label>
                </div>
                <input
                  type="text"
                  required
                  value={amountInput}
                  onChange={(e) => setAmountInput(e.target.value)}
                  placeholder={useAtomicUnits ? "10000" : "100"}
                  className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>

              {mode === "transfer" && drainPreview && (
                <div className="space-y-1 rounded border border-blue-200 bg-blue-50/60 p-3 font-mono text-[11px] text-blue-900">
                  <div className="font-semibold">
                    Scope-Derived Drain Preview ({transferScope ?? "UNKNOWN"}):
                  </div>
                  <div>Rate: {drainPreview.effectiveBps} bps ({drainPreview.discounted ? "50% discounted" : "base"})</div>
                  <div>Fee Collected: {drainPreview.totalFee.toString()} units</div>
                  <div>Net to Recipient: {drainPreview.netReceived.toString()} units</div>
                </div>
              )}
              {mode === "transfer" && !drainPreview && (
                <div className="space-y-1 rounded border border-amber-200 bg-amber-50/70 p-3 font-mono text-[11px] text-amber-900">
                  <div className="font-semibold">
                    {baseDrainBps !== null && authRatio === null
                      ? `Transfer Drain Policy: AUTH RATIO UNAVAILABLE (${transferScope ?? "UNAVAILABLE"})`
                      : `Transfer Drain Policy: UNCONFIGURED (${transferScope ?? "SELECT_WALLETS"})`}
                  </div>
                  <div>
                    {baseDrainBps !== null && authRatio === null
                      ? "Wallet auth_ratio unavailable — cannot preview fee discount tier."
                      : "Protocol fails closed for transfers whose scope drain rate is unconfigured."}
                  </div>
                </div>
              )}
            </>
          )}

          {mode === "create" && (
            <>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1 block font-medium text-slate-700">Name</label>
                  <input
                    type="text"
                    required
                    value={newTokenName}
                    onChange={(e) => setNewTokenName(e.target.value)}
                    placeholder="VECTOR FUEL"
                    className="w-full border border-slate-300 px-2.5 py-2 text-xs focus:border-blue-600 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="mb-1 block font-medium text-slate-700">Symbol</label>
                  <input
                    type="text"
                    required
                    value={newTokenSymbol}
                    onChange={(e) => setNewTokenSymbol(e.target.value)}
                    placeholder="VFL"
                    className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs uppercase focus:border-blue-600 focus:outline-none"
                  />
                </div>
              </div>
              {!ghostToken && (
                <div>
                  <label className="mb-1 block font-medium text-slate-700">Issuer Wallet</label>
                  <select
                    value={newTokenWallet}
                    onChange={(e) => setNewTokenWallet(e.target.value)}
                    required={!ghostToken}
                    className="w-full border border-slate-300 bg-white px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                  >
                    {wallets.map((w) => (
                      <option key={w.wallet_id} value={w.wallet_id}>
                        {w.label} ({w.wallet_id})
                      </option>
                    ))}
                  </select>
                </div>
              )}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1 block font-medium text-slate-700">Initial Supply</label>
                  <input
                    type="number"
                    min={1}
                    required
                    value={newTokenInitialSupply}
                    onChange={(e) => setNewTokenInitialSupply(e.target.value)}
                    className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="mb-1 block font-medium text-slate-700">Max Supply</label>
                  <input
                    type="number"
                    min={1}
                    required
                    value={newTokenMaxSupply}
                    onChange={(e) => setNewTokenMaxSupply(e.target.value)}
                    className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1 block font-medium text-slate-700">Drain Rate (bps)</label>
                  <input
                    type="number"
                    required
                    min={0}
                    max={10000}
                    value={newTokenDrainBps}
                    onChange={(e) => setNewTokenDrainBps(e.target.value)}
                    className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="mb-1 block font-medium text-slate-700">Purpose</label>
                  <input
                    type="text"
                    required
                    value={newTokenPolicy}
                    onChange={(e) => setNewTokenPolicy(e.target.value)}
                    className="w-full border border-slate-300 px-2.5 py-2 text-xs focus:border-blue-600 focus:outline-none"
                  />
                </div>
              </div>
              <label className="flex cursor-pointer items-center gap-2 text-xs text-slate-700">
                <input
                  type="checkbox"
                  checked={ghostToken}
                  onChange={(e) => setGhostToken(e.target.checked)}
                  className="h-3.5 w-3.5 accent-purple-600"
                />
                Ghost Token (escrowed under ghost_custody:: without wallet owner)
              </label>
            </>
          )}

          <button
            type="submit"
            disabled={submitting || !activeSigner}
            className="w-full bg-blue-600 px-4 py-2.5 text-xs font-medium text-white transition-colors hover:bg-blue-700 disabled:opacity-50"
          >
            {submitting
              ? "Submitting Signed Operation..."
              : mode === "transfer"
                ? "Sign & TransferToken"
                : mode === "burn"
                  ? "Sign & DrainToken"
                  : "Sign & CreateToken"}
          </button>
        </form>
      </section>
    </div>
  );
}
