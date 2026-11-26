"use client";

import { useState, type FormEvent } from "react";
import { ArrowRightLeft, Coins, Flame, Plus, ShieldCheck } from "lucide-react";
import {
  formatTokenUnitsClient,
  parseDecimalToAtomic,
  previewDrainClient,
  shortenHash,
} from "@/lib/format";
import {
  canonicalTokenRequestSigningBytes,
  signBytesWithPrivateKey,
} from "@/lib/client-crypto";
import type { BrowserSignerKey, DrainRewardDto, RegionDto, TokenDto, WalletDto } from "@/lib/types";

interface TokensPanelProps {
  tokens: TokenDto[];
  wallets: WalletDto[];
  regions: RegionDto[];
  rewards: DrainRewardDto[];
  signerKeys: Record<string, BrowserSignerKey>;
  activeSignerId: string | null;
  onOpenWallets: () => void;
  onRefresh: () => Promise<void>;
  onNotify: (kind: "success" | "error", msg: string) => void;
}

type OpMode = "transfer" | "transport" | "burn" | "create";

export function TokensPanel({
  tokens,
  wallets,
  regions,
  rewards,
  signerKeys,
  activeSignerId,
  onOpenWallets,
  onRefresh,
  onNotify,
}: TokensPanelProps) {
  const [mode, setMode] = useState<OpMode>("transfer");
  const [selectedTokenId, setSelectedTokenId] = useState(tokens[0]?.token_id ?? "");
  const [submitting, setSubmitting] = useState(false);

  // Transfer & Transport fields
  const [toWallet, setToWallet] = useState(wallets[1]?.wallet_id ?? wallets[0]?.wallet_id ?? "");
  const [amountInput, setAmountInput] = useState("100");
  const [useAtomicUnits, setUseAtomicUnits] = useState(false);

  // Create Token fields
  const [newTokenName, setNewTokenName] = useState("");
  const [newTokenSymbol, setNewTokenSymbol] = useState("");
  const [newTokenRegion, setNewTokenRegion] = useState(regions[0]?.region_id ?? "");
  const [newTokenDecimals, setNewTokenDecimals] = useState("8");
  const [newTokenMaxSupply, setNewTokenMaxSupply] = useState("100000000000000000");
  const [newTokenPolicy, setNewTokenPolicy] = useState("bounded-reserve-transport-supply");
  const [newTokenDrainBps, setNewTokenDrainBps] = useState("200");

  const activeToken =
    tokens.find((t) => t.token_id === selectedTokenId) ?? tokens[0] ?? null;

  const activeSigner = activeSignerId ? signerKeys[activeSignerId] : null;
  const activeSignerWallet = activeSigner ? wallets.find((w) => w.wallet_id === activeSigner.wallet_id) : null;
  const authRatio = activeSignerWallet?.auth_ratio ?? 1000;
  const baseDrainBps = activeToken?.drain_bps ?? 200;

  const drainPreview = activeToken && amountInput ? (() => {
    try {
      const atomic = useAtomicUnits ? amountInput : parseDecimalToAtomic(amountInput, activeToken.decimals);
      return previewDrainClient(atomic, baseDrainBps, authRatio, 700);
    } catch {
      return null;
    }
  })() : null;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!activeSigner) {
      onNotify("error", "No active signer wallet unlocked. Unlock or create one in Wallets.");
      onOpenWallets();
      return;
    }

    setSubmitting(true);
    try {
      if (mode === "create") {
        const requestId = `tkn_create_${Date.now()}`;
        const decimals = Number(newTokenDecimals);
        const symbol = newTokenSymbol.trim().toUpperCase();
        const maxSupply = newTokenMaxSupply.trim();
        const drainBps = Number(newTokenDrainBps);

        const reqParams = {
          decimals,
          drain_bps: drainBps,
          max_supply: maxSupply,
          name: newTokenName.trim(),
          region_id: newTokenRegion,
          supply_policy: newTokenPolicy.trim(),
          symbol,
          token_type: "Native Vector Network asset",
        };
        const signingBytes = canonicalTokenRequestSigningBytes(
          "TOKEN_CREATE",
          requestId,
          activeSigner.public_key_hex,
          reqParams,
        );
        const signature = await signBytesWithPrivateKey(activeSigner.private_key_hex, signingBytes);

        const res = await fetch("/api/tokens", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            request_id: requestId,
            name: newTokenName.trim(),
            symbol,
            region_id: newTokenRegion,
            decimals,
            max_supply: maxSupply,
            supply_policy: newTokenPolicy.trim(),
            drain_bps: drainBps,
            authority_pubkey: activeSigner.public_key_hex,
            signature,
          }),
        });
        const data = (await res.json()) as { token?: TokenDto; error?: string };
        if (!res.ok || !data.token) {
          onNotify("error", data.error ?? "Token creation failed");
          return;
        }
        setSelectedTokenId(data.token.token_id);
        setNewTokenName("");
        setNewTokenSymbol("");
        await onRefresh();
        onNotify("success", `Issued ${data.token.name} (${data.token.symbol})`);
        return;
      }

      if (!activeToken) {
        onNotify("error", "Select a token first");
        return;
      }

      const atomic = useAtomicUnits ? amountInput.trim() : parseDecimalToAtomic(amountInput, activeToken.decimals);
      const requestId = `op_${Date.now()}`;

      if (mode === "transfer") {
        const reqParams = {
          amount: atomic,
          from_wallet_id: activeSigner.wallet_id,
          to_wallet_id: toWallet,
          token_id: activeToken.token_id,
        };
        const signingBytes = canonicalTokenRequestSigningBytes(
          "TOKEN_TRANSFER",
          requestId,
          activeSigner.public_key_hex,
          reqParams,
        );
        const signature = await signBytesWithPrivateKey(activeSigner.private_key_hex, signingBytes);

        const res = await fetch("/api/tokens/transfer", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            request_id: requestId,
            token_id: activeToken.token_id,
            from_wallet_id: activeSigner.wallet_id,
            to_wallet_id: toWallet,
            amount: atomic,
            actor_public_key: activeSigner.public_key_hex,
            signature,
          }),
        });
        const data = (await res.json()) as { error?: string };
        if (!res.ok) {
          onNotify("error", data.error ?? "Transfer failed");
          return;
        }
        await onRefresh();
        onNotify("success", `Transferred with drain fee rewards`);
      } else if (mode === "transport") {
        const reqParams = {
          amount: atomic,
          to_wallet_id: toWallet,
          token_id: activeToken.token_id,
        };
        const signingBytes = canonicalTokenRequestSigningBytes(
          "TOKEN_TRANSPORT",
          requestId,
          activeSigner.public_key_hex,
          reqParams,
        );
        const signature = await signBytesWithPrivateKey(activeSigner.private_key_hex, signingBytes);

        const res = await fetch("/api/tokens/transport", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            request_id: requestId,
            token_id: activeToken.token_id,
            to_wallet_id: toWallet,
            amount: atomic,
            actor_public_key: activeSigner.public_key_hex,
            signature,
          }),
        });
        const data = (await res.json()) as { error?: string };
        if (!res.ok) {
          onNotify("error", data.error ?? "Transport failed");
          return;
        }
        await onRefresh();
        onNotify("success", `Transported reserve supply from bound capacity`);
      } else if (mode === "burn") {
        const reqParams = {
          amount: atomic,
          from_wallet_id: activeSigner.wallet_id,
          token_id: activeToken.token_id,
        };
        const signingBytes = canonicalTokenRequestSigningBytes(
          "TOKEN_BURN",
          requestId,
          activeSigner.public_key_hex,
          reqParams,
        );
        const signature = await signBytesWithPrivateKey(activeSigner.private_key_hex, signingBytes);

        const res = await fetch("/api/tokens/burn", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            request_id: requestId,
            token_id: activeToken.token_id,
            from_wallet_id: activeSigner.wallet_id,
            amount: atomic,
            actor_public_key: activeSigner.public_key_hex,
            signature,
          }),
        });
        const data = (await res.json()) as { error?: string };
        if (!res.ok) {
          onNotify("error", data.error ?? "Burn failed");
          return;
        }
        await onRefresh();
        onNotify("success", `Burned tokens`);
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
              Bounded reserve transport & auth-discounted drain fees
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                  <th className="px-5 py-2.5">Token</th>
                  <th className="px-4 py-2.5">Token ID</th>
                  <th className="px-4 py-2.5 text-right">Circulating</th>
                  <th className="px-4 py-2.5 text-right">Transported / Burned</th>
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
                          {tok.name} ({tok.symbol})
                        </div>
                        <div className="font-mono text-[11px] text-slate-500">
                          {tok.decimals} decimals · drain={tok.drain_bps ?? 200} bps
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-700">{tok.token_id}</td>
                      <td className="px-4 py-3 text-right font-mono font-semibold tabular-nums text-slate-900">
                        {formatTokenUnitsClient(tok.total_supply, tok.decimals)}
                      </td>
                      <td className="px-4 py-3 text-right font-mono tabular-nums text-slate-600">
                        {formatTokenUnitsClient(tok.transported_supply ?? tok.minted_supply, tok.decimals)} /{" "}
                        {formatTokenUnitsClient(tok.burned_supply, tok.decimals)}
                      </td>
                      <td className="px-5 py-3 text-right font-mono font-medium">
                        <span className={tok.conservation.conserved ? "text-emerald-700" : "text-red-700"}>
                          {tok.conservation.conserved ? "VERIFIED" : "MISMATCH"}
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
                Drain Fee Reward Ledger & 4-Way Split
              </h3>
              <p className="text-xs text-slate-500">
                Fees split equally 4 ways: Region Creator, Wallet Creator, Token Creator, Network Node Pool
              </p>
            </div>
            {rewards.length === 0 ? (
              <div className="px-5 py-6 text-xs text-slate-500">
                No transfer drain rewards recorded yet. Execute a transfer to trigger fee distribution.
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
          <p className="text-xs text-slate-500">Executed via active client Ed25519 signer</p>
        </div>

        <div className="grid grid-cols-4 border-b border-slate-200 bg-slate-50 text-[11px] font-medium">
          {(
            [
              { id: "transfer", label: "Transfer", icon: ArrowRightLeft },
              { id: "transport", label: "Transport", icon: Coins },
              { id: "burn", label: "Burn", icon: Flame },
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
                    <div className="text-[11px] text-slate-500">auth_ratio = {authRatio} / 1000</div>
                  </div>
                  <span className={authRatio >= 700 ? "text-emerald-700 font-bold" : "text-amber-700"}>
                    {authRatio >= 700 ? "50% Fee Discount" : "Base Fee Rate"}
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
          )}

          {(mode === "transfer" || mode === "transport") && (
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
                  placeholder={useAtomicUnits ? "10000000000" : "100"}
                  className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>

              {mode === "transfer" && drainPreview && (
                <div className="rounded border border-blue-200 bg-blue-50/60 p-3 text-[11px] font-mono text-blue-900 space-y-1">
                  <div className="font-semibold">Transfer Drain Fee Breakdown:</div>
                  <div>Rate: {drainPreview.effectiveBps} bps ({drainPreview.discounted ? "50% discounted" : "base"})</div>
                  <div>Fee Collected: {drainPreview.totalFee.toString()} units</div>
                  <div>Net to Recipient: {drainPreview.netReceived.toString()} units</div>
                  <div className="text-[10px] text-blue-700 mt-1">
                    Split equally 4 ways: Region, Wallet, Token creators & Network Pool.
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
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1 block font-medium text-slate-700">Region</label>
                  <select
                    value={newTokenRegion}
                    onChange={(e) => setNewTokenRegion(e.target.value)}
                    className="w-full border border-slate-300 bg-white px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                  >
                    {regions.map((r) => (
                      <option key={r.region_id} value={r.region_id}>
                        {r.region_name}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="mb-1 block font-medium text-slate-700">Decimals</label>
                  <input
                    type="number"
                    min={0}
                    max={18}
                    value={newTokenDecimals}
                    onChange={(e) => setNewTokenDecimals(e.target.value)}
                    className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1 block font-medium text-slate-700">Max Supply (Atomic)</label>
                  <input
                    type="text"
                    required
                    value={newTokenMaxSupply}
                    onChange={(e) => setNewTokenMaxSupply(e.target.value)}
                    className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="mb-1 block font-medium text-slate-700">Drain Bps (e.g. 200)</label>
                  <input
                    type="number"
                    min={0}
                    max={10000}
                    value={newTokenDrainBps}
                    onChange={(e) => setNewTokenDrainBps(e.target.value)}
                    className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                  />
                </div>
              </div>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Supply Policy</label>
                <input
                  type="text"
                  required
                  value={newTokenPolicy}
                  onChange={(e) => setNewTokenPolicy(e.target.value)}
                  className="w-full border border-slate-300 px-2.5 py-2 text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>
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
                ? "Sign & Transfer (with Drain Rewards)"
                : mode === "transport"
                  ? "Sign & Transport (Bounded Reserve)"
                  : mode === "burn"
                    ? "Sign & Burn"
                    : "Issue New Token"}
          </button>
        </form>
      </section>
    </div>
  );
}
