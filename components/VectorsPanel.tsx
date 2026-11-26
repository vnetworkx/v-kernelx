"use client";

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { FileCode2, Landmark, Layers, Play } from "lucide-react";
import { formatTimestampMs, shortenHash } from "@/lib/format";
import { signTransactionEnvelopeClient } from "@/lib/client-crypto";
import type {
  BrowserSignerKey,
  ContractDto,
  LoanDto,
  RegionDto,
  TokenDto,
  VectorStateDto,
  WalletDto,
} from "@/lib/types";

interface VectorsPanelProps {
  networkId: string;
  regions: RegionDto[];
  wallets: WalletDto[];
  tokens: TokenDto[];
  contracts: ContractDto[];
  loans: LoanDto[];
  initialVectors?: VectorStateDto[];
  signerKeys: Record<string, BrowserSignerKey>;
  activeSignerId: string | null;
  onOpenWallets: () => void;
  onRefresh: () => Promise<void>;
  onNotify: (kind: "success" | "error", msg: string) => void;
}

type OpMode = "create_contract" | "execute_contract" | "create_loan" | "execute_loan";

export function VectorsPanel({
  networkId,
  regions,
  wallets,
  tokens,
  contracts,
  loans,
  initialVectors = [],
  signerKeys,
  activeSignerId,
  onOpenWallets,
  onRefresh,
  onNotify,
}: VectorsPanelProps) {
  const [vectors, setVectors] = useState<VectorStateDto[]>(initialVectors);
  const [loading, setLoading] = useState(true);
  const [mode, setMode] = useState<OpMode>("create_contract");
  const [submitting, setSubmitting] = useState(false);

  // CreateContract fields
  const [contractName, setContractName] = useState("");
  const [contractRegionId, setContractRegionId] = useState(regions[0]?.region_id ?? "");
  const [contractRulesJson, setContractRulesJson] = useState('{"escrow_mode":"deterministic"}');
  const [contractActionName, setContractActionName] = useState("settle");

  // ExecuteContract fields
  const [selectedContractId, setSelectedContractId] = useState(contracts[0]?.contract_id ?? "");
  const [execActionName, setExecActionName] = useState("settle");
  const [execArgsJson, setExecArgsJson] = useState(
    wallets[0] ? `{"recipient_wallet_id":"${wallets[0].wallet_id}","amount":10}` : '{"amount":10}',
  );

  // CreateLoan fields
  const [loanName, setLoanName] = useState("");
  const [loanTokenId, setLoanTokenId] = useState(tokens[0]?.token_id ?? "");
  const [lenderWalletId, setLenderWalletId] = useState(wallets[0]?.wallet_id ?? "");
  const [borrowerWalletId, setBorrowerWalletId] = useState(
    wallets[1]?.wallet_id ?? wallets[0]?.wallet_id ?? "",
  );
  const [loanPrincipal, setLoanPrincipal] = useState("500");
  const [loanCollateral, setLoanCollateral] = useState("100");
  const [loanInterestBps, setLoanInterestBps] = useState("250");

  // ExecuteLoan fields
  const [selectedLoanId, setSelectedLoanId] = useState(loans[0]?.loan_id ?? "");
  const [loanAction, setLoanAction] = useState<"DISBURSE" | "REPAY" | "LIQUIDATE">("REPAY");
  const [loanExecAmount, setLoanExecAmount] = useState("100");

  const activeSigner = activeSignerId ? signerKeys[activeSignerId] : null;

  const loadVectors = useCallback(async () => {
    try {
      const res = await fetch("/api/vectors");
      if (res.ok) {
        const data = (await res.json()) as { vectors?: VectorStateDto[] };
        setVectors(data.vectors ?? []);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadVectors();
  }, [loadVectors]);

  useEffect(() => {
    if (contracts.length > 0 && !selectedContractId) {
      setSelectedContractId(contracts[0].contract_id);
    }
  }, [contracts, selectedContractId]);

  useEffect(() => {
    if (loans.length > 0 && !selectedLoanId) {
      setSelectedLoanId(loans[0].loan_id);
    }
  }, [loans, selectedLoanId]);

  async function handleSignedSubmit(e: FormEvent) {
    e.preventDefault();
    if (!activeSigner) {
      onNotify("error", "No active signer wallet unlocked. Unlock or create one in Wallets.");
      onOpenWallets();
      return;
    }

    setSubmitting(true);
    try {
      const requestId = `vec_${mode}_${Date.now()}`;
      const nonce = Date.now();
      const timestampMs = Date.now();
      let operation: { op: string; payload: Record<string, unknown> };

      if (mode === "create_contract") {
        let parsedRules: Record<string, unknown> = {};
        if (contractRulesJson.trim()) {
          const parsed = JSON.parse(contractRulesJson) as unknown;
          if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
            throw new Error("Contract rules must be a JSON object");
          }
          parsedRules = parsed as Record<string, unknown>;
        }
        operation = {
          op: "CreateContract",
          payload: {
            name: contractName.trim(),
            region_id: contractRegionId.trim() || null,
            rules: parsedRules,
            actions: [{ action: contractActionName.trim() || "settle" }],
          },
        };
      } else if (mode === "execute_contract") {
        if (!selectedContractId) {
          throw new Error("Select a contract to execute");
        }
        let parsedArgs: Record<string, unknown> = {};
        if (execArgsJson.trim()) {
          const parsed = JSON.parse(execArgsJson) as unknown;
          if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
            throw new Error("Execution args must be a JSON object");
          }
          parsedArgs = parsed as Record<string, unknown>;
        }
        operation = {
          op: "ExecuteContract",
          payload: {
            contract_id: selectedContractId,
            action: execActionName.trim(),
            args: parsedArgs,
          },
        };
      } else if (mode === "create_loan") {
        if (!loanTokenId || !lenderWalletId || !borrowerWalletId) {
          throw new Error("Select token, lender wallet, and borrower wallet");
        }
        operation = {
          op: "CreateLoan",
          payload: {
            name: loanName.trim(),
            token_id: loanTokenId,
            lender_wallet_id: lenderWalletId,
            borrower_wallet_id: borrowerWalletId,
            principal: Number(loanPrincipal),
            collateral: Number(loanCollateral),
            interest_bps: Number(loanInterestBps),
            maturity_at_ms: null,
          },
        };
      } else {
        if (!selectedLoanId) {
          throw new Error("Select a loan");
        }
        operation = {
          op: "ExecuteLoan",
          payload: {
            loan_id: selectedLoanId,
            action: loanAction,
            amount: Number(loanExecAmount) || 0,
          },
        };
      }

      const envelope = await signTransactionEnvelopeClient({
        privateKeyHex: activeSigner.private_key_hex,
        actorPubkey: activeSigner.public_key_hex,
        networkId,
        requestId,
        nonce,
        timestampMs,
        operation,
      });

      const res = await fetch("/api/vectors/action", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(envelope),
      });
      const data = (await res.json()) as { entity_id?: string; event_id?: string; error?: string };
      if (!res.ok) {
        onNotify("error", data.error ?? `${operation.op} transaction rejected`);
        return;
      }

      if (mode === "create_contract") setContractName("");
      if (mode === "create_loan") setLoanName("");
      await loadVectors();
      await onRefresh();
      onNotify("success", `Committed ${operation.op} (${data.entity_id ?? data.event_id ?? "ok"})`);
    } catch (err) {
      onNotify("error", err instanceof Error ? err.message : "Operation failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
      <div className="space-y-6 xl:col-span-2">
        {/* 3D Balance Vectors */}
        <section className="border border-slate-200 bg-white">
          <div className="flex items-center gap-2 border-b border-slate-200 px-5 py-3.5">
            <Layers className="h-4 w-4 text-blue-600" />
            <div>
              <h2 className="text-sm font-semibold text-slate-900">
                3D Balance Vectors ({vectors.length})
              </h2>
              <p className="text-xs text-slate-500">
                Live kernel vector coordinates [token, auth_ratio_au, energy] derived from /v1/explorer/network
              </p>
            </div>
          </div>

          {loading ? (
            <div className="px-5 py-8 text-xs text-slate-500">Loading balance vectors...</div>
          ) : vectors.length === 0 ? (
            <div className="px-5 py-8 text-center text-xs text-slate-500">
              No active balance vectors found on node.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                    <th className="px-5 py-2.5">Vector Account</th>
                    <th className="px-4 py-2.5">Scope</th>
                    <th className="px-4 py-2.5">Auth Ratio</th>
                    <th className="px-5 py-2.5 text-right">[Token, AuthAU, Energy]</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {vectors.map((vec) => (
                    <tr key={vec.vectorId} className="hover:bg-slate-50">
                      <td className="px-5 py-2.5">
                        <div className="font-mono font-semibold text-slate-900">{vec.vectorId}</div>
                        <div className="font-mono text-[11px] text-slate-400">
                          v{vec.version} · {vec.status}
                        </div>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-slate-600">
                        {shortenHash(vec.spaceId, 12, 8)}
                      </td>
                      <td className="px-4 py-2.5 font-mono tabular-nums">
                        <span className={vec.certification.certified ? "font-semibold text-emerald-700" : "text-amber-700"}>
                          {vec.certification.authRatio} au
                        </span>
                      </td>
                      <td className="px-5 py-2.5 text-right font-mono font-semibold tabular-nums text-slate-900">
                        [{vec.components.join(", ")}]
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* Smart Contracts (vContracts) */}
        <section className="border border-slate-200 bg-white">
          <div className="flex items-center gap-2 border-b border-slate-200 px-5 py-3.5">
            <FileCode2 className="h-4 w-4 text-blue-600" />
            <div>
              <h2 className="text-sm font-semibold text-slate-900">
                vContracts Registry ({contracts.length})
              </h2>
              <p className="text-xs text-slate-500">
                Deterministic multi-party state machines with escrow balance custody
              </p>
            </div>
          </div>

          {contracts.length === 0 ? (
            <div className="px-5 py-6 text-xs text-slate-500">No vContracts deployed yet.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                    <th className="px-5 py-2.5">Contract</th>
                    <th className="px-4 py-2.5">Scope</th>
                    <th className="px-4 py-2.5">Executions</th>
                    <th className="px-5 py-2.5 text-right">Escrow / State</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {contracts.map((c) => (
                    <tr key={c.contract_id} className="hover:bg-slate-50">
                      <td className="px-5 py-2.5">
                        <div className="font-semibold text-slate-900">{c.name}</div>
                        <div className="font-mono text-[11px] text-slate-400">{c.contract_id}</div>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-slate-600">
                        {c.region_id ? shortenHash(c.region_id, 10, 6) : "NETWORK"}
                      </td>
                      <td className="px-4 py-2.5 font-mono tabular-nums text-slate-700">
                        {c.execution_count} · {c.active ? "ACTIVE" : "CLOSED"}
                      </td>
                      <td className="px-5 py-2.5 text-right font-mono text-[11px] text-slate-600">
                        {Object.keys(c.escrow_balances ?? {}).length > 0
                          ? Object.entries(c.escrow_balances ?? {})
                              .map(([k, v]) => `${shortenHash(k, 8, 4)}:${v}`)
                              .join(", ")
                          : `v${c.version} · ${formatTimestampMs(c.created_at_ms)}`}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* Collateralized Loans (vLoans) */}
        <section className="border border-slate-200 bg-white">
          <div className="flex items-center gap-2 border-b border-slate-200 px-5 py-3.5">
            <Landmark className="h-4 w-4 text-emerald-700" />
            <div>
              <h2 className="text-sm font-semibold text-slate-900">
                vLoans Registry ({loans.length})
              </h2>
              <p className="text-xs text-slate-500">
                Escrowed principal, locked collateral, deterministic repayment &amp; liquidation
              </p>
            </div>
          </div>

          {loans.length === 0 ? (
            <div className="px-5 py-6 text-xs text-slate-500">No vLoans active on node.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                    <th className="px-5 py-2.5">Loan</th>
                    <th className="px-4 py-2.5">Parties</th>
                    <th className="px-4 py-2.5">Principal / Repaid</th>
                    <th className="px-5 py-2.5 text-right">Collateral / Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {loans.map((l) => (
                    <tr key={l.loan_id} className="hover:bg-slate-50">
                      <td className="px-5 py-2.5">
                        <div className="font-semibold text-slate-900">{l.name}</div>
                        <div className="font-mono text-[11px] text-slate-400">
                          {l.loan_id} · {l.interest_bps} bps
                        </div>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[11px] text-slate-600">
                        {shortenHash(l.lender_wallet_id, 8, 4)} -&gt; {shortenHash(l.borrower_wallet_id, 8, 4)}
                      </td>
                      <td className="px-4 py-2.5 font-mono tabular-nums text-slate-800">
                        {l.principal} / {l.repaid_amount}
                      </td>
                      <td className="px-5 py-2.5 text-right font-mono tabular-nums">
                        <span className="font-semibold text-slate-900">{l.collateral_locked}</span>{" "}
                        <span className="text-slate-500">· {l.status}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      {/* Signed Contract / Loan Console */}
      <section className="h-fit border border-slate-200 bg-white">
        <div className="border-b border-slate-200 px-5 py-3.5">
          <h2 className="text-sm font-semibold text-slate-900">Contracts &amp; Loans Console</h2>
          <p className="text-xs text-slate-500">
            Submitted via Rust SignedOperationHttpRequest (/v1/transactions)
          </p>
        </div>

        <div className="grid grid-cols-2 border-b border-slate-200 bg-slate-50 text-[11px] font-medium">
          {(
            [
              { id: "create_contract", label: "New vContract" },
              { id: "execute_contract", label: "Exec Contract" },
              { id: "create_loan", label: "New vLoan" },
              { id: "execute_loan", label: "Exec Loan" },
            ] as const
          ).map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setMode(tab.id)}
              className={`border-b border-r border-slate-200 py-2 text-center ${
                mode === tab.id
                  ? "bg-white font-semibold text-blue-600"
                  : "text-slate-600 hover:bg-slate-100"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <form onSubmit={handleSignedSubmit} className="space-y-3.5 p-5 text-xs">
          <div>
            <label className="mb-1 block font-medium text-slate-700">Active Signer</label>
            <div className="rounded border border-slate-200 bg-slate-50 p-2 font-mono text-xs">
              {activeSigner ? activeSigner.label : "No signer selected"}
            </div>
          </div>

          {mode === "create_contract" && (
            <>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Contract Name</label>
                <input
                  type="text"
                  required
                  value={contractName}
                  onChange={(e) => setContractName(e.target.value)}
                  placeholder="settlement-escrow"
                  className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Region Scope (optional)</label>
                <select
                  value={contractRegionId}
                  onChange={(e) => setContractRegionId(e.target.value)}
                  className="w-full border border-slate-300 bg-white px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                >
                  <option value="">Network Scope (optional)</option>
                  {regions.map((r) => (
                    <option key={r.region_id} value={r.region_id}>
                      {r.region_name} ({r.region_id})
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Primary Action Name</label>
                <input
                  type="text"
                  required
                  value={contractActionName}
                  onChange={(e) => setContractActionName(e.target.value)}
                  className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Rules JSON</label>
                <textarea
                  rows={3}
                  value={contractRulesJson}
                  onChange={(e) => setContractRulesJson(e.target.value)}
                  className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>
            </>
          )}

          {mode === "execute_contract" && (
            <>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Target Contract</label>
                <select
                  value={selectedContractId}
                  onChange={(e) => setSelectedContractId(e.target.value)}
                  required
                  className="w-full border border-slate-300 bg-white px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                >
                  <option value="">Select vContract...</option>
                  {contracts.map((c) => (
                    <option key={c.contract_id} value={c.contract_id}>
                      {c.name} ({c.contract_id})
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Action</label>
                <input
                  type="text"
                  required
                  value={execActionName}
                  onChange={(e) => setExecActionName(e.target.value)}
                  placeholder="settle"
                  className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Args JSON</label>
                <textarea
                  rows={3}
                  value={execArgsJson}
                  onChange={(e) => setExecArgsJson(e.target.value)}
                  className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>
            </>
          )}

          {mode === "create_loan" && (
            <>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Loan Name</label>
                <input
                  type="text"
                  required
                  value={loanName}
                  onChange={(e) => setLoanName(e.target.value)}
                  placeholder="working-capital-loan"
                  className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Token</label>
                <select
                  value={loanTokenId}
                  onChange={(e) => setLoanTokenId(e.target.value)}
                  required
                  className="w-full border border-slate-300 bg-white px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                >
                  <option value="">Select Token...</option>
                  {tokens.map((t) => (
                    <option key={t.token_id} value={t.token_id}>
                      {t.symbol} ({t.token_id})
                    </option>
                  ))}
                </select>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="mb-1 block font-medium text-slate-700">Lender</label>
                  <select
                    value={lenderWalletId}
                    onChange={(e) => setLenderWalletId(e.target.value)}
                    required
                    className="w-full border border-slate-300 bg-white px-2 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                  >
                    {wallets.map((w) => (
                      <option key={w.wallet_id} value={w.wallet_id}>
                        {w.label}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="mb-1 block font-medium text-slate-700">Borrower</label>
                  <select
                    value={borrowerWalletId}
                    onChange={(e) => setBorrowerWalletId(e.target.value)}
                    required
                    className="w-full border border-slate-300 bg-white px-2 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                  >
                    {wallets.map((w) => (
                      <option key={w.wallet_id} value={w.wallet_id}>
                        {w.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-2">
                <div>
                  <label className="mb-1 block font-medium text-slate-700">Principal</label>
                  <input
                    type="number"
                    min={1}
                    required
                    value={loanPrincipal}
                    onChange={(e) => setLoanPrincipal(e.target.value)}
                    className="w-full border border-slate-300 px-2 py-2 font-mono text-xs"
                  />
                </div>
                <div>
                  <label className="mb-1 block font-medium text-slate-700">Collateral</label>
                  <input
                    type="number"
                    min={0}
                    required
                    value={loanCollateral}
                    onChange={(e) => setLoanCollateral(e.target.value)}
                    className="w-full border border-slate-300 px-2 py-2 font-mono text-xs"
                  />
                </div>
                <div>
                  <label className="mb-1 block font-medium text-slate-700">Rate bps</label>
                  <input
                    type="number"
                    min={0}
                    max={10000}
                    required
                    value={loanInterestBps}
                    onChange={(e) => setLoanInterestBps(e.target.value)}
                    className="w-full border border-slate-300 px-2 py-2 font-mono text-xs"
                  />
                </div>
              </div>
            </>
          )}

          {mode === "execute_loan" && (
            <>
              <div>
                <label className="mb-1 block font-medium text-slate-700">Target Loan</label>
                <select
                  value={selectedLoanId}
                  onChange={(e) => setSelectedLoanId(e.target.value)}
                  required
                  className="w-full border border-slate-300 bg-white px-2.5 py-2 font-mono text-xs focus:border-blue-600 focus:outline-none"
                >
                  <option value="">Select vLoan...</option>
                  {loans.map((l) => (
                    <option key={l.loan_id} value={l.loan_id}>
                      {l.name} ({l.status})
                    </option>
                  ))}
                </select>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="mb-1 block font-medium text-slate-700">Loan Action</label>
                  <select
                    value={loanAction}
                    onChange={(e) =>
                      setLoanAction(e.target.value as "DISBURSE" | "REPAY" | "LIQUIDATE")
                    }
                    className="w-full border border-slate-300 bg-white px-2.5 py-2 font-mono text-xs"
                  >
                    <option value="DISBURSE">DISBURSE</option>
                    <option value="REPAY">REPAY</option>
                    <option value="LIQUIDATE">LIQUIDATE</option>
                  </select>
                </div>
                <div>
                  <label className="mb-1 block font-medium text-slate-700">Amount</label>
                  <input
                    type="number"
                    min={0}
                    required
                    value={loanExecAmount}
                    onChange={(e) => setLoanExecAmount(e.target.value)}
                    className="w-full border border-slate-300 px-2.5 py-2 font-mono text-xs"
                  />
                </div>
              </div>
            </>
          )}

          <button
            type="submit"
            disabled={submitting || !activeSigner}
            className="inline-flex w-full items-center justify-center gap-1.5 bg-blue-600 px-4 py-2.5 text-xs font-medium text-white transition-colors hover:bg-blue-700 disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5" />
            {submitting ? "Submitting Signed Tx..." : `Sign & Submit ${mode.replace("_", " ").toUpperCase()}`}
          </button>
        </form>
      </section>
    </div>
  );
}
