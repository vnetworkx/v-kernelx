"use client";

import { useEffect, useState } from "react";
import { Play, RotateCcw, Sparkles } from "lucide-react";
import type { VectorRecordDto, VectorStateDto } from "@/lib/types";

const DEFAULT_SCRIPT = `ORIGIN_CREATE {"vectorId":"v-alpha","ownerPubkey":"pk-alpha","spaceId":"space-1","components":[1000,2000],"seed":"seed-a","nonce":29,"difficulty":1}
ORIGIN_CREATE {"vectorId":"v-beta","ownerPubkey":"pk-beta","spaceId":"space-1","components":[50,75],"seed":"seed-b","nonce":6,"difficulty":1}
TRANSFER {"from":"v-alpha","to":"v-beta","amount":[250,250]}
DRAIN {"vectorId":"v-alpha","basisPoints":100}
PROJECT {"vectorId":"v-beta","projectedComponents":[10,10],"escrowId":"escrow-1"}
RECONSTRUCT {"vectorId":"v-beta","gains":[2,1],"losses":[0,0],"outcomeTag":"settled"}`;

export function SandboxPanel() {
  const [script, setScript] = useState(DEFAULT_SCRIPT);
  const [output, setOutput] = useState<string>("");
  const [vectors, setVectors] = useState<VectorStateDto[]>([]);
  const [records, setRecords] = useState<VectorRecordDto[]>([]);
  const [busy, setBusy] = useState(false);

  async function refreshSandbox() {
    const res = await fetch("/api/sandbox");
    if (!res.ok) return;
    const data = (await res.json()) as {
      vectors?: VectorStateDto[];
      records?: VectorRecordDto[];
    };
    setVectors(data.vectors ?? []);
    setRecords(data.records ?? []);
  }

  useEffect(() => {
    void refreshSandbox();
  }, []);

  async function runAction(action: "execute" | "demo" | "reset") {
    setBusy(true);
    try {
      const res = await fetch("/api/sandbox", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(action === "execute" ? { action, script } : { action }),
      });
      const data = (await res.json()) as {
        output?: string | string[];
        vectors?: VectorStateDto[];
        records?: VectorRecordDto[];
        error?: string;
      };
      if (!res.ok) {
        setOutput(`Error: ${data.error ?? "Sandbox execution failed"}`);
        return;
      }
      const formattedOutput = Array.isArray(data.output)
        ? data.output.join("\n")
        : (data.output ?? "");
      setOutput(formattedOutput);
      setVectors(data.vectors ?? []);
      setRecords(data.records ?? []);
    } catch (err) {
      setOutput(`Error: ${err instanceof Error ? err.message : "Sandbox request failed"}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
      <section className="flex flex-col border border-slate-200 bg-white">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 px-5 py-3.5">
          <div>
            <h2 className="text-sm font-semibold text-slate-900">
              VectorKernelX Opcode Sandbox
            </h2>
            <p className="text-xs text-slate-500">
              Isolated compiler &amp; verifier preview (does not mutate persistent WAL ledger)
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => void runAction("demo")}
              disabled={busy}
              className="inline-flex items-center gap-1 border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-100"
            >
              <Sparkles className="h-3.5 w-3.5 text-blue-600" />
              Load Demo
            </button>
            <button
              type="button"
              onClick={() => void runAction("reset")}
              disabled={busy}
              className="inline-flex items-center gap-1 border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              Reset
            </button>
          </div>
        </div>

        <div className="space-y-3 p-5">
          <textarea
            value={script}
            onChange={(e) => setScript(e.target.value)}
            rows={9}
            spellCheck={false}
            className="w-full border border-slate-300 bg-slate-950 p-3.5 font-mono text-xs leading-relaxed text-slate-100 focus:border-blue-600 focus:outline-none"
          />
          <div className="flex items-center justify-between">
            <span className="font-mono text-[11px] text-slate-500">
              Opcodes: ORIGIN_CREATE · TRANSFER · DRAIN · PROJECT · RECONSTRUCT · CERTIFY
            </span>
            <button
              type="button"
              onClick={() => void runAction("execute")}
              disabled={busy}
              className="inline-flex items-center gap-1.5 bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-700 disabled:opacity-50"
            >
              <Play className="h-3.5 w-3.5" />
              {busy ? "Running..." : "Execute Script"}
            </button>
          </div>
          {output && (
            <pre className="max-h-48 overflow-auto border border-slate-200 bg-slate-50 p-3 font-mono text-[11px] text-slate-800">
              {output}
            </pre>
          )}
        </div>
      </section>

      <section className="space-y-6">
        <div className="border border-slate-200 bg-white">
          <div className="border-b border-slate-200 px-5 py-3.5">
            <h3 className="text-sm font-semibold text-slate-900">
              Sandbox Vector States ({vectors.length})
            </h3>
          </div>
          {vectors.length === 0 ? (
            <div className="px-5 py-8 text-center text-xs text-slate-500">
              Run a script or click &ldquo;Load Demo&rdquo; to populate in-memory vectors.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                    <th className="px-5 py-2.5">Vector ID</th>
                    <th className="px-4 py-2.5">Type</th>
                    <th className="px-4 py-2.5">Status</th>
                    <th className="px-5 py-2.5 text-right">Components</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {vectors.map((v) => (
                    <tr key={v.vectorId} className="hover:bg-slate-50">
                      <td className="px-5 py-2.5 font-mono font-medium text-slate-900">
                        {v.vectorId}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-slate-600">{v.vectorType}</td>
                      <td className="px-4 py-2.5 font-mono text-slate-700">{v.status}</td>
                      <td className="px-5 py-2.5 text-right font-mono tabular-nums text-slate-900">
                        [{v.components.join(", ")}]
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="border border-slate-200 bg-white">
          <div className="border-b border-slate-200 px-5 py-3.5">
            <h3 className="text-sm font-semibold text-slate-900">
              Transition Trace ({records.length})
            </h3>
          </div>
          {records.length === 0 ? (
            <div className="px-5 py-6 text-xs text-slate-500">No sandbox transitions executed.</div>
          ) : (
            <div className="max-h-64 divide-y divide-slate-100 overflow-auto px-5 text-xs">
              {records.map((r) => (
                <div key={r.recordId} className="flex items-center justify-between py-2.5">
                  <div>
                    <span className="font-mono font-medium text-slate-900">{r.operation}</span>
                    <span className="ml-2 font-mono text-slate-500">{r.vectorId}</span>
                  </div>
                  <span className="font-mono tabular-nums text-slate-600">
                    [{r.after.components.join(", ")}]
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
