"use client";

import { useState } from "react";
import { CheckCircle2, Code2, Play, Send } from "lucide-react";
import { formatTimestampMs, shortenHash } from "@/lib/format";
import { signProgramSubmissionClient } from "@/lib/client-crypto";
import type { BrowserSignerKey, ProgramDto } from "@/lib/types";

interface SandboxPanelProps {
  networkId: string;
  programs: ProgramDto[];
  signerKeys: Record<string, BrowserSignerKey>;
  activeSignerId: string | null;
  onOpenWallets: () => void;
  onRefresh: () => Promise<void>;
  onNotify: (kind: "success" | "error", msg: string) => void;
}

const TEMPLATES: Record<string, { fileName: string; source: string }> = {
  workflow: {
    fileName: "workflow.vx",
    source: `space create AppSpace {
    name = "Application Space";
    visibility = "public";
}

region create AppRegion in "AppSpace" {
    name = "App Region";
    prefix = "APP";
    visibility = "public";
    section = 1;
}

query network;
verify proof network;`,
  },
  contract: {
    fileName: "escrow-contract.vx",
    source: `contract create EscrowContract {
    region = "AppRegion";
    escrow_mode = "deterministic";
    action settle(recipient="BeneficiaryWallet", amount=100);
    action release(memo="released");
}

query network;`,
  },
  ghost: {
    fileName: "ghost-entity.vx",
    source: `// Parentless Ghost entities bind directly to Network scope
region create GhostRegion {
    name = "Ghost Region";
    prefix = "GHO";
    visibility = "private";
    section = 99;
    ghost = true;
}

query network;`,
  },
};

export function SandboxPanel({
  networkId,
  programs,
  signerKeys,
  activeSignerId,
  onOpenWallets,
  onRefresh,
  onNotify,
}: SandboxPanelProps) {
  const [fileName, setFileName] = useState("workflow.vx");
  const [sourceBytes, setSourceBytes] = useState(TEMPLATES.workflow.source);
  const [compileOutput, setCompileOutput] = useState<string>("");
  const [busyMode, setBusyMode] = useState<"compile" | "submit" | null>(null);

  const activeSigner = activeSignerId ? signerKeys[activeSignerId] : null;

  function loadTemplate(key: keyof typeof TEMPLATES) {
    const tpl = TEMPLATES[key];
    setFileName(tpl.fileName);
    setSourceBytes(tpl.source);
    setCompileOutput("");
  }

  async function handleCompile() {
    setBusyMode("compile");
    try {
      const res = await fetch("/api/sandbox", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: "compile",
          file_name: fileName.trim() || "program.vx",
          source_bytes: sourceBytes,
          modules: {},
        }),
      });
      const data = (await res.json()) as {
        compiled?: unknown;
        error?: string;
      };
      if (!res.ok) {
        setCompileOutput(`Compile Error: ${data.error ?? "Compiler rejected source"}`);
        onNotify("error", data.error ?? "Vector Language compilation failed");
        return;
      }
      setCompileOutput(JSON.stringify(data.compiled, null, 2));
      onNotify("success", `Compiled ${fileName} cleanly via Rust vectorspace compiler`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Compile request failed";
      setCompileOutput(`Compile Error: ${msg}`);
      onNotify("error", msg);
    } finally {
      setBusyMode(null);
    }
  }

  async function handleSubmitSignedProgram() {
    if (!activeSigner) {
      onNotify("error", "Unlock or generate an Ed25519 signer in Wallets before submitting a .vx program.");
      onOpenWallets();
      return;
    }
    setBusyMode("submit");
    try {
      const signed = await signProgramSubmissionClient({
        privateKeyHex: activeSigner.private_key_hex,
        actorPubkey: activeSigner.public_key_hex,
        fileName: fileName.trim() || "program.vx",
        sourceBytes,
        modules: {},
        networkId,
        requestId: `vx_${Date.now()}`,
        nonce: Date.now(),
        executionParams: {},
      });
      const res = await fetch("/api/sandbox", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: "submit",
          ...signed,
        }),
      });
      const data = (await res.json()) as {
        submission?: unknown;
        error?: string;
      };
      if (!res.ok) {
        setCompileOutput(`Submission Error: ${data.error ?? "Program rejected"}`);
        onNotify("error", data.error ?? "Program submission failed");
        return;
      }
      setCompileOutput(JSON.stringify(data.submission, null, 2));
      await onRefresh();
      onNotify("success", `Signed program ${fileName} committed to Rust kernel`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Program submission failed";
      setCompileOutput(`Submission Error: ${msg}`);
      onNotify("error", msg);
    } finally {
      setBusyMode(null);
    }
  }

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
      <section className="flex flex-col border border-slate-200 bg-white">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 px-5 py-3.5">
          <div>
            <h2 className="text-sm font-semibold text-slate-900">
              Vector Language (.vx / .vdx) Workbench
            </h2>
            <p className="text-xs text-slate-500">
              Compile through Rust vectorspace compiler or sign &amp; execute directly against /v1/programs/submit
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              onClick={() => loadTemplate("workflow")}
              className="border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-100"
            >
              Space &amp; Region
            </button>
            <button
              type="button"
              onClick={() => loadTemplate("contract")}
              className="border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-100"
            >
              vContract
            </button>
            <button
              type="button"
              onClick={() => loadTemplate("ghost")}
              className="border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-100"
            >
              Ghost Entity
            </button>
          </div>
        </div>

        <div className="space-y-3 p-5 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <label className="font-medium text-slate-700">Filename:</label>
              <input
                type="text"
                value={fileName}
                onChange={(e) => setFileName(e.target.value)}
                className="border border-slate-300 px-2.5 py-1 font-mono text-xs focus:border-blue-600 focus:outline-none"
              />
            </div>
            <div className="font-mono text-[11px] text-slate-500">
              Signer: {activeSigner ? activeSigner.label : "None unlocked (compile still works)"}
            </div>
          </div>

          <textarea
            value={sourceBytes}
            onChange={(e) => setSourceBytes(e.target.value)}
            rows={12}
            spellCheck={false}
            className="w-full border border-slate-300 bg-slate-950 p-3.5 font-mono text-xs leading-relaxed text-slate-100 focus:border-blue-600 focus:outline-none"
          />

          <div className="flex flex-wrap items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => void handleCompile()}
              disabled={busyMode !== null}
              className="inline-flex items-center gap-1.5 border border-slate-300 bg-white px-4 py-2 text-xs font-medium text-slate-800 hover:bg-slate-50 disabled:opacity-50"
            >
              <Code2 className="h-3.5 w-3.5 text-blue-600" />
              {busyMode === "compile" ? "Compiling..." : "Compile & Verify"}
            </button>
            <button
              type="button"
              onClick={() => void handleSubmitSignedProgram()}
              disabled={busyMode !== null}
              className="inline-flex items-center gap-1.5 bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-700 disabled:opacity-50"
            >
              <Send className="h-3.5 w-3.5" />
              {busyMode === "submit" ? "Submitting Signed .vx..." : "Sign & Execute (.vx)"}
            </button>
          </div>

          {compileOutput && (
            <pre className="max-h-64 overflow-auto border border-slate-200 bg-slate-50 p-3 font-mono text-[11px] text-slate-800">
              {compileOutput}
            </pre>
          )}
        </div>
      </section>

      <section className="space-y-6">
        <div className="border border-slate-200 bg-white">
          <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3.5">
            <div>
              <h3 className="text-sm font-semibold text-slate-900">
                Committed Network Programs ({programs.length})
              </h3>
              <p className="text-xs text-slate-500">
                Verified .vx / .vdx program executions persisted in canonical ledger state
              </p>
            </div>
            <Play className="h-4 w-4 text-slate-400" />
          </div>

          {programs.length === 0 ? (
            <div className="px-5 py-8 text-center text-xs text-slate-500">
              No Vector Language programs committed to this node yet.
            </div>
          ) : (
            <div className="divide-y divide-slate-100">
              {[...programs].reverse().map((prog) => (
                <div key={prog.program_id} className="space-y-1.5 p-4 text-xs">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 font-mono font-semibold text-slate-900">
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600" />
                      <span>{prog.file_name}</span>
                      <span className="text-slate-400">· {prog.program_id}</span>
                    </div>
                    <span className="font-mono text-[11px] text-slate-500">
                      {prog.status} · {formatTimestampMs(prog.submitted_at_ms)}
                    </span>
                  </div>
                  <div className="font-mono text-[11px] text-slate-500">
                    source={shortenHash(prog.source_hash, 12, 8)} · events=
                    {prog.resulting_event_ids.length} · entities={prog.created_entities.length}
                  </div>
                  {prog.outputs.length > 0 && (
                    <pre className="max-h-28 overflow-auto border border-slate-100 bg-slate-50 p-2 font-mono text-[11px] text-slate-700">
                      {prog.outputs.join("\n")}
                    </pre>
                  )}
                  {prog.error_message && (
                    <div className="font-mono text-[11px] text-red-700">{prog.error_message}</div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
