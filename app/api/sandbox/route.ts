import { NextResponse } from "next/server";
import { findValidNonce, STATE_SCHEMA_V1 } from "@/ts/src/index.ts";
import { getSandboxKernel, resetSandboxKernel } from "@/lib/server/kernel";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const sandbox = getSandboxKernel();
  return NextResponse.json({
    schema: STATE_SCHEMA_V1,
    vectors: sandbox.queryVectors(),
    records: sandbox.queryRecords(),
  });
}

export async function POST(request: Request) {
  try {
    const body = (await request.json().catch(() => ({}))) as {
      action?: unknown;
      script?: unknown;
    };
    const action = typeof body.action === "string" ? body.action : "execute";

    if (action === "demo") {
      const sandbox = resetSandboxKernel();
      const nonceA = findValidNonce("seed-a", 1) ?? 0;
      const nonceB = findValidNonce("seed-b", 1) ?? 0;
      sandbox.originCreate("v-a", "pk-a", "space-1", [1000, 2000], "seed-a", nonceA, 1);
      sandbox.originCreate("v-b", "pk-b", "space-1", [50, 75], "seed-b", nonceB, 1);
      sandbox.transfer("v-a", "v-b", [250, 250]);
      sandbox.drain("v-a", 100);
      sandbox.project("v-b", [10, 10], "escrow-1");
      sandbox.reconstruct("v-b", [2, 1], [0, 0], "settled");
      return NextResponse.json({
        schema: STATE_SCHEMA_V1,
        output: "Loaded canonical 6-step protocol demo (ORIGIN_CREATE x2 -> TRANSFER -> DRAIN -> PROJECT -> RECONSTRUCT).",
        vectors: sandbox.queryVectors(),
        records: sandbox.queryRecords(),
      });
    }

    if (action === "reset") {
      const sandbox = resetSandboxKernel();
      return NextResponse.json({
        schema: STATE_SCHEMA_V1,
        output: "Sandbox reset.",
        vectors: sandbox.queryVectors(),
        records: sandbox.queryRecords(),
      });
    }

    const script = String(body.script ?? "");
    const sandbox = getSandboxKernel();
    const lines = sandbox.execute(script);
    return NextResponse.json({
      schema: STATE_SCHEMA_V1,
      output: lines.length > 0 ? lines.join("\n") : "Executed (0 commands).",
      vectors: sandbox.queryVectors(),
      records: sandbox.queryRecords(),
    });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : String(err) },
      { status: 400 },
    );
  }
}
