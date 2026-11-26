import { NextResponse } from "next/server";
import { getKernel } from "@/lib/server/kernel";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const kernel = getKernel();
    return NextResponse.json({
      status: "ok",
      node_id: kernel.nodeId,
      db_integrity_ok: kernel.store.integrityCheck(),
    });
  } catch (err) {
    return NextResponse.json(
      { status: "error", error: err instanceof Error ? err.message : String(err) },
      { status: 500 },
    );
  }
}
