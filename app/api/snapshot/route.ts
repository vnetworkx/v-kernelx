import { NextResponse } from "next/server";
import { getKernel, logServerEvent } from "@/lib/server/kernel";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({ snapshots: getKernel().store.listSnapshots() });
}

export async function POST() {
  try {
    const kernel = getKernel();
    const snapshot = kernel.createAndStoreSnapshot();
    const verified = kernel.verifySnapshot(snapshot);
    logServerEvent("info", "snapshot_created", {
      snapshot_id: snapshot.snapshot_id,
      verified,
    });
    return NextResponse.json({ snapshot, verified });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : String(err) },
      { status: 400 },
    );
  }
}
