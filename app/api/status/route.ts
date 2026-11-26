import { NextResponse } from "next/server";
import {
  fetchNetworkExplorerSnapshot,
  mapNetworkSnapshotToWorkbenchProps,
} from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const snapshot = await fetchNetworkExplorerSnapshot();
  if (!snapshot.reachable) {
    return NextResponse.json(
      { error: snapshot.error ?? `Node unreachable at ${snapshot.endpoint}` },
      { status: 503 },
    );
  }
  const mapped = mapNetworkSnapshotToWorkbenchProps(snapshot);
  return NextResponse.json(mapped.initialStatus);
}
