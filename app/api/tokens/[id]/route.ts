import { NextResponse } from "next/server";
import {
  fetchNetworkExplorerSnapshot,
  mapNetworkSnapshotToWorkbenchProps,
} from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  context: { params: Promise<{ id: string }> },
) {
  const { id } = await context.params;
  const snapshot = await fetchNetworkExplorerSnapshot();
  if (!snapshot.reachable) {
    return NextResponse.json({ error: snapshot.error ?? "Node unreachable" }, { status: 503 });
  }
  const mapped = mapNetworkSnapshotToWorkbenchProps(snapshot);
  const token = mapped.initialTokens.find(
    (t) => t.token_id === id || t.symbol.toLowerCase() === id.toLowerCase(),
  );
  if (!token) {
    return NextResponse.json({ error: `Token '${id}' not found` }, { status: 404 });
  }
  return NextResponse.json({ token });
}
