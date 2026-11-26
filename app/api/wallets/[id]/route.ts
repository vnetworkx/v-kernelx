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
  const wallet = mapped.initialWallets.find((w) => w.wallet_id === id);
  if (!wallet) {
    return NextResponse.json({ error: `Wallet '${id}' not found` }, { status: 404 });
  }
  return NextResponse.json({ wallet });
}
