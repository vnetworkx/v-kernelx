import { NextResponse } from "next/server";
import { fetchNetworkExplorerSnapshot } from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const snapshot = await fetchNetworkExplorerSnapshot();
  return NextResponse.json(snapshot, { status: snapshot.reachable ? 200 : 503 });
}
