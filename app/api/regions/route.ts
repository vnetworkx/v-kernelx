import { NextResponse } from "next/server";
import {
  fetchNetworkExplorerSnapshot,
  mapNetworkSnapshotToWorkbenchProps,
  postNetworkApiJson,
} from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const snapshot = await fetchNetworkExplorerSnapshot();
  if (!snapshot.reachable) {
    return NextResponse.json(
      { regions: [], core_event_hash: "", error: snapshot.error },
      { status: 503 },
    );
  }
  const mapped = mapNetworkSnapshotToWorkbenchProps(snapshot);
  return NextResponse.json({
    regions: mapped.initialRegions,
    core_event_hash: mapped.coreEventHash,
  });
}

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
  if (!body.signature || !body.actor_pubkey || !body.operation) {
    return NextResponse.json(
      {
        error:
          "Signed Rust transaction envelope (actor_pubkey, signature, network_id, nonce, timestamp_ms, operation) is required",
      },
      { status: 400 },
    );
  }
  const upstream = await postNetworkApiJson("/v1/transactions", body);
  return NextResponse.json(
    upstream.data ?? { error: upstream.error ?? "Transaction rejected" },
    { status: upstream.ok ? 200 : upstream.status },
  );
}
