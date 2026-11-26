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
    return NextResponse.json({ wallets: [], error: snapshot.error }, { status: 503 });
  }
  const mapped = mapNetworkSnapshotToWorkbenchProps(snapshot);
  return NextResponse.json({ wallets: mapped.initialWallets });
}

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
  if (!body.signature || !body.actor_pubkey || !body.operation) {
    return NextResponse.json(
      {
        error:
          "Wallets are created and authorized via signed CreateWallet/AuthorizeWalletKey transactions on /v1/transactions",
      },
      { status: 400 },
    );
  }
  const upstream = await postNetworkApiJson("/v1/transactions", body);
  return NextResponse.json(
    upstream.data ?? { error: upstream.error ?? "Wallet operation rejected" },
    { status: upstream.ok ? 200 : upstream.status },
  );
}
