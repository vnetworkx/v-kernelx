import { NextResponse } from "next/server";
import { fetchNetworkApiJson } from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  context: { params: Promise<{ id: string }> },
) {
  const { id } = await context.params;
  const upstream = await fetchNetworkApiJson<Array<Record<string, unknown>>>("/v1/ledger/events");
  if (!upstream.ok || !Array.isArray(upstream.data)) {
    return NextResponse.json(
      { error: upstream.error ?? "Rust node unreachable" },
      { status: upstream.status },
    );
  }
  const events = upstream.data.filter(
    (e) =>
      String(e.entity_id ?? "") === id ||
      JSON.stringify(e.payload ?? "").includes(id),
  );
  return NextResponse.json({ wallet_id: id, transactions: events });
}
