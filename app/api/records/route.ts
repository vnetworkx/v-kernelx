import { NextResponse } from "next/server";
import { fetchNetworkApiJson } from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const upstream = await fetchNetworkApiJson<unknown[]>("/v1/ledger/events");
  if (!upstream.ok) {
    return NextResponse.json(
      { records: [], error: upstream.error ?? "Rust node unreachable" },
      { status: upstream.status },
    );
  }
  return NextResponse.json({ records: upstream.data ?? [] });
}
