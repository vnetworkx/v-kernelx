import { NextResponse } from "next/server";
import { fetchNetworkApiJson } from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const upstream = await fetchNetworkApiJson<unknown[] | { events?: unknown[] }>("/v1/ledger/events");
  if (!upstream.ok || !upstream.data) {
    return NextResponse.json(
      { events: [], error: upstream.error ?? "Rust node unreachable" },
      { status: upstream.status },
    );
  }
  const events = Array.isArray(upstream.data)
    ? upstream.data
    : Array.isArray(upstream.data.events)
      ? upstream.data.events
      : [];
  return NextResponse.json({ events });
}
