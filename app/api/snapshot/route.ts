import { NextResponse } from "next/server";
import { fetchNetworkApiJson } from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const upstream = await fetchNetworkApiJson<Record<string, unknown>>("/v1/ledger/proofs");
  if (!upstream.ok) {
    return NextResponse.json(
      { snapshots: [], error: upstream.error ?? "Rust node unreachable" },
      { status: upstream.status },
    );
  }
  return NextResponse.json({
    snapshots: upstream.data?.latest_certificate
      ? [upstream.data.latest_certificate]
      : [],
  });
}

export async function POST() {
  return NextResponse.json(
    {
      error:
        "Snapshots and atomic WAL commits are managed automatically by vnetwork-node on consensus finality",
    },
    { status: 405 },
  );
}
