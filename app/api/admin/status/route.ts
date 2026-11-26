import { NextResponse } from "next/server";
import { fetchNetworkApiJson } from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const [status, consensus] = await Promise.all([
    fetchNetworkApiJson("/v1/network/status"),
    fetchNetworkApiJson("/v1/consensus/status"),
  ]);
  if (!status.ok) {
    return NextResponse.json(
      { error: status.error ?? "Rust node unreachable" },
      { status: 503 },
    );
  }
  return NextResponse.json({
    status: status.data,
    consensus: consensus.data,
  });
}
