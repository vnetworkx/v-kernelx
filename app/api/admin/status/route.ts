import { NextResponse } from "next/server";
import { fetchNetworkApiJson, requireAdminToken } from "@/lib/server/kernel";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const auth = requireAdminToken(request);
  if (!auth.ok) {
    return NextResponse.json({ error: auth.error }, { status: auth.status });
  }
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
