import { NextResponse } from "next/server";
import { postNetworkApiJson } from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
  if (!body.signature || !body.actor_pubkey || !body.operation) {
    return NextResponse.json(
      {
        error:
          "Signed Rust DrainToken transaction envelope is required on /v1/transactions",
      },
      { status: 400 },
    );
  }
  const upstream = await postNetworkApiJson("/v1/transactions", body);
  return NextResponse.json(
    upstream.data ?? { error: upstream.error ?? "Drain rejected" },
    { status: upstream.ok ? 200 : upstream.status },
  );
}
