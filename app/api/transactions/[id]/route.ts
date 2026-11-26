import { NextResponse } from "next/server";
import { fetchNetworkApiJson } from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  context: { params: Promise<{ id: string }> },
) {
  const { id } = await context.params;
  const upstream = await fetchNetworkApiJson(`/v1/transactions/${encodeURIComponent(id)}`);
  return NextResponse.json(
    upstream.data ?? { error: upstream.error ?? "Transaction not found" },
    { status: upstream.ok ? 200 : upstream.status },
  );
}
