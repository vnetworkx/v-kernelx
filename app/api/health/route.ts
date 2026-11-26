import { NextResponse } from "next/server";
import { fetchNetworkApiJson, getNetworkApiUrl } from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const upstream = await fetchNetworkApiJson<{
    healthy?: boolean;
    storage_ok?: boolean;
    node_id?: string;
    network_id?: string;
    height?: number;
  }>("/healthz");

  if (!upstream.ok || !upstream.data) {
    return NextResponse.json(
      {
        status: "unhealthy",
        healthy: false,
        storage_ok: false,
        endpoint: getNetworkApiUrl(),
        error: upstream.error ?? "Upstream Rust node unreachable",
      },
      { status: 503 },
    );
  }

  const healthy = upstream.data.healthy === true && upstream.data.storage_ok !== false;
  return NextResponse.json(
    {
      status: healthy ? "ok" : "degraded",
      healthy,
      node_id: upstream.data.node_id ?? "",
      network_id: upstream.data.network_id ?? "",
      height: upstream.data.height ?? 0,
      db_integrity_ok: upstream.data.storage_ok !== false,
    },
    { status: healthy ? 200 : 503 },
  );
}
