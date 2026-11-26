import { NextResponse } from "next/server";
import { fetchNetworkApiJson, getNetworkApiUrl } from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const upstream = await fetchNetworkApiJson<{
    healthy?: boolean;
    ready?: boolean;
    storage_ok?: boolean;
    wal_consistency_ok?: boolean;
    equivocation_store_ok?: boolean;
    equivocation_count?: number;
    verification_status?: string;
    key_storage_mode?: string;
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
        wal_consistency_ok: false,
        equivocation_store_ok: false,
        equivocation_count: 0,
        verification_status: upstream.data ? "INVALID" : "UNKNOWN",
        db_integrity_ok: false,
        endpoint: getNetworkApiUrl(),
        error: upstream.error ?? "Upstream Rust node unreachable",
      },
      { status: 503 },
    );
  }

  const storageOk = upstream.data.storage_ok === true;
  const walOk = upstream.data.wal_consistency_ok === true;
  const equivocationStoreOk = upstream.data.equivocation_store_ok === true;
  const equivocationCount = Number(upstream.data.equivocation_count ?? 0);
  const healthy =
    upstream.data.healthy === true &&
    storageOk &&
    walOk &&
    equivocationStoreOk &&
    equivocationCount === 0;

  return NextResponse.json(
    {
      status: healthy ? "ok" : "degraded",
      healthy,
      ready: upstream.data.ready === true && healthy,
      node_id: upstream.data.node_id ?? "",
      network_id: upstream.data.network_id ?? "",
      height: upstream.data.height ?? 0,
      storage_ok: storageOk,
      wal_consistency_ok: walOk,
      equivocation_store_ok: equivocationStoreOk,
      equivocation_count: equivocationCount,
      key_storage_mode: upstream.data.key_storage_mode ?? "unknown",
      verification_status: healthy ? "VERIFIED" : "INVALID",
      db_integrity_ok: storageOk && walOk && equivocationStoreOk,
    },
    { status: healthy ? 200 : 503 },
  );
}
