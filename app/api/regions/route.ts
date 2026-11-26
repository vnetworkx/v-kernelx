import { NextResponse } from "next/server";
import type { RegionCreateRequest } from "@/ts/src/index.ts";
import { getCoreTriggerEventHash, getKernel, logServerEvent } from "@/lib/server/kernel";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const kernel = getKernel();
  const core_event_hash = getCoreTriggerEventHash(kernel);
  return NextResponse.json({
    regions: kernel.listRegions(),
    core_event_hash,
  });
}

export async function POST(request: Request) {
  try {
    const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
    const kernel = getKernel();

    if (!body.signed_request || !body.actor_public_key) {
      return NextResponse.json(
        { error: "Ed25519 client signature (signed_request + actor_public_key) is required" },
        { status: 400 },
      );
    }

    const result = kernel.createRegion(
      body.signed_request as RegionCreateRequest,
      String(body.actor_public_key),
    );
    logServerEvent("info", "region_created", {
      region_id: result.region.region_id,
      name: result.region.region_name,
    });
    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : String(err) },
      { status: 400 },
    );
  }
}
