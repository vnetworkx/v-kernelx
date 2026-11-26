import { NextResponse } from "next/server";
import { postNetworkApiJson } from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({
    schema: "vector-network/1.0.0",
    vectors: [],
    records: [],
  });
}

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as {
    file_name?: unknown;
    script?: unknown;
    source_bytes?: unknown;
    modules?: unknown;
  };

  const sourceBytes =
    typeof body.source_bytes === "string"
      ? body.source_bytes
      : typeof body.script === "string"
        ? body.script
        : "";
  if (!sourceBytes.trim()) {
    return NextResponse.json(
      { error: "Vector Language source_bytes (or script) is required" },
      { status: 400 },
    );
  }

  const upstream = await postNetworkApiJson("/v1/language/compile", {
    file_name: typeof body.file_name === "string" ? body.file_name : "sandbox.vx",
    source_bytes: sourceBytes,
    modules:
      body.modules && typeof body.modules === "object" ? body.modules : {},
  });

  if (!upstream.ok) {
    return NextResponse.json(
      { error: upstream.error ?? "Rust Vector Language compiler unavailable" },
      { status: upstream.status },
    );
  }

  return NextResponse.json({
    schema: "vector-network/1.0.0",
    compiled: upstream.data,
    vectors: [],
    records: [],
  });
}
