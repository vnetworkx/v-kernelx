import { NextResponse } from "next/server";
import { postNetworkApiJson } from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({
    mode: "vector-language",
    modes: ["compile", "submit"],
  });
}

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;

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

  const fileName = typeof body.file_name === "string" ? body.file_name : "program.vx";
  const modules =
    body.modules && typeof body.modules === "object" ? body.modules : {};

  if (body.action === "submit" || (body.signature && body.actor_pubkey && body.network_id)) {
    if (
      typeof body.actor_pubkey !== "string" ||
      typeof body.signature !== "string" ||
      typeof body.network_id !== "string" ||
      typeof body.request_id !== "string" ||
      typeof body.nonce !== "number"
    ) {
      return NextResponse.json(
        {
          error:
            "Signed .vx program submission requires actor_pubkey, network_id, request_id, nonce, and signature",
        },
        { status: 400 },
      );
    }
    const upstream = await postNetworkApiJson("/v1/programs/submit", {
      actor_pubkey: body.actor_pubkey,
      file_name: fileName,
      source_bytes: sourceBytes,
      modules,
      network_id: body.network_id,
      request_id: body.request_id,
      nonce: body.nonce,
      execution_params:
        body.execution_params && typeof body.execution_params === "object"
          ? body.execution_params
          : {},
      signature: body.signature,
    });
    if (!upstream.ok) {
      return NextResponse.json(
        { error: upstream.error ?? "Program submission rejected" },
        { status: upstream.status },
      );
    }
    return NextResponse.json({
      mode: "submit",
      submission: upstream.data,
    });
  }

  const upstream = await postNetworkApiJson("/v1/language/compile", {
    file_name: fileName,
    source_bytes: sourceBytes,
    modules,
  });

  if (!upstream.ok) {
    return NextResponse.json(
      { error: upstream.error ?? "Rust Vector Language compiler unavailable" },
      { status: upstream.status },
    );
  }

  return NextResponse.json({
    mode: "compile",
    compiled: upstream.data,
  });
}
