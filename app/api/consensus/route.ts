import { NextResponse } from "next/server";
import { fetchNetworkApiJson } from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const upstream = await fetchNetworkApiJson<Record<string, unknown>>("/v1/consensus/status");
  if (!upstream.ok || !upstream.data) {
    return NextResponse.json(
      { validators: [], rounds: [], error: upstream.error ?? "Rust node unreachable" },
      { status: upstream.status },
    );
  }
  const rawVals = Array.isArray(upstream.data.validators)
    ? (upstream.data.validators as Array<Record<string, unknown>>)
    : [];
  return NextResponse.json({
    validators: rawVals.map((v) => ({
      node_id: String(v.validator_id ?? v.node_id ?? ""),
      public_key_hex: String(v.pubkey_hex ?? v.public_key_hex ?? ""),
      label: String(v.validator_id ?? "validator"),
      weight: Number(v.weight ?? 1),
      active: v.active !== false,
      joined_at_ms: 0,
    })),
    rounds: [],
    consensus: upstream.data,
  });
}

export async function POST() {
  return NextResponse.json(
    {
      error:
        "Consensus rounds are driven exclusively by validator P2P proposals and quorum votes in vnetwork-node",
    },
    { status: 405 },
  );
}
