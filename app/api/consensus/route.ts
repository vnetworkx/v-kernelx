import { NextResponse } from "next/server";
import { fetchNetworkApiJson } from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const upstream = await fetchNetworkApiJson<Record<string, unknown>>("/v1/consensus/status");
  if (!upstream.ok || !upstream.data) {
    return NextResponse.json(
      {
        validators: [],
        rounds: [],
        equivocations: [],
        equivocation_count: 0,
        equivocation_store_ok: false,
        error: upstream.error ?? "Rust node unreachable",
      },
      { status: upstream.status },
    );
  }
  const rawVals = Array.isArray(upstream.data.validators)
    ? (upstream.data.validators as Array<Record<string, unknown>>)
    : [];
  const rawEquivocations = Array.isArray(upstream.data.equivocations)
    ? (upstream.data.equivocations as Array<Record<string, unknown>>)
    : [];
  return NextResponse.json({
    validators: rawVals.map((v) => ({
      node_id: String(v.validator_id ?? v.node_id ?? ""),
      public_key_hex: String(v.validator_pubkey_hex ?? v.pubkey_hex ?? v.public_key_hex ?? ""),
      label: String(v.validator_id ?? "validator"),
      weight: Number(v.weight ?? 1),
      active: v.active !== false,
      joined_at_ms: Number(v.joined_epoch ?? 0),
    })),
    rounds: [],
    equivocations: rawEquivocations,
    equivocation_count: Number(upstream.data.equivocation_count ?? rawEquivocations.length),
    equivocation_store_ok: upstream.data.equivocation_store_ok === true,
    quorum_threshold_bps: Number(upstream.data.quorum_threshold_bps ?? 6667),
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
