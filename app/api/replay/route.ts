import { NextResponse } from "next/server";
import { fetchNetworkApiJson } from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const upstream = await fetchNetworkApiJson<Record<string, unknown>>("/v1/ledger/proofs");
  if (!upstream.ok || !upstream.data) {
    return NextResponse.json(
      { error: upstream.error ?? "Rust node unreachable" },
      { status: upstream.status },
    );
  }
  return NextResponse.json({
    state_root: {
      root_hash: String(upstream.data.state_root ?? ""),
      event_count: Number(upstream.data.event_count ?? 0),
      logical_clock: Number(upstream.data.height ?? 0),
    },
    replay_hash: String(upstream.data.replay_hash ?? ""),
    applied_event_hashes: [],
    matches_stored_state: Boolean(upstream.data.chain_valid),
    mismatch_reasons: upstream.data.chain_valid ? [] : ["Ledger chain verification returned false"],
  });
}
