import { NextResponse } from "next/server";
import { fetchNetworkApiJson } from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const [replayRes, proofsRes] = await Promise.all([
    fetchNetworkApiJson<{
      valid?: boolean;
      events_replayed?: number;
      replayed_state_root?: string;
      live_state_root?: string;
      replayed_replay_hash?: string;
      live_replay_hash?: string;
    }>("/v1/ledger/replay"),
    fetchNetworkApiJson<{
      chain_valid?: boolean;
      state_root?: string;
      replay_hash?: string;
      event_count?: number;
      height?: number;
    }>("/v1/ledger/proofs"),
  ]);

  if (!replayRes.ok || !replayRes.data) {
    return NextResponse.json(
      {
        error: replayRes.error ?? "Rust node replay endpoint unreachable",
        matches_stored_state: false,
        verification_status: "UNKNOWN",
      },
      { status: replayRes.status },
    );
  }

  const r = replayRes.data;
  const mismatchReasons: string[] = [];
  if (r.valid !== true) {
    mismatchReasons.push("Deterministic replay returned valid=false");
  }
  if (!r.replayed_state_root || r.replayed_state_root !== r.live_state_root) {
    mismatchReasons.push(
      `State root mismatch: replayed=${r.replayed_state_root ?? "missing"} live=${r.live_state_root ?? "missing"}`,
    );
  }
  if (!r.replayed_replay_hash || r.replayed_replay_hash !== r.live_replay_hash) {
    mismatchReasons.push(
      `Replay hash mismatch: replayed=${r.replayed_replay_hash ?? "missing"} live=${r.live_replay_hash ?? "missing"}`,
    );
  }
  if (proofsRes.ok && proofsRes.data && proofsRes.data.chain_valid !== true) {
    mismatchReasons.push("Ledger event chain proof verification failed");
  }

  const verified = mismatchReasons.length === 0;
  return NextResponse.json({
    state_root: {
      root_hash: String(r.live_state_root ?? proofsRes.data?.state_root ?? ""),
      event_count: Number(r.events_replayed ?? proofsRes.data?.event_count ?? 0),
      logical_clock: Number(proofsRes.data?.height ?? 0),
    },
    replay_hash: String(r.replayed_replay_hash ?? proofsRes.data?.replay_hash ?? ""),
    events_replayed: Number(r.events_replayed ?? 0),
    replayed_state_root: String(r.replayed_state_root ?? ""),
    live_state_root: String(r.live_state_root ?? ""),
    applied_event_hashes: [],
    matches_stored_state: verified,
    verification_status: verified ? "VERIFIED" : "INVALID",
    mismatch_reasons: mismatchReasons,
  });
}
