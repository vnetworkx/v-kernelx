import { NextResponse } from "next/server";
import { fetchNetworkExplorerSnapshot } from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const snapshot = await fetchNetworkExplorerSnapshot();
  if (!snapshot.reachable || !snapshot.data) {
    return NextResponse.json(
      { vectors: [], tokens: [], rewards: [], error: snapshot.error ?? "Rust node unreachable" },
      { status: 503 },
    );
  }
  const tokens = Array.isArray(snapshot.data.tokens)
    ? (snapshot.data.tokens as Array<Record<string, unknown>>)
    : [];
  const balances = Array.isArray(snapshot.data.balances)
    ? (snapshot.data.balances as Array<Record<string, unknown>>)
    : [];
  const tokenById = new Map(tokens.map((t) => [String(t.token_id ?? ""), t]));

  const vectors = balances.map((b) => {
    const tid = String(b.token_id ?? "");
    const wid = String(b.wallet_id ?? "");
    const vec = (b.vector ?? {}) as Record<string, unknown>;
    const tok = tokenById.get(tid);
    const authRatioAu = Number(vec.auth_ratio_au ?? 0);
    const explicitSpaceId = typeof tok?.space_id === "string" ? tok.space_id : null;
    const ownerPubkey = typeof b.owner_pubkey === "string" ? b.owner_pubkey : null;
    return {
      schema: "vector-token-balance/v1",
      vectorId: `${tid}::${wid}`,
      ownerPubkey,
      spaceId: explicitSpaceId,
      vectorType: tok ? `${String(tok.symbol ?? "TOKEN")} (${String(tok.name ?? "")})` : tid,
      status: wid.startsWith("ghost_custody::") ? "GHOST_CUSTODY" : wid.startsWith("escrow::") ? "ESCROW" : "ACTIVE",
      components: [
        Number(vec.token ?? 0),
        authRatioAu,
        Number(vec.energy ?? 0),
      ],
      typeMetadata: {
        token_id: tid,
        wallet_id: wid,
      },
      certification: {
        certified: null,
        authRatio: authRatioAu,
        threshold: null,
        lastCheckedAtMs: null,
        reason: "Certification evidence is not provided by the authoritative snapshot",
      },
      projection: null,
      origin: null,
      version: Number(b.version ?? 1),
      createdAtMs: Number(tok?.created_at_ms ?? b.updated_at_ms ?? 0),
      updatedAtMs: Number(b.updated_at_ms ?? 0),
    };
  });

  return NextResponse.json({
    vectors,
    tokens,
    rewards: [],
  });
}
