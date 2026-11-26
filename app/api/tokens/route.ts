import { randomBytes } from "node:crypto";
import { NextResponse } from "next/server";
import { getKernel, logServerEvent } from "@/lib/server/kernel";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const kernel = getKernel();
  const tokens = kernel.store.listTokens().map((t) => ({
    ...t,
    balances: kernel.store.listTokenBalancesForToken(t.token_id),
    conservation: kernel.verifySupplyConservation(t.token_id),
  }));
  return NextResponse.json({ tokens });
}

export async function POST(request: Request) {
  try {
    const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
    const kernel = getKernel();
    const requestId = String(
      body.request_id ?? `tkn_${Date.now()}_${randomBytes(4).toString("hex")}`,
    );

    if (!body.signature || !body.authority_pubkey) {
      return NextResponse.json(
        { error: "Ed25519 client signature (authority_pubkey + signature) is required" },
        { status: 400 },
      );
    }

    const result = kernel.createToken({
      request_id: requestId,
      name: String(body.name ?? ""),
      symbol: String(body.symbol ?? ""),
      region_id: String(body.region_id ?? ""),
      decimals: Number(body.decimals ?? 8),
      max_supply: String(body.max_supply ?? "0"),
      supply_policy: String(body.supply_policy ?? "bounded-reserve-transport-supply"),
      token_type: body.token_type ? String(body.token_type) : undefined,
      drain_bps: body.drain_bps !== undefined ? Number(body.drain_bps) : undefined,
      authority_pubkey: String(body.authority_pubkey),
      signature: String(body.signature),
    });
    logServerEvent("info", "token_created", {
      token_id: result.token.token_id,
      symbol: result.token.symbol,
    });
    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : String(err) },
      { status: 400 },
    );
  }
}
