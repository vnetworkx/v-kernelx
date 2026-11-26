import { randomBytes } from "node:crypto";
import { NextResponse } from "next/server";
import { getKernel, logServerEvent } from "@/lib/server/kernel";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  try {
    const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
    const kernel = getKernel();
    const requestId = String(
      body.request_id ?? `burn_${Date.now()}_${randomBytes(4).toString("hex")}`,
    );

    if (!body.signature || !body.actor_public_key) {
      return NextResponse.json(
        { error: "Ed25519 client signature (actor_public_key + signature) is required" },
        { status: 400 },
      );
    }

    const result = kernel.burnToken({
      request_id: requestId,
      token_id: String(body.token_id ?? ""),
      from_wallet_id: String(body.from_wallet_id ?? ""),
      amount: String(body.amount ?? "0"),
      actor_public_key: String(body.actor_public_key),
      signature: String(body.signature),
    });
    logServerEvent("info", "token_burned", {
      token_id: result.token.token_id,
      from: result.balance.wallet_id,
      amount: String(body.amount),
    });
    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : String(err) },
      { status: 400 },
    );
  }
}
