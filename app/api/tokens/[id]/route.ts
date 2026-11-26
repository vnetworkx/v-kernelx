import { NextResponse } from "next/server";
import { getKernel } from "@/lib/server/kernel";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  context: { params: Promise<{ id: string }> },
) {
  const { id } = await context.params;
  const decodedId = decodeURIComponent(id);
  const kernel = getKernel();
  const token = kernel.store.getToken(decodedId);
  if (!token) {
    return NextResponse.json({ error: "Token not found" }, { status: 404 });
  }
  return NextResponse.json({
    token,
    balances: kernel.store.listTokenBalancesForToken(token.token_id),
    conservation: kernel.verifySupplyConservation(token.token_id),
  });
}
