import { NextResponse } from "next/server";
import { getKernel } from "@/lib/server/kernel";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const kernel = getKernel();
    const wallet = kernel.getWallet(id);
    if (!wallet) {
      return NextResponse.json({ error: `Wallet not found: ${id}` }, { status: 404 });
    }
    const transactions = kernel.getWalletTransactions(id);
    return NextResponse.json({ wallet, transactions });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : String(err) },
      { status: 400 },
    );
  }
}
